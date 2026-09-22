import argparse, itertools, json, random, time
from pathlib import Path

import numpy as np
import torch
from huggingface_hub import HfApi
from transformers import AutoTokenizer, AutoModelForCausalLM

REPO="Qwen/Qwen2.5-0.5B"
REVISION="060db6499f32faf8b98477b0a26969ef7d8b9987"
COLORS=["red","blue","green"]
SEED=1717
STAGES=[0,4,8,12,14,15,16,17,18,19,20,21,22,23,24]
NEG_STAGES=[0,12,16,20,21,24]
RANDOM_CONTROLS=20
GATE={"accuracy_min":0.90,"complete_min":5,"distinct_min":0.90}

PREFIX=(
"Facts: Ada's mug is yellow. Bo's mug is purple. Cy's mug is orange.\n"
"Question: What color is Bo's mug?\nAnswer: purple.\n\n"
"Facts: Dan's ring is black. Eve's ring is white. Fox's ring is brown.\n"
"Question: What color is Fox's ring?\nAnswer: brown.\n\n"
)

FAMILIES=[
 {"name":"owned_kite","object":"kite","names":["Tom","Bob","Sam"],
  "facts":"{A} owns a {Va} kite. {B} owns a {Vb} kite. {C} owns a {Vc} kite."},
 {"name":"stored_coin","object":"coin","names":["Amy","Mia","Eva"],
  "facts":"{A} keeps a {Va} coin. {B} keeps a {Vb} coin. {C} keeps a {Vc} coin."}
]

def build_prompt(fam,vals,qi):
    names=fam["names"]; A,B,C=names; Va,Vb,Vc=vals; Q=names[qi]
    # Build the current facts sentence-by-sentence so character spans are explicit.
    if fam["name"]=="owned_kite":
        sentences=[
            f"{A} owns a {Va} kite.",
            f"{B} owns a {Vb} kite.",
            f"{C} owns a {Vc} kite.",
        ]
    else:
        sentences=[
            f"{A} keeps a {Va} coin.",
            f"{B} keeps a {Vb} coin.",
            f"{C} keeps a {Vc} coin.",
        ]
    head=PREFIX+"Facts: "
    pieces=[]; pos=len(head); spans=[]
    for idx,s in enumerate(sentences):
        if idx:
            pieces.append(" "); pos+=1
        start=pos; pieces.append(s); pos+=len(s); end=pos
        ent_start=start; ent_end=start+len(names[idx])
        color=vals[idx]
        # exact lexical color location inside sentence
        local=s.index(color); col_start=start+local; col_end=col_start+len(color)
        spans.append({"sentence_chars":[start,end],"entity_chars":[ent_start,ent_end],"color_chars":[col_start,col_end]})
    facts_text="".join(pieces)
    tail=f"\nQuestion: What color is {Q}'s {fam['object']}?\nAnswer:"
    text=head+facts_text+tail
    return text,spans

def answer_ids(tok):
    out={}
    for c in COLORS:
        ids=tok.encode(" "+c,add_special_tokens=False)
        if len(ids)!=1: return None,{c:ids}
        out[c]=ids[0]
    return out,None

def char_span_tokens(offsets,span):
    a,b=span
    idx=[i for i,(x,y) in enumerate(offsets) if y>a and x<b and not (x==y==0)]
    if not idx: raise RuntimeError(f"no tokens overlap char span {span}")
    return idx

def locate(tok,text,spans):
    enc=tok(text,add_special_tokens=False,return_offsets_mapping=True)
    ids=enc["input_ids"]; off=enc["offset_mapping"]
    facts=[]
    for s in spans:
        entity=char_span_tokens(off,s["entity_chars"])
        color=char_span_tokens(off,s["color_chars"])
        sent=char_span_tokens(off,s["sentence_chars"])
        if len(entity)!=1: raise RuntimeError(f"entity must be one token for frozen families, got {entity}")
        if len(color)!=1: raise RuntimeError(f"color must be one token, got {color}")
        facts.append({"entity":entity[0],"color":color[0],"span":sent})
    return ids,facts

class Collector:
    def __init__(self,model): self.model=model; self.hs=[]; self.stage={}
    def __enter__(self):
        def eh(m,inp,out): self.stage[0]=out[0].detach().float().cpu()
        self.hs.append(self.model.model.embed_tokens.register_forward_hook(eh))
        for i,layer in enumerate(self.model.model.layers):
            def mk(k):
                def h(m,inp,out):
                    x=out[0] if isinstance(out,tuple) else out
                    self.stage[k]=x[0].detach().float().cpu()
                return h
            self.hs.append(layer.register_forward_hook(mk(i+1)))
        return self
    def __exit__(self,*a):
        for h in self.hs: h.remove()

class MultiPatcher:
    def __init__(self,model,stage,positions,vectors):
        self.model=model; self.stage=stage; self.positions=list(positions); self.vectors=vectors; self.h=None
    def _apply(self,y):
        z=y.clone()
        for k,pos in enumerate(self.positions):
            z[0,pos]=self.vectors[k].to(z.device,z.dtype)
        return z
    def __enter__(self):
        if self.stage==0:
            def hook(m,inp,out): return self._apply(out)
            self.h=self.model.model.embed_tokens.register_forward_hook(hook)
        else:
            layer=self.model.model.layers[self.stage-1]
            def hook(m,inp,out):
                if isinstance(out,tuple):
                    return (self._apply(out[0]),)+tuple(out[1:])
                return self._apply(out)
            self.h=layer.register_forward_hook(hook)
        return self
    def __exit__(self,*a):
        if self.h: self.h.remove()

def run(model,tok,text,cids,device,collect=False,patch=None):
    ids=tok(text,add_special_tokens=False,return_tensors="pt")["input_ids"].to(device)
    c=Collector(model) if collect else None
    p=MultiPatcher(model,*patch) if patch else None
    if c: c.__enter__()
    if p: p.__enter__()
    try:
        with torch.inference_mode(): o=model(ids,use_cache=False)
        lg=o.logits[0,-1].float()
        cand=torch.tensor([float(lg[cids[x]]) for x in COLORS])
        pred=COLORS[int(torch.argmax(cand))]
        return pred,cand.cpu(),dict(c.stage) if c else None,ids[0].cpu()
    finally:
        if p: p.__exit__(None,None,None)
        if c: c.__exit__(None,None,None)

def behavior(model,tok,cids,device,fam):
    rows=[]; complete=0; distinct=[]
    for vals in itertools.permutations(COLORS):
        ps=[]; cs=[]
        for qi in range(3):
            text,_=build_prompt(fam,vals,qi)
            pred,cand,_,_=run(model,tok,text,cids,device)
            ok=pred==vals[qi]
            rows.append({"values":vals,"qi":qi,"target":vals[qi],"pred":pred,"correct":ok})
            ps.append(pred); cs.append(ok)
        complete+=int(all(cs)); distinct.append(len(set(ps))==3)
    acc=sum(r["correct"] for r in rows)/len(rows); qd=sum(distinct)/len(distinct)
    return {"accuracy":acc,"complete":complete,"query_distinct":qd,
            "pass":acc>=GATE["accuracy_min"] and complete>=GATE["complete_min"] and qd>=GATE["distinct_min"],
            "rows":rows}

def donor_vals(vals,qi):
    v=list(vals); j=(qi+1)%3; v[qi],v[j]=v[j],v[qi]
    return tuple(v),j,(qi+2)%3

def collect_all(model,tok,cids,device,fam):
    out={}
    for vals in itertools.permutations(COLORS):
        for qi in range(3):
            text,spans=build_prompt(fam,vals,qi)
            ids,facts=locate(tok,text,spans)
            pred,cand,stages,tids=run(model,tok,text,cids,device,collect=True)
            if list(tids.numpy())!=ids: raise RuntimeError("tokenization mismatch between locator and forward")
            out[("|".join(vals),qi)]={"vals":vals,"qi":qi,"text":text,"facts":facts,
                                     "ids":tids,"pred":pred,"cand":cand,"stages":stages}
    return out

def margin(cand,dt,rt):
    return float(cand[COLORS.index(dt)]-cand[COLORS.index(rt)])

def mode_positions(rec,qi,j,k):
    f=rec["facts"]
    return {
      "target_entity":[f[qi]["entity"]],
      "target_color":[f[qi]["color"]],
      "target_binding_pair":[f[qi]["entity"],f[qi]["color"]],
      "target_fact_span":list(f[qi]["span"]),
      "partner_entity":[f[j]["entity"]],
      "partner_color":[f[j]["color"]],
      "partner_fact_span":list(f[j]["span"]),
      "unchanged_color":[f[k]["color"]],
      "both_swapped_colors":[f[qi]["color"],f[j]["color"]],
    }

def interventions(model,tok,cids,device,fam,base):
    rows=[]
    for vals in itertools.permutations(COLORS):
        rkey="|".join(vals)
        for qi in range(3):
            dv,j,k=donor_vals(vals,qi); dkey="|".join(dv)
            R=base[(rkey,qi)]; D=base[(dkey,qi)]
            # exact token alignment
            if len(R["ids"])!=len(D["ids"]): raise RuntimeError("recipient/donor token lengths differ")
            diffs=[p for p in range(len(R["ids"])) if int(R["ids"][p])!=int(D["ids"][p])]
            expected=sorted([R["facts"][qi]["color"],R["facts"][j]["color"]])
            if diffs!=expected: raise RuntimeError(f"recipient/donor differ at {diffs}, expected {expected}")
            rt=vals[qi]; dt=dv[qi]
            mr=margin(R["cand"],dt,rt); md=margin(D["cand"],dt,rt); den=md-mr
            if abs(den)<1e-8: raise RuntimeError("degenerate baseline margin")
            modes=mode_positions(R,qi,j,k)
            for s in STAGES:
                for mode,poss in modes.items():
                    vecs=torch.stack([D["stages"][s][p] for p in poss],dim=0)
                    pred,cand,_,_=run(model,tok,R["text"],cids,device,patch=(s,poss,vecs))
                    mp=margin(cand,dt,rt)
                    delta=torch.stack([D["stages"][s][p]-R["stages"][s][p] for p in poss],dim=0)
                    rows.append({"family":fam["name"],"recipient":rkey,"donor":dkey,"query_index":qi,
                      "partner_index":j,"stage":s,"mode":mode,"positions":poss,
                      "recipient_target":rt,"donor_target":dt,
                      "recipient_margin":mr,"donor_margin":md,"patched_margin":mp,
                      "donor_recovery":(mp-mr)/den,"pred":pred,"donor_pred":pred==dt,
                      "patch_norm":float(torch.linalg.vector_norm(delta)),
                      "stage0_both_colors_trivial":bool(s==0 and mode=="both_swapped_colors")})
    return rows

def summarize(rows):
    g={}
    for r in rows: g.setdefault((r["stage"],r["mode"]),[]).append(r)
    out=[]
    for (s,m),rr in sorted(g.items()):
        out.append({"stage":s,"mode":m,"n":len(rr),
          "mean_donor_recovery":float(np.mean([x["donor_recovery"] for x in rr])),
          "median_donor_recovery":float(np.median([x["donor_recovery"] for x in rr])),
          "donor_pred_fraction":float(np.mean([x["donor_pred"] for x in rr])),
          "mean_patch_norm":float(np.mean([x["patch_norm"] for x in rr]))})
    return out

def binding_selective(summary):
    by={(r["stage"],r["mode"]):r for r in summary}
    good=[]
    for s in STAGES:
        t=by[(s,"target_color")]; p=by[(s,"partner_color")]
        if (t["mean_donor_recovery"]>=.75 and t["donor_pred_fraction"]>=.75 and
            p["mean_donor_recovery"]<.25 and p["donor_pred_fraction"]<.25):
            good.append(s)
    return good

def prefix_controls(model,tok,cids,device,fam,base):
    rows=[]
    for vals in itertools.permutations(COLORS):
        rkey="|".join(vals)
        for qi in range(3):
            dv,j,k=donor_vals(vals,qi); dkey="|".join(dv)
            R=base[(rkey,qi)]; D=base[(dkey,qi)]
            changed=sorted([R["facts"][qi]["color"],R["facts"][j]["color"]])
            first=changed[0]
            poss=[p for p in [first-2,first-1] if p>=0]
            rt=vals[qi]; dt=dv[qi]; mr=margin(R["cand"],dt,rt); md=margin(D["cand"],dt,rt); den=md-mr
            for s in NEG_STAGES:
                for pos in poss:
                    vecs=torch.stack([D["stages"][s][pos]],dim=0)
                    _,cand,_,_=run(model,tok,R["text"],cids,device,patch=(s,[pos],vecs))
                    delta=D["stages"][s][pos]-R["stages"][s][pos]
                    rows.append({"stage":s,"position":pos,
                      "patch_norm":float(torch.linalg.vector_norm(delta)),
                      "donor_recovery":(margin(cand,dt,rt)-mr)/den})
    return rows

def random_control(model,tok,cids,device,fam,base,stage,mode):
    gen=torch.Generator().manual_seed(SEED+stage*101)
    rows=[]
    for vals in itertools.permutations(COLORS):
        rkey="|".join(vals)
        for qi in range(3):
            dv,j,k=donor_vals(vals,qi); dkey="|".join(dv)
            R=base[(rkey,qi)]; D=base[(dkey,qi)]
            poss=mode_positions(R,qi,j,k)[mode]
            rt=vals[qi]; dt=dv[qi]; mr=margin(R["cand"],dt,rt); md=margin(D["cand"],dt,rt); den=md-mr
            donor_mat=torch.stack([D["stages"][stage][p] for p in poss],dim=0)
            rec_mat=torch.stack([R["stages"][stage][p] for p in poss],dim=0)
            delta=donor_mat-rec_mat; n=float(torch.linalg.vector_norm(delta))
            _,tc,_,_=run(model,tok,R["text"],cids,device,patch=(stage,poss,donor_mat))
            targ=(margin(tc,dt,rt)-mr)/den
            ctr=[]
            for _ in range(RANDOM_CONTROLS):
                noise=torch.randn(rec_mat.shape,generator=gen)
                nn=float(torch.linalg.vector_norm(noise))
                rand=rec_mat+noise*(n/nn if nn else 0.0)
                _,cc,_,_=run(model,tok,R["text"],cids,device,patch=(stage,poss,rand))
                ctr.append((margin(cc,dt,rt)-mr)/den)
            rows.append({"recipient":rkey,"donor":dkey,"query_index":qi,
              "targeted_recovery":targ,"random_mean":float(np.mean(ctr)),"random_max":float(np.max(ctr)),
              "targeted_exceeds_random_max":bool(targ>max(ctr))})
    return {"stage":stage,"mode":mode,"pairs":rows,
      "fraction_targeted_exceeds_random_max":float(np.mean([x["targeted_exceeds_random_max"] for x in rows])),
      "mean_targeted_recovery":float(np.mean([x["targeted_recovery"] for x in rows])),
      "mean_random_recovery":float(np.mean([x["random_mean"] for x in rows]))}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--output",required=True); args=ap.parse_args()
    random.seed(SEED); np.random.seed(SEED); torch.manual_seed(SEED); t0=time.time()
    info=HfApi().model_info(REPO,revision=REVISION); assert info.sha==REVISION
    tok=AutoTokenizer.from_pretrained(REPO,revision=REVISION)
    kw={"revision":REVISION,"low_cpu_mem_usage":True}
    if torch.cuda.is_available(): kw.update({"torch_dtype":torch.float16,"device_map":"auto"})
    model=AutoModelForCausalLM.from_pretrained(REPO,**kw); model.eval(); device=next(model.parameters()).device

    cids,err=answer_ids(tok)
    out={"specimen":{"repo":REPO,"revision":REVISION,"device":str(device),"layers":model.config.num_hidden_layers,
                     "hidden":model.config.hidden_size},
         "protocol":{"stages":STAGES,"negative_stages":NEG_STAGES,"random_controls":RANDOM_CONTROLS,"gate":GATE}}
    if cids is None:
        out["status"]="WITHHELD_MULTI_TOKEN_COLORS"; out["token_error"]=err
        Path(args.output).parent.mkdir(parents=True,exist_ok=True); Path(args.output).write_text(json.dumps(out,indent=2)); return

    for fam in FAMILIES:
        b=behavior(model,tok,cids,device,fam)
        out.setdefault("behavior",{})[fam["name"]]=b
        print("BEHAVIOR",fam["name"],json.dumps({k:v for k,v in b.items() if k!="rows"}),flush=True)
    if not all(out["behavior"][f["name"]]["pass"] for f in FAMILIES):
        out["status"]="MECHANISTIC_PHASE_WITHHELD"
        Path(args.output).parent.mkdir(parents=True,exist_ok=True); Path(args.output).write_text(json.dumps(out,indent=2)); return

    out["families"]={}
    for fam in FAMILIES:
        base=collect_all(model,tok,cids,device,fam)
        rows=interventions(model,tok,cids,device,fam,base)
        sm=summarize(rows)
        sel=binding_selective(sm)
        neg=prefix_controls(model,tok,cids,device,fam,base)
        rc={"status":"SKIPPED_NO_QUALIFYING_SOURCE_STAGE"}
        if sel:
            rc=random_control(model,tok,cids,device,fam,base,max(s for s in sel if s>0) if any(s>0 for s in sel) else sel[-1],"target_color")
        else:
            # frozen fallback to target_fact_span if target_color never qualifies
            by={(r["stage"],r["mode"]):r for r in sm}
            fact=[s for s in STAGES if by[(s,"target_fact_span")]["mean_donor_recovery"]>=.75 and
                  by[(s,"target_fact_span")]["donor_pred_fraction"]>=.75 and s>0]
            if fact:
                rc=random_control(model,tok,cids,device,fam,base,max(fact),"target_fact_span")
        out["families"][fam["name"]]={"summary":sm,"rows":rows,"binding_selective_stages":sel,
          "latest_binding_selective_stage":max(sel) if sel else None,
          "first_later_nonselective_stage":next((s for s in STAGES if sel and s>max(sel)),None),
          "prefix_negative_controls":neg,"random_control":rc}
        print("SELECTIVE",fam["name"],sel,flush=True)
        if rc.get("status") is None:
            print("RANDOM",fam["name"],json.dumps({k:v for k,v in rc.items() if k!="pairs"}),flush=True)

    # pooled mode/stage summaries
    pool={}
    for fd in out["families"].values():
        for r in fd["rows"]: pool.setdefault((r["stage"],r["mode"]),[]).append(r)
    out["pooled_summary"]=[{"stage":k[0],"mode":k[1],"n":len(v),
      "mean_donor_recovery":float(np.mean([x["donor_recovery"] for x in v])),
      "donor_pred_fraction":float(np.mean([x["donor_pred"] for x in v])),
      "mean_patch_norm":float(np.mean([x["patch_norm"] for x in v]))} for k,v in sorted(pool.items())]

    out["status"]="COMPLETE"; out["seconds"]=time.time()-t0
    Path(args.output).parent.mkdir(parents=True,exist_ok=True); Path(args.output).write_text(json.dumps(out,indent=2))
    print("DONE",out["seconds"],flush=True)

if __name__=="__main__": main()
