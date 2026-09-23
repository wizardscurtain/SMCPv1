import argparse, itertools, json, math, time
from pathlib import Path
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL = "Qwen/Qwen2.5-3B"
REVISION = "3aab1f1954e9cc14eb9509a215f9e5ca08227a9b"
COLORS = ["red", "blue", "green"]
SEED = 1701

QA_PREFIX = (
    "Facts: Ada's mug is yellow. Bo's mug is purple. Cy's mug is orange.\n"
    "Question: What color is Bo's mug?\nAnswer: purple\n\n"
    "Facts: Dan's ring is black. Eve's ring is white. Fox's ring is brown.\n"
    "Question: What color is Fox's ring?\nAnswer: brown\n\n"
)

FAMILIES = {
    "possessive_ball_qa": ("eligibility", ["Lily","Tom","Ben"],
        "Facts: {A}'s ball is {Va}. {B}'s ball is {Vb}. {C}'s ball is {Vc}.\nQuestion: What color is {Q}'s ball?\nAnswer:"),
    "hat_qa": ("eligibility", ["Lily","Tom","Ben"],
        "Facts: {A} has a {Va} hat. {B} has a {Vb} hat. {C} has a {Vc} hat.\nQuestion: What color is {Q}'s hat?\nAnswer:"),
    "bag_qa": ("eligibility", ["Lily","Tom","Ben"],
        "Facts: {A} carries a {Va} bag. {B} carries a {Vb} bag. {C} carries a {Vc} bag.\nQuestion: What color is the bag carried by {Q}?\nAnswer:"),
    "coat_record": ("confirmation", ["Anna","Max","Sam"],
        "Records: {A} -> coat={Va}; {B} -> coat={Vb}; {C} -> coat={Vc}.\nQuery: coat color for {Q} ="),
    "cup_record": ("confirmation", ["Anna","Max","Sam"],
        "Records: {A} -> chosen cup={Va}; {B} -> chosen cup={Vb}; {C} -> chosen cup={Vc}.\nQuery: chosen cup color for {Q} ="),
}

def prompt_rows():
    rows=[]
    for fam,(split,names,template) in FAMILIES.items():
        for perm_i,vals in enumerate(itertools.permutations(COLORS)):
            for qi,qn in enumerate(names):
                item=template.format(A=names[0],B=names[1],C=names[2],Va=vals[0],Vb=vals[1],Vc=vals[2],Q=qn)
                rows.append({"family":fam,"split":split,"perm_i":perm_i,"query_index":qi,
                             "query_name":qn,"target":vals[qi],"prompt":QA_PREFIX+item})
    return rows

def cosine_centroid_predict(train_x, train_y, test_x, labels):
    mu=train_x.mean(0,keepdims=True)
    tx=train_x-mu
    qx=test_x-mu
    cents=[]
    for label in labels:
        c=tx[np.array(train_y)==label].mean(0)
        n=np.linalg.norm(c)
        cents.append(c/(n if n>1e-12 else 1.0))
    cents=np.stack(cents)
    qn=np.linalg.norm(qx,axis=1,keepdims=True)
    qx=qx/np.maximum(qn,1e-12)
    scores=qx@cents.T
    return np.array([labels[i] for i in scores.argmax(1)]),scores

def accuracy(pred, truth):
    return float(np.mean(np.asarray(pred)==np.asarray(truth)))

def cross_surface_metrics(x, rows, target_key):
    elig=[i for i,r in enumerate(rows) if r["split"]=="eligibility"]
    conf=[i for i,r in enumerate(rows) if r["split"]=="confirmation"]
    labels=sorted({r[target_key] for r in rows})
    y=[r[target_key] for r in rows]
    p,s=cosine_centroid_predict(x[elig], [y[i] for i in elig], x[conf], labels)
    out={"confirmation_pooled":accuracy(p,[y[i] for i in conf])}
    for fam in ("coat_record","cup_record"):
        idx=[j for j,i in enumerate(conf) if rows[i]["family"]==fam]
        out[fam]=accuracy(p[idx],[y[conf[j]] for j in idx])
    loo=[]
    for held in ("possessive_ball_qa","hat_qa","bag_qa"):
        tr=[i for i,r in enumerate(rows) if r["split"]=="eligibility" and r["family"]!=held]
        te=[i for i,r in enumerate(rows) if r["family"]==held]
        pp,_=cosine_centroid_predict(x[tr],[y[i] for i in tr],x[te],labels)
        loo.append(accuracy(pp,[y[i] for i in te]))
    out["eligibility_leave_family_out_mean"]=float(np.mean(loo))
    out["eligibility_leave_family_out"]=dict(zip(("possessive_ball_qa","hat_qa","bag_qa"),loo))
    return out

def context_center(states, rows):
    out=np.empty_like(states)
    groups={}
    for i,r in enumerate(rows):
        groups.setdefault((r["family"],r["perm_i"]),[]).append(i)
    for idx in groups.values():
        mu=states[idx].mean(0,keepdims=True)
        out[idx]=states[idx]-mu
    return out

def value_plane(model, tok):
    ids=[]
    for c in COLORS:
        z=tok.encode(" "+c,add_special_tokens=False)
        if len(z)!=1: raise RuntimeError((c,z))
        ids.append(z[0])
    w=model.lm_head.weight.detach().float().cpu().numpy()[ids]
    w=w-w.mean(0,keepdims=True)
    q,_=np.linalg.qr(w.T)
    return q[:,:2],ids

def query_plane_overlap(offsets, rows, value_basis):
    vals=[]
    for fam in FAMILIES:
        for perm_i in range(6):
            idx=[i for i,r in enumerate(rows) if r["family"]==fam and r["perm_i"]==perm_i]
            m=offsets[idx]
            q,_=np.linalg.qr(m.T)
            q=q[:,:2]
            s=np.linalg.svd(q.T@value_basis,compute_uv=False)
            vals.append(float(np.mean(s*s)))
    return float(np.mean(vals))

def shuffled_null(x, rows, target_key, rng, n=100):
    elig=[i for i,r in enumerate(rows) if r["split"]=="eligibility"]
    conf=[i for i,r in enumerate(rows) if r["split"]=="confirmation"]
    labels=sorted({r[target_key] for r in rows})
    y=np.array([r[target_key] for r in rows],dtype=object)
    scores=[]
    for _ in range(n):
        yy=y.copy(); rng.shuffle(yy)
        p,_=cosine_centroid_predict(x[elig],yy[elig],x[conf],labels)
        scores.append(accuracy(p,yy[conf]))
    return {"mean":float(np.mean(scores)),"p95":float(np.quantile(scores,.95)),"max":float(np.max(scores))}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--out",default="/tmp/pass17_geometry.json")
    args=ap.parse_args()
    torch.manual_seed(SEED); np.random.seed(SEED)
    tok=AutoTokenizer.from_pretrained(MODEL,revision=REVISION)
    model=AutoModelForCausalLM.from_pretrained(MODEL,revision=REVISION,torch_dtype=torch.float16).cuda().eval()
    rows=prompt_rows()
    hidden=[]
    behavior=[]
    for ri,r in enumerate(rows):
        enc=tok(r["prompt"],return_tensors="pt").to("cuda")
        with torch.inference_mode():
            o=model(**enc,use_cache=False,output_hidden_states=True)
        hs=torch.stack([h[0,-1].float().cpu() for h in o.hidden_states]).numpy()
        if not hidden: hidden=[[] for _ in range(hs.shape[0])]
        for l in range(hs.shape[0]): hidden[l].append(hs[l])
        logits=o.logits[0,-1].float()
        cids={c:tok.encode(" "+c,add_special_tokens=False)[0] for c in COLORS}
        pred=max(COLORS,key=lambda c:float(logits[cids[c]]))
        behavior.append(pred==r["target"])
        if (ri+1)%18==0: print("CAPTURED",ri+1,"/",len(rows),flush=True)
    hidden=[np.stack(x) for x in hidden]
    vb,cids=value_plane(model,tok)
    rng=np.random.default_rng(SEED)
    curves=[]
    for l,raw in enumerate(hidden):
        off=context_center(raw,rows)
        q=cross_surface_metrics(off,rows,"query_index")
        v=cross_surface_metrics(off,rows,"target")
        curves.append({"layer":l,"query_offset":q,"value_offset":v,
                       "value_plane_overlap":query_plane_overlap(off,rows,vb)})
    candidates=[]
    for c in curves:
        v=c["value_offset"]; q=c["query_offset"]
        if (v["confirmation_pooled"]>=.75 and v["coat_record"]>=2/3 and v["cup_record"]>=2/3
            and v["eligibility_leave_family_out_mean"]>=.75
            and v["confirmation_pooled"]-q["confirmation_pooled"]>=.15):
            candidates.append(c["layer"])
    # Null only at the best value layer, chosen by confirmation then LOO.
    best=max(curves,key=lambda c:(c["value_offset"]["confirmation_pooled"],c["value_offset"]["eligibility_leave_family_out_mean"]))
    best_off=context_center(hidden[best["layer"]],rows)
    null=shuffled_null(best_off,rows,"target",rng)
    result={
      "protocol":"Pass17 operational analogue screen: centered query offsets; no causal claims from geometry alone",
      "model":MODEL,"revision":REVISION,"script_seed":SEED,
      "behavior_accuracy":float(np.mean(behavior)),
      "n_prompts":len(rows),"n_hidden_states":len(hidden),
      "curves":curves,"candidate_layers":candidates,
      "best_value_layer":best["layer"],"best_value_metrics":best["value_offset"],
      "best_query_metrics":best["query_offset"],"best_value_null":null,
      "causal_followup_allowed":bool(candidates),
    }
    Path(args.out).write_text(json.dumps(result,indent=2))
    print("PASS17_SUMMARY",json.dumps({k:result[k] for k in ("model","revision","behavior_accuracy","n_prompts","n_hidden_states","candidate_layers","best_value_layer","best_value_metrics","best_query_metrics","best_value_null","causal_followup_allowed")},separators=(",",":")),flush=True)

if __name__=="__main__": main()
