import argparse, json, time
from pathlib import Path
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL="Qwen/Qwen2.5-3B"
REVISION="3aab1f1954e9cc14eb9509a215f9e5ca08227a9b"
STAGE=34
BLOCK_INDEX=33
COLORS=["red","blue","green"]
TRAIN=[
    ("red","blue","green"),
    ("blue","green","red"),
    ("green","red","blue"),
]
TEST=[
    ("red","green","blue"),
    ("blue","red","green"),
    ("green","blue","red"),
]
TEMPLATES={
    "facts_question_ball":(["Lily","Tom","Ben"],"Facts:\n{A}'s ball is {Va}.\n{B}'s ball is {Vb}.\n{C}'s ball is {Vc}.\nQuestion: What color is {Q}'s ball?\nAnswer:"),
    "worked_example_box":(["Lily","Tom","Ben"],"Example: Nora's key is yellow. Omar's key is purple. Pia's key is orange.\nQuestion: What color is Omar's key? Answer: purple\n\nNew facts: {A}'s box is {Va}. {B}'s box is {Vb}. {C}'s box is {Vc}.\nQuestion: What color is {Q}'s box? Answer:"),
    "facts_question_coat":(["Anna","Max","Sam"],"Facts:\n{A} wears a {Va} coat.\n{B} wears a {Vb} coat.\n{C} wears a {Vc} coat.\nQuestion: What color coat does {Q} wear?\nAnswer:"),
}
BACKENDS={
    "fp16_default":{"dtype":"float16","attn":None},
    "fp32_eager":{"dtype":"float32","attn":"eager"},
}

def center(x): return x-x.mean(0,keepdim=True)
def cosflat(a,b):
    a=a.reshape(-1).float(); b=b.reshape(-1).float()
    return float((a@b/(torch.linalg.norm(a)*torch.linalg.norm(b)+1e-12)).item())
def hamming(a,b): return sum(x!=y for x,y in zip(a,b))
def donor_h2(target): return max(TRAIN,key=lambda d:(hamming(target,d),d))
def prompt(names,tpl,vals,q):
    return tpl.format(A=names[0],B=names[1],C=names[2],Va=vals[0],Vb=vals[1],Vc=vals[2],Q=names[q])

def load_model(kind,device):
    cfg=BACKENDS[kind]
    dtype=torch.float16 if cfg["dtype"]=="float16" else torch.float32
    kw={"revision":REVISION,"torch_dtype":dtype}
    if cfg["attn"] is not None: kw["attn_implementation"]=cfg["attn"]
    return AutoModelForCausalLM.from_pretrained(MODEL,**kw).to(device).eval()

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--out",default="/tmp/pass22.json");ap.add_argument("--device",default="cuda" if torch.cuda.is_available() else "cpu");args=ap.parse_args()
    device=args.device
    tok=AutoTokenizer.from_pretrained(MODEL,revision=REVISION)
    cids={}
    for c in COLORS:
        ids=tok.encode(" "+c,add_special_tokens=False)
        if len(ids)!=1: raise RuntimeError((c,ids))
        cids[c]=ids[0]

    def logits3(o):
        v=torch.tensor([float(o.logits[0,-1,cids[c]].item()) for c in COLORS])
        if not torch.isfinite(v).all(): raise RuntimeError("non-finite candidate logits")
        return v

    # Phase 1: extract stage-34 affine components and same-backend baselines to CPU.
    representations={}
    baselines={}
    for bk in BACKENDS:
        print("EXTRACT",bk,flush=True)
        model=load_model(bk,device)
        representations[bk]={}; baselines[bk]={}
        with torch.inference_mode():
            for tn,(names,tpl) in TEMPLATES.items():
                representations[bk][tn]={}; baselines[bk][tn]={}
                for vals in TRAIN+TEST:
                    hs=[]; ls=[]
                    for q in range(3):
                        enc=tok(prompt(names,tpl,vals,q),return_tensors="pt");enc={k:v.to(device) for k,v in enc.items()}
                        o=model(**enc,output_hidden_states=True,use_cache=False)
                        hs.append(o.hidden_states[STAGE][0,-1].detach().float().cpu())
                        ls.append(logits3(o).cpu())
                    Q=torch.stack(hs)
                    representations[bk][tn][vals]={"m":Q.mean(0,keepdim=True),"C":center(Q)}
                    baselines[bk][tn][vals]=torch.stack(ls)
        del model
        if torch.cuda.is_available(): torch.cuda.empty_cache()

    result={"protocol":"Pass22 backend/precision localization matrix at Qwen3B stage34","model":MODEL,"revision":REVISION,"stage":STAGE,"block_index":BLOCK_INDEX,"backends":BACKENDS,"templates":{}}
    t0=time.time()
    for downstream in BACKENDS:
        print("DOWNSTREAM",downstream,flush=True)
        model=load_model(downstream,device)
        layers=model.model.layers
        def run_replace(ptxt,x):
            block=layers[BLOCK_INDEX]
            def hook(mod,inp,out):
                first=out[0] if isinstance(out,tuple) else out
                xx=x.to(device=first.device,dtype=first.dtype).reshape(1,1,-1)
                y=torch.cat([first[:,:-1,:],xx],dim=1)
                return (y,)+out[1:] if isinstance(out,tuple) else y
            h=block.register_forward_hook(hook)
            try:
                enc=tok(ptxt,return_tensors="pt");enc={k:v.to(device) for k,v in enc.items()}
                with torch.inference_mode(): o=model(**enc,use_cache=False)
                return logits3(o).cpu()
            finally: h.remove()

        for tn,(names,tpl) in TEMPLATES.items():
            result["templates"].setdefault(tn,{})
            rec_base_by_target={v:center(baselines[downstream][tn][v]) for v in TEST}
            rows_by_repr={}
            for rep in BACKENDS:
                rows=[]
                for target in TEST:
                    donor=donor_h2(target)
                    donor_base=center(baselines[downstream][tn][donor])
                    rec_base=rec_base_by_target[target]
                    m=representations[rep][tn][target]["m"]
                    Ct=representations[rep][tn][target]["C"]
                    Cd=representations[rep][tn][donor]["C"]
                    rec_logs=[]; don_logs=[]
                    for q in range(3):
                        ptxt=prompt(names,tpl,target,q)
                        rec_logs.append(run_replace(ptxt,m+Ct[q:q+1]))
                        don_logs.append(run_replace(ptxt,m+Cd[q:q+1]))
                    R=center(torch.stack(rec_logs)); D=center(torch.stack(don_logs))
                    rows.append({
                        "target":target,"donor":donor,
                        "recipient_reconstruction_cosine":cosflat(R,rec_base),
                        "donor_plane_donor_cosine":cosflat(D,donor_base),
                        "donor_plane_recipient_cosine":cosflat(D,rec_base),
                        "donor_plane_donor_closer":cosflat(D,donor_base)>cosflat(D,rec_base),
                        "recipient_reconstruction_candidate_accuracy":sum(COLORS[int(rec_logs[q].argmax())]==target[q] for q in range(3))/3,
                        "donor_plane_donor_candidate_accuracy":sum(COLORS[int(don_logs[q].argmax())]==donor[q] for q in range(3))/3,
                    })
                rows_by_repr[rep]={
                    "mean_recipient_reconstruction_cosine":float(np.mean([r["recipient_reconstruction_cosine"] for r in rows])),
                    "mean_donor_plane_donor_cosine":float(np.mean([r["donor_plane_donor_cosine"] for r in rows])),
                    "donor_closer_fraction":float(np.mean([r["donor_plane_donor_closer"] for r in rows])),
                    "mean_recipient_reconstruction_candidate_accuracy":float(np.mean([r["recipient_reconstruction_candidate_accuracy"] for r in rows])),
                    "mean_donor_plane_donor_candidate_accuracy":float(np.mean([r["donor_plane_donor_candidate_accuracy"] for r in rows])),
                    "rows":rows,
                }
            result["templates"][tn][downstream]=rows_by_repr
            print("MATRIX",tn,downstream,json.dumps({k:{kk:vv for kk,vv in v.items() if kk!="rows"} for k,v in rows_by_repr.items()},separators=(",",":")),flush=True)
        del model
        if torch.cuda.is_available(): torch.cuda.empty_cache()

    # Compare the stage-34 affine coordinates themselves across extraction backends.
    result["representation_similarity"]={}
    for tn in TEMPLATES:
        vals={}
        for assignment in TRAIN+TEST:
            a=representations["fp16_default"][tn][assignment]
            b=representations["fp32_eager"][tn][assignment]
            vals[str(assignment)]={
                "centroid_cosine":cosflat(a["m"],b["m"]),
                "centered_plane_cosine":cosflat(a["C"],b["C"]),
                "centroid_relative_l2":float(torch.linalg.norm(a["m"]-b["m"])/(torch.linalg.norm(a["m"])+1e-12)),
                "plane_relative_l2":float(torch.linalg.norm(a["C"]-b["C"])/(torch.linalg.norm(a["C"])+1e-12)),
            }
        result["representation_similarity"][tn]={
            "mean_centroid_cosine":float(np.mean([v["centroid_cosine"] for v in vals.values()])),
            "mean_plane_cosine":float(np.mean([v["centered_plane_cosine"] for v in vals.values()])),
            "mean_centroid_relative_l2":float(np.mean([v["centroid_relative_l2"] for v in vals.values()])),
            "mean_plane_relative_l2":float(np.mean([v["plane_relative_l2"] for v in vals.values()])),
            "assignments":vals,
        }
    result["seconds"]=time.time()-t0
    Path(args.out).write_text(json.dumps(result,indent=2))
    compact={"representation_similarity":{k:{kk:vv for kk,vv in v.items() if kk!="assignments"} for k,v in result["representation_similarity"].items()},"matrix":{}}
    for tn,tv in result["templates"].items():
        compact["matrix"][tn]={}
        for down,rv in tv.items():
            compact["matrix"][tn][down]={rep:{kk:vv for kk,vv in metrics.items() if kk!="rows"} for rep,metrics in rv.items()}
    print("PASS22_SUMMARY",json.dumps(compact,separators=(",",":")),flush=True)

if __name__=="__main__": main()
