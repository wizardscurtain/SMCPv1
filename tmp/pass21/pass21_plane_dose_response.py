import argparse, itertools, json, time
from pathlib import Path
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL="Qwen/Qwen2.5-3B"
REVISION="3aab1f1954e9cc14eb9509a215f9e5ca08227a9b"
STAGE=34
BLOCK_INDEX=33
COLORS=["red","blue","green"]
ALPHAS=[0.0,0.25,0.5,0.75,1.0]
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
CRITERIA={
    "alpha0_recipient_closer_fraction_min":0.80,
    "alpha1_h3_donor_closer_fraction_min":0.80,
    "h3_donor_cosine_monotonic_fraction_min":0.75,
    "h3_recipient_cosine_monotonic_fraction_min":0.75,
    "min_families_passing":2,
}

def center(x): return x-x.mean(0,keepdim=True)
def cosflat(a,b):
    a=a.reshape(-1).float();b=b.reshape(-1).float()
    return float((a@b/(torch.linalg.norm(a)*torch.linalg.norm(b)+1e-12)).item())
def hamming(a,b): return sum(x!=y for x,y in zip(a,b))
def donor_from(pool,target):
    return max(pool,key=lambda d:(hamming(target,d),d))
def prompt(names,tpl,vals,q):
    return tpl.format(A=names[0],B=names[1],C=names[2],Va=vals[0],Vb=vals[1],Vc=vals[2],Q=names[q])

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--out",default="/tmp/pass21.json");ap.add_argument("--device",default="cuda" if torch.cuda.is_available() else "cpu");args=ap.parse_args()
    device=args.device
    tok=AutoTokenizer.from_pretrained(MODEL,revision=REVISION)
    dtype=torch.float16 if device.startswith("cuda") else None
    model=AutoModelForCausalLM.from_pretrained(MODEL,revision=REVISION,torch_dtype=dtype).to(device).eval()
    layers=model.model.layers
    cids={}
    for c in COLORS:
        ids=tok.encode(" "+c,add_special_tokens=False)
        if len(ids)!=1:raise RuntimeError((c,ids))
        cids[c]=ids[0]
    def logits3(o): return torch.tensor([float(o.logits[0,-1,cids[c]].item()) for c in COLORS])
    def forward(p,hidden=False):
        enc=tok(p,return_tensors="pt");enc={k:v.to(device) for k,v in enc.items()}
        with torch.inference_mode(): return model(**enc,output_hidden_states=hidden,use_cache=False)
    def replace_forward(p,x):
        block=layers[BLOCK_INDEX]
        def hook(mod,inp,out):
            first=out[0] if isinstance(out,tuple) else out
            xx=x.to(device=first.device,dtype=first.dtype).reshape(1,1,-1)
            y=torch.cat([first[:,:-1,:],xx],dim=1)
            return (y,)+out[1:] if isinstance(out,tuple) else y
        h=block.register_forward_hook(hook)
        try:return logits3(forward(p,False))
        finally:h.remove()

    result={"protocol":"Pass21 Qwen3B stage34 centered-plane causal dose response","model":MODEL,"revision":REVISION,"stage":STAGE,"block_index":BLOCK_INDEX,"alphas":ALPHAS,"criteria":CRITERIA,"templates":{},"overall_pass":False}
    t0=time.time()
    for tn,(names,tpl) in TEMPLATES.items():
        print("===",tn,"===",flush=True)
        states={};base={}
        for vals in TRAIN+TEST:
            qs=[];ls=[]
            for q in range(3):
                o=forward(prompt(names,tpl,vals,q),True)
                qs.append(o.hidden_states[STAGE][0,-1].detach().float().cpu())
                ls.append(logits3(o).cpu())
            Q=torch.stack(qs);states[vals]={"m":Q.mean(0,keepdim=True),"C":center(Q)};base[vals]=torch.stack(ls)
        rows=[]
        for target in TEST:
            h3=donor_from([v for v in TEST if v!=target],target)
            h2=donor_from(TRAIN,target)
            if hamming(target,h3)!=3:raise RuntimeError(("expected h3",target,h3))
            if hamming(target,h2)!=2:raise RuntimeError(("expected h2",target,h2))
            rec_base=center(base[target])
            for label,donor in (("h3",h3),("h2",h2)):
                don_base=center(base[donor])
                series=[]
                for alpha in ALPHAS:
                    logs=[]
                    for q in range(3):
                        C=(1-alpha)*states[target]["C"][q:q+1]+alpha*states[donor]["C"][q:q+1]
                        x=states[target]["m"]+C
                        logs.append(replace_forward(prompt(names,tpl,target,q),x).cpu())
                    L=torch.stack(logs);CL=center(L)
                    series.append({
                        "alpha":alpha,
                        "recipient_cosine":cosflat(CL,rec_base),
                        "donor_cosine":cosflat(CL,don_base),
                        "recipient_candidate_accuracy":sum(COLORS[int(logs[q].argmax())]==target[q] for q in range(3))/3,
                        "donor_candidate_accuracy":sum(COLORS[int(logs[q].argmax())]==donor[q] for q in range(3))/3,
                    })
                rows.append({"target":target,"donor_type":label,"donor":donor,"hamming":hamming(target,donor),"series":series})
        h3rows=[r for r in rows if r["donor_type"]=="h3"]
        h2rows=[r for r in rows if r["donor_type"]=="h2"]
        alpha0_recipient=float(np.mean([r["series"][0]["recipient_cosine"]>r["series"][0]["donor_cosine"] for r in h3rows]))
        alpha1_h3_donor=float(np.mean([r["series"][-1]["donor_cosine"]>r["series"][-1]["recipient_cosine"] for r in h3rows]))
        donor_steps=[];recipient_steps=[]
        for r in h3rows:
            ds=[x["donor_cosine"] for x in r["series"]];rs=[x["recipient_cosine"] for x in r["series"]]
            donor_steps.extend(ds[i+1]>=ds[i] for i in range(len(ds)-1))
            recipient_steps.extend(rs[i+1]<=rs[i] for i in range(len(rs)-1))
        h3_donor_mono=float(np.mean(donor_steps));h3_rec_mono=float(np.mean(recipient_steps))
        h3_endpoint_donor=float(np.mean([r["series"][-1]["donor_cosine"] for r in h3rows]))
        h2_endpoint_donor=float(np.mean([r["series"][-1]["donor_cosine"] for r in h2rows]))
        means={}
        for label,rr in (("h3",h3rows),("h2",h2rows)):
            means[label]=[{"alpha":a,"recipient_cosine":float(np.mean([r["series"][i]["recipient_cosine"] for r in rr])),"donor_cosine":float(np.mean([r["series"][i]["donor_cosine"] for r in rr]))} for i,a in enumerate(ALPHAS)]
        summary={
            "alpha0_recipient_closer_fraction":alpha0_recipient,
            "alpha1_h3_donor_closer_fraction":alpha1_h3_donor,
            "h3_donor_cosine_monotonic_fraction":h3_donor_mono,
            "h3_recipient_cosine_monotonic_fraction":h3_rec_mono,
            "h3_endpoint_mean_donor_cosine":h3_endpoint_donor,
            "h2_endpoint_mean_donor_cosine":h2_endpoint_donor,
            "h3_minus_h2_endpoint_donor_cosine":h3_endpoint_donor-h2_endpoint_donor,
            "mean_curves":means,
        }
        summary["pass"]=bool(
            alpha0_recipient>=CRITERIA["alpha0_recipient_closer_fraction_min"] and
            alpha1_h3_donor>=CRITERIA["alpha1_h3_donor_closer_fraction_min"] and
            h3_donor_mono>=CRITERIA["h3_donor_cosine_monotonic_fraction_min"] and
            h3_rec_mono>=CRITERIA["h3_recipient_cosine_monotonic_fraction_min"]
        )
        result["templates"][tn]={"summary":summary,"assignments":rows}
        print(json.dumps({"template":tn,**summary},indent=2),flush=True)
    passes=sum(v["summary"]["pass"] for v in result["templates"].values());result["families_passing"]=passes;result["overall_pass"]=passes>=CRITERIA["min_families_passing"];result["seconds"]=time.time()-t0
    Path(args.out).write_text(json.dumps(result,indent=2))
    print("PASS21_SUMMARY",json.dumps({"overall_pass":result["overall_pass"],"families_passing":passes,"templates":{k:v["summary"] for k,v in result["templates"].items()},"criteria":CRITERIA},separators=(",",":")),flush=True)
if __name__=="__main__":main()
