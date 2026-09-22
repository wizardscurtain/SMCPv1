import argparse, itertools, json, time
from pathlib import Path
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL = "Qwen/Qwen2.5-3B"
REVISION = "3aab1f1954e9cc14eb9509a215f9e5ca08227a9b"
STAGE = 27
BLOCK_INDEX = 26
COLORS = ["red", "blue", "green"]
TEMPLATES = {
    "facts_question_ball": (["Lily","Tom","Ben"], "Facts:\n{A}'s ball is {Va}.\n{B}'s ball is {Vb}.\n{C}'s ball is {Vc}.\nQuestion: What color is {Q}'s ball?\nAnswer:"),
    "worked_example_box": (["Lily","Tom","Ben"], "Example: Nora's key is yellow. Omar's key is purple. Pia's key is orange.\nQuestion: What color is Omar's key? Answer: purple\n\nNew facts: {A}'s box is {Va}. {B}'s box is {Vb}. {C}'s box is {Vc}.\nQuestion: What color is {Q}'s box? Answer:"),
    "facts_question_coat": (["Anna","Max","Sam"], "Facts:\n{A} wears a {Va} coat.\n{B} wears a {Vb} coat.\n{C} wears a {Vc} coat.\nQuestion: What color coat does {Q} wear?\nAnswer:"),
}
TRAIN = [
    ("red","blue","green"),
    ("blue","green","red"),
    ("green","red","blue"),
]
TEST = [
    ("red","green","blue"),
    ("blue","red","green"),
    ("green","blue","red"),
]
CRITERIA = {
    "reconstruction_mean_recipient_cosine_min": 0.95,
    "reconstruction_recipient_closer_fraction_min": 0.80,
    "wrong_plane_mean_donor_cosine_min": 0.80,
    "wrong_plane_donor_closer_fraction_min": 0.67,
    "jvp_to_nonlinear_mean_cosine_min": 0.90,
    "jvp_to_recipient_mean_cosine_min": 0.90,
    "min_families_passing": 2,
}

def center(x):
    return x - x.mean(0, keepdim=True)

def cosflat(a,b):
    a=a.reshape(-1).float(); b=b.reshape(-1).float()
    return float((a@b/(torch.linalg.norm(a)*torch.linalg.norm(b)+1e-12)).item())

def prompt(names,tpl,vals,q):
    return tpl.format(A=names[0],B=names[1],C=names[2],Va=vals[0],Vb=vals[1],Vc=vals[2],Q=names[q])

def donor_for(vals):
    cands=TRAIN
    return max(cands,key=lambda d:(sum(a!=b for a,b in zip(vals,d)),d))

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--out",default="/tmp/pass20c.json"); ap.add_argument("--device",default="cuda" if torch.cuda.is_available() else "cpu"); args=ap.parse_args()
    device=args.device
    tok=AutoTokenizer.from_pretrained(MODEL,revision=REVISION)
    dtype=torch.float32
    model=AutoModelForCausalLM.from_pretrained(MODEL,revision=REVISION,torch_dtype=dtype,attn_implementation="eager").to(device).eval()
    for p in model.parameters(): p.requires_grad_(False)
    cids={}
    for c in COLORS:
        ids=tok.encode(" "+c,add_special_tokens=False)
        if len(ids)!=1: raise RuntimeError((c,ids))
        cids[c]=ids[0]
    layers=model.model.layers

    def logits3(o):
        vals=torch.stack([o.logits[0,-1,cids[c]].float() for c in COLORS])
        if not torch.isfinite(vals).all(): raise RuntimeError("non-finite candidate logits")
        return vals

    def full_forward(p, hidden=False):
        enc=tok(p,return_tensors="pt"); enc={k:v.to(device) for k,v in enc.items()}
        return model(**enc,output_hidden_states=hidden,use_cache=False)

    def replace_forward(p,x, require_grad=False):
        block=layers[BLOCK_INDEX]
        def hook(mod,inp,out):
            first=out[0] if isinstance(out,tuple) else out
            xx=x.to(device=first.device,dtype=first.dtype).reshape(1,1,-1)
            y=torch.cat([first[:,:-1,:],xx],dim=1)
            return (y,)+out[1:] if isinstance(out,tuple) else y
        h=block.register_forward_hook(hook)
        try:
            o=full_forward(p,hidden=False)
            return logits3(o)
        finally:
            h.remove()

    result={"protocol":"Pass20c Qwen3B earliest-common-stage held-out prototype centroid and local-Jacobian test","model":MODEL,"revision":REVISION,"stage":STAGE,"block_index":BLOCK_INDEX,"train_assignments":TRAIN,"test_assignments":TEST,"criteria":CRITERIA,"templates":{},"overall_pass":False}
    t0=time.time()
    for tn,(names,tpl) in TEMPLATES.items():
        print("===",tn,"===",flush=True)
        states={}; base_logits={}
        for vals in TRAIN+TEST:
            qs=[]; ls=[]
            for q in range(3):
                o=full_forward(prompt(names,tpl,vals,q),hidden=True)
                qs.append(o.hidden_states[STAGE][0,-1].detach().float().cpu())
                ls.append(logits3(o).detach().cpu())
            Q=torch.stack(qs); states[vals]={"m":Q.mean(0,keepdim=True),"C":center(Q)}
            base_logits[vals]=torch.stack(ls)
            # Baseline errors are allowed because Pass20a qualifies the family statistically; finite logits remain mandatory.
        proto_m=torch.stack([states[v]["m"][0] for v in TRAIN]).mean(0,keepdim=True)
        rows=[]
        for vals in TEST:
            donor=donor_for(vals)
            actual_m=states[vals]["m"]; actual_C=states[vals]["C"]; donor_C=states[donor]["C"]
            rec_base=center(base_logits[vals]); don_base=center(base_logits[donor])
            rec_logs=[]; wrong_logs=[]; jvp_logs=[]
            for q in range(3):
                ptxt=prompt(names,tpl,vals,q)
                x_recon=(proto_m+actual_C[q:q+1]).to(device)
                rec_logs.append(replace_forward(ptxt,x_recon).detach().cpu())
                x_wrong=(actual_m+donor_C[q:q+1]).to(device)
                wrong_logs.append(replace_forward(ptxt,x_wrong).detach().cpu())
                m0=proto_m[0].to(device=device,dtype=torch.float32).requires_grad_(True)
                v=actual_C[q].to(device=device,dtype=torch.float32)
                def f(x):
                    return replace_forward(ptxt,x)
                base,deriv=torch.autograd.functional.jvp(f,(m0,),(v,),create_graph=False,strict=False)
                jvp_logs.append((base+deriv).detach().cpu())
            rec=center(torch.stack(rec_logs)); wrong=center(torch.stack(wrong_logs)); jvp=center(torch.stack(jvp_logs))
            row={
                "assignment":vals,"donor_training_assignment":donor,
                "reconstruction_recipient_cosine":cosflat(rec,rec_base),
                "reconstruction_donor_cosine":cosflat(rec,don_base),
                "wrong_plane_recipient_cosine":cosflat(wrong,rec_base),
                "wrong_plane_donor_cosine":cosflat(wrong,don_base),
                "jvp_to_nonlinear_reconstruction_cosine":cosflat(jvp,rec),
                "jvp_to_recipient_baseline_cosine":cosflat(jvp,rec_base),
                "reconstruction_candidate_accuracy":sum(COLORS[int(x.argmax())]==vals[q] for q,x in enumerate(rec_logs))/3,
                "wrong_plane_donor_candidate_accuracy":sum(COLORS[int(x.argmax())]==donor[q] for q,x in enumerate(wrong_logs))/3,
            }
            rows.append(row)
        baseline_test_accuracy=float(np.mean([
            COLORS[int(base_logits[vals][q].argmax())] == vals[q]
            for vals in TEST for q in range(3)
        ]))
        summary={
            "baseline_test_candidate_accuracy":baseline_test_accuracy,
            "reconstruction_mean_recipient_cosine":float(np.mean([r["reconstruction_recipient_cosine"] for r in rows])),
            "reconstruction_recipient_closer_fraction":float(np.mean([r["reconstruction_recipient_cosine"]>r["reconstruction_donor_cosine"] for r in rows])),
            "wrong_plane_mean_donor_cosine":float(np.mean([r["wrong_plane_donor_cosine"] for r in rows])),
            "wrong_plane_donor_closer_fraction":float(np.mean([r["wrong_plane_donor_cosine"]>r["wrong_plane_recipient_cosine"] for r in rows])),
            "jvp_to_nonlinear_mean_cosine":float(np.mean([r["jvp_to_nonlinear_reconstruction_cosine"] for r in rows])),
            "jvp_to_recipient_mean_cosine":float(np.mean([r["jvp_to_recipient_baseline_cosine"] for r in rows])),
            "reconstruction_candidate_accuracy":float(np.mean([r["reconstruction_candidate_accuracy"] for r in rows])),
            "wrong_plane_donor_candidate_accuracy":float(np.mean([r["wrong_plane_donor_candidate_accuracy"] for r in rows])),
        }
        summary["pass"]=bool(
            summary["reconstruction_mean_recipient_cosine"]>=CRITERIA["reconstruction_mean_recipient_cosine_min"] and
            summary["reconstruction_recipient_closer_fraction"]>=CRITERIA["reconstruction_recipient_closer_fraction_min"] and
            summary["wrong_plane_mean_donor_cosine"]>=CRITERIA["wrong_plane_mean_donor_cosine_min"] and
            summary["wrong_plane_donor_closer_fraction"]>=CRITERIA["wrong_plane_donor_closer_fraction_min"] and
            summary["jvp_to_nonlinear_mean_cosine"]>=CRITERIA["jvp_to_nonlinear_mean_cosine_min"] and
            summary["jvp_to_recipient_mean_cosine"]>=CRITERIA["jvp_to_recipient_mean_cosine_min"]
        )
        result["templates"][tn]={"prototype_centroid_norm":float(torch.linalg.norm(proto_m).item()),"summary":summary,"held_out":rows}
        print(json.dumps({"template":tn,**summary},indent=2),flush=True)
    passes=sum(v["summary"]["pass"] for v in result["templates"].values())
    result["families_passing"]=passes; result["overall_pass"]=passes>=CRITERIA["min_families_passing"]; result["seconds"]=time.time()-t0
    Path(args.out).write_text(json.dumps(result,indent=2))
    print("PASS19_SUMMARY",json.dumps({"overall_pass":result["overall_pass"],"families_passing":passes,"templates":{k:v["summary"] for k,v in result["templates"].items()},"criteria":CRITERIA},separators=(",",":")),flush=True)

if __name__=="__main__":
    main()
