import argparse, itertools, json, time
from pathlib import Path
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODELS = [
    "EleutherAI/pythia-1b",
    "Qwen/Qwen2.5-0.5B",
]
COLORS = ["red", "blue", "green"]

ELIGIBILITY = {
    "direct_qa_ball": {
        "names": ["Lily", "Tom", "Ben"],
        "template": "Facts:\n{A}'s ball is {Va}.\n{B}'s ball is {Vb}.\n{C}'s ball is {Vc}.\nQuestion: What color is {Q}'s ball?\nAnswer:",
    },
    "table_lookup_badge": {
        "names": ["Lily", "Tom", "Ben"],
        "template": "Badge-color bindings:\n{A} = {Va}\n{B} = {Vb}\n{C} = {Vc}\nLookup {Q} =",
    },
    "worked_example_box": {
        "names": ["Lily", "Tom", "Ben"],
        "template": (
            "Example:\nNora's key is yellow. Omar's key is purple. Pia's key is orange.\n"
            "Question: What color is Omar's key?\nAnswer: purple\n\n"
            "Now solve:\n{A}'s box is {Va}. {B}'s box is {Vb}. {C}'s box is {Vc}.\n"
            "Question: What color is {Q}'s box?\nAnswer:"
        ),
    },
}

CONFIRMATION = {
    "direct_qa_coat": {
        "names": ["Anna", "Max", "Sam"],
        "template": "Facts:\n{A} wears a {Va} coat.\n{B} wears a {Vb} coat.\n{C} wears a {Vc} coat.\nQuestion: What color coat does {Q} wear?\nAnswer:",
    },
    "table_lookup_cup": {
        "names": ["Anna", "Max", "Sam"],
        "template": "Cup colors:\n{A}:{Va}\n{B}:{Vb}\n{C}:{Vc}\nQuery[{Q}] ->",
    },
    "worked_example_ring": {
        "names": ["Anna", "Max", "Sam"],
        "template": (
            "Example:\nIvy chose a yellow scarf. Leo chose a purple scarf. Mia chose an orange scarf.\n"
            "Asked: Leo's scarf color.\nAnswer: purple\n\n"
            "New facts:\n{A} chose a {Va} ring. {B} chose a {Vb} ring. {C} chose a {Vc} ring.\n"
            "Asked: {Q}'s ring color.\nAnswer:"
        ),
    },
}

GATE = {
    "eligibility_pooled_min": 0.80,
    "eligibility_family_min": 0.80,
    "eligibility_min_families": 2,
    "confirmation_pooled_min": 0.80,
    "confirmation_family_min": 0.80,
    "confirmation_min_families": 2,
}

def eval_family(model, tok, spec, device):
    names = spec["names"]
    candidate_ids = {}
    for color in COLORS:
        ids = tok.encode(" " + color, add_special_tokens=False)
        if len(ids) != 1:
            raise RuntimeError(f"candidate {color!r} is not one token for {tok.name_or_path}: {ids}")
        candidate_ids[color] = ids[0]
    rows=[]
    for vals in itertools.permutations(COLORS):
        for qi, qn in enumerate(names):
            prompt = spec["template"].format(A=names[0], B=names[1], C=names[2], Va=vals[0], Vb=vals[1], Vc=vals[2], Q=qn)
            enc = tok(prompt, return_tensors="pt").to(device)
            with torch.inference_mode():
                logits = model(**enc, use_cache=False).logits[0,-1].float()
            scores={c:float(logits[i].item()) for c,i in candidate_ids.items()}
            pred=max(COLORS,key=lambda c:scores[c]); target=vals[qi]
            rows.append({"values":list(vals),"query":qn,"target":target,"pred":pred,"correct":pred==target,"scores":scores,"prompt":prompt})
    by_perm=[]
    for vals in itertools.permutations(COLORS):
        rs=[r for r in rows if tuple(r["values"])==vals]
        by_perm.append(all(r["correct"] for r in rs))
    return {
        "n":len(rows),
        "accuracy":float(np.mean([r["correct"] for r in rows])),
        "complete_permutation_fraction":float(np.mean(by_perm)),
        "prediction_counts":{c:sum(r["pred"]==c for r in rows) for c in COLORS},
        "rows":rows,
    }

def pooled(fams):
    rows=[r for f in fams.values() for r in f["rows"]]
    return float(np.mean([r["correct"] for r in rows]))

def gate(elig, conf):
    ep=pooled(elig); cp=pooled(conf)
    ef=sum(v["accuracy"]>=GATE["eligibility_family_min"] for v in elig.values())
    cf=sum(v["accuracy"]>=GATE["confirmation_family_min"] for v in conf.values())
    ok=(ep>=GATE["eligibility_pooled_min"] and ef>=GATE["eligibility_min_families"] and cp>=GATE["confirmation_pooled_min"] and cf>=GATE["confirmation_min_families"])
    return {"pass":bool(ok),"eligibility_pooled":ep,"eligibility_families_passing":ef,"confirmation_pooled":cp,"confirmation_families_passing":cf,"rule":GATE}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--out",default="/tmp/pass15.json"); ap.add_argument("--device",default="cuda" if torch.cuda.is_available() else "cpu"); args=ap.parse_args()
    out=Path(args.out); result={"protocol":"Pass15 behavior-only observable bridge; no hidden-state inspection","models":{},"selected_model":None}
    for mid in MODELS:
        t0=time.time(); print(f"=== {mid} ===",flush=True)
        tok=AutoTokenizer.from_pretrained(mid)
        model=AutoModelForCausalLM.from_pretrained(mid).to(args.device).eval()
        elig={k:eval_family(model,tok,v,args.device) for k,v in ELIGIBILITY.items()}
        conf={k:eval_family(model,tok,v,args.device) for k,v in CONFIRMATION.items()}
        g=gate(elig,conf)
        cfg={"hidden_size":getattr(model.config,"hidden_size",None),"num_hidden_layers":getattr(model.config,"num_hidden_layers",None),"num_attention_heads":getattr(model.config,"num_attention_heads",None),"revision":getattr(model.config,"_commit_hash",None)}
        result["models"][mid]={"config":cfg,"eligibility":elig,"confirmation":conf,"gate":g,"seconds":time.time()-t0}
        print(json.dumps({"model":mid,"gate":g,"config":cfg,"families":{"eligibility":{k:v['accuracy'] for k,v in elig.items()},"confirmation":{k:v['accuracy'] for k,v in conf.items()}}},indent=2),flush=True)
        out.write_text(json.dumps(result,indent=2))
        del model
        if torch.cuda.is_available(): torch.cuda.empty_cache()
        if g["pass"]:
            result["selected_model"]=mid; break
    out.write_text(json.dumps(result,indent=2)); print(json.dumps({"selected_model":result["selected_model"]},indent=2),flush=True)
if __name__=="__main__": main()
