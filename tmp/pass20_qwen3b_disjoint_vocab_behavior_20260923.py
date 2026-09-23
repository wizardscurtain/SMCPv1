import argparse, itertools, json, time
from pathlib import Path
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL="Qwen/Qwen2.5-3B"
REVISION="3aab1f1954e9cc14eb9509a215f9e5ca08227a9b"
VALUES=["cat","dog","bird"]

DEMO_PREFIX=(
"Facts: Ada's mascot is a horse. Bo's mascot is a rabbit. Cy's mascot is a fish.\n"
"Question: What animal is Bo's mascot?\nAnswer: rabbit\n\n"
"Facts: Dan's companion is a wolf. Eve's companion is a fox. Fay's companion is a deer.\n"
"Question: What animal is Fay's companion?\nAnswer: deer\n\n"
)

ELIGIBILITY={
"possessive_pet":{"names":["Lily","Tom","Ben"],"template":"Facts: {A}'s pet is a {Va}. {B}'s pet is a {Vb}. {C}'s pet is a {Vc}.\nQuestion: What animal is {Q}'s pet?\nAnswer:"},
"mascot_qa":{"names":["Lily","Tom","Ben"],"template":"Facts: {A} has a {Va} mascot. {B} has a {Vb} mascot. {C} has a {Vc} mascot.\nQuestion: What animal is {Q}'s mascot?\nAnswer:"},
"chosen_token":{"names":["Lily","Tom","Ben"],"template":"Facts: {A} chose the {Va} token. {B} chose the {Vb} token. {C} chose the {Vc} token.\nQuestion: Which animal token did {Q} choose?\nAnswer:"},
}
CONFIRMATION={
"companion_record":{"names":["Anna","Max","Sam"],"template":"Records: {A} -> companion={Va}; {B} -> companion={Vb}; {C} -> companion={Vc}.\nQuery: companion animal for {Q} ="},
"assigned_animal":{"names":["Anna","Max","Sam"],"template":"Records: {A} -> assigned animal={Va}; {B} -> assigned animal={Vb}; {C} -> assigned animal={Vc}.\nQuery: assigned animal for {Q} ="},
}
GATE={
"eligibility_pooled_min":0.75,
"eligibility_families_min_accuracy":2/3,
"eligibility_min_families":2,
"confirmation_pooled_min":0.70,
"confirmation_family_min_accuracy":2/3,
"confirmation_min_families":2,
}

def eval_family(model,tok,spec,device):
    names=spec["names"]; cand={}
    for v in VALUES:
        ids=tok.encode(" "+v,add_special_tokens=False)
        if len(ids)!=1: raise RuntimeError((v,ids))
        cand[v]=ids[0]
    rows=[]
    for vals in itertools.permutations(VALUES):
        for qi,qn in enumerate(names):
            item=spec["template"].format(A=names[0],B=names[1],C=names[2],Va=vals[0],Vb=vals[1],Vc=vals[2],Q=qn)
            prompt=DEMO_PREFIX+item
            enc=tok(prompt,return_tensors="pt").to(device)
            with torch.inference_mode(): logits=model(**enc,use_cache=False).logits[0,-1].float()
            scores={v:float(logits[i]) for v,i in cand.items()}
            pred=max(VALUES,key=lambda v:scores[v]); target=vals[qi]
            order=sorted(VALUES,key=lambda v:scores[v],reverse=True)
            topid=int(torch.argmax(logits))
            rows.append({"values":list(vals),"query":qn,"target":target,"candidate_pred":pred,
                         "candidate_correct":pred==target,"target_candidate_rank":order.index(target)+1,
                         "full_top1_token":tok.decode([topid]),"full_top1_is_target":topid==cand[target],
                         "candidate_scores":scores,"prompt":prompt})
    return {"n":len(rows),"candidate_accuracy":float(np.mean([r["candidate_correct"] for r in rows])),
            "full_top1_target_accuracy":float(np.mean([r["full_top1_is_target"] for r in rows])),
            "mean_target_candidate_rank":float(np.mean([r["target_candidate_rank"] for r in rows])),
            "candidate_prediction_counts":{v:sum(r["candidate_pred"]==v for r in rows) for v in VALUES},
            "rows":rows}

def pooled(d):
    rows=[r for f in d.values() for r in f["rows"]]
    return float(np.mean([r["candidate_correct"] for r in rows]))

def gate(e,c):
    ep,cp=pooled(e),pooled(c)
    ef=sum(v["candidate_accuracy"]>=GATE["eligibility_families_min_accuracy"] for v in e.values())
    cf=sum(v["candidate_accuracy"]>=GATE["confirmation_family_min_accuracy"] for v in c.values())
    ok=ep>=GATE["eligibility_pooled_min"] and ef>=GATE["eligibility_min_families"] and cp>=GATE["confirmation_pooled_min"] and cf>=GATE["confirmation_min_families"]
    return {"pass":bool(ok),"eligibility_pooled":ep,"eligibility_families_passing":ef,
            "confirmation_pooled":cp,"confirmation_families_passing":cf,"rule":GATE}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--out",default="/tmp/pass20_behavior.json"); args=ap.parse_args()
    out=Path(args.out); out.parent.mkdir(parents=True,exist_ok=True)
    tok=AutoTokenizer.from_pretrained(MODEL,revision=REVISION)
    model=AutoModelForCausalLM.from_pretrained(MODEL,revision=REVISION,torch_dtype=torch.float16).cuda().eval()
    e={k:eval_family(model,tok,v,"cuda") for k,v in ELIGIBILITY.items()}
    c={k:eval_family(model,tok,v,"cuda") for k,v in CONFIRMATION.items()}
    g=gate(e,c)
    result={"protocol":"Pass20 disjoint-vocabulary behavior gate; no hidden-state inspection",
            "model":MODEL,"revision":REVISION,"values":VALUES,"eligibility":e,"confirmation":c,"gate":g}
    out.write_text(json.dumps(result,indent=2))
    print("PASS20_SUMMARY",json.dumps({"model":MODEL,"revision":REVISION,"gate":g,
          "eligibility":{k:v["candidate_accuracy"] for k,v in e.items()},
          "confirmation":{k:v["candidate_accuracy"] for k,v in c.items()}},separators=(",",":")),flush=True)

if __name__=="__main__": main()
