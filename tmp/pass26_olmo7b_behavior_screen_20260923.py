import itertools,json
from pathlib import Path
import numpy as np,torch
from transformers import AutoTokenizer,AutoModelForCausalLM
MODEL="allenai/OLMo-2-1124-7B"
DOMAINS={
"color":{"vals":["red","blue","green"],"prefix":"Facts: Ada's mug is yellow. Bo's mug is purple. Cy's mug is orange.\nQuestion: What color is Bo's mug?\nAnswer: purple\n\nFacts: Dan's ring is black. Eve's ring is white. Fox's ring is brown.\nQuestion: What color is Fox's ring?\nAnswer: brown\n\n","ef":{"ball":(["Lily","Tom","Ben"],"Facts: {A}'s ball is {Va}. {B}'s ball is {Vb}. {C}'s ball is {Vc}.\nQuestion: What color is {Q}'s ball?\nAnswer:"),"hat":(["Lily","Tom","Ben"],"Facts: {A} has a {Va} hat. {B} has a {Vb} hat. {C} has a {Vc} hat.\nQuestion: What color is {Q}'s hat?\nAnswer:"),"bag":(["Lily","Tom","Ben"],"Facts: {A} carries a {Va} bag. {B} carries a {Vb} bag. {C} carries a {Vc} bag.\nQuestion: What color is the bag carried by {Q}?\nAnswer:")},"cf":{"coat":(["Anna","Max","Sam"],"Records: {A} -> coat={Va}; {B} -> coat={Vb}; {C} -> coat={Vc}.\nQuery: coat color for {Q} ="),"cup":(["Anna","Max","Sam"],"Records: {A} -> chosen cup={Va}; {B} -> chosen cup={Vb}; {C} -> chosen cup={Vc}.\nQuery: chosen cup color for {Q} =")}},
"animal":{"vals":["cat","dog","bird"],"prefix":"Facts: Ada's mascot is a horse. Bo's mascot is a rabbit. Cy's mascot is a fish.\nQuestion: What animal is Bo's mascot?\nAnswer: rabbit\n\nFacts: Dan's companion is a wolf. Eve's companion is a fox. Fay's companion is a deer.\nQuestion: What animal is Fay's companion?\nAnswer: deer\n\n","ef":{"pet":(["Lily","Tom","Ben"],"Facts: {A}'s pet is a {Va}. {B}'s pet is a {Vb}. {C}'s pet is a {Vc}.\nQuestion: What animal is {Q}'s pet?\nAnswer:"),"mascot":(["Lily","Tom","Ben"],"Facts: {A} has a {Va} mascot. {B} has a {Vb} mascot. {C} has a {Vc} mascot.\nQuestion: What animal is {Q}'s mascot?\nAnswer:"),"token":(["Lily","Tom","Ben"],"Facts: {A} chose the {Va} token. {B} chose the {Vb} token. {C} chose the {Vc} token.\nQuestion: Which animal token did {Q} choose?\nAnswer:")},"cf":{"companion":(["Anna","Max","Sam"],"Records: {A} -> companion={Va}; {B} -> companion={Vb}; {C} -> companion={Vc}.\nQuery: companion animal for {Q} ="),"assigned":(["Anna","Max","Sam"],"Records: {A} -> assigned animal={Va}; {B} -> assigned animal={Vb}; {C} -> assigned animal={Vc}.\nQuery: assigned animal for {Q} =")}}}
G={"ep":.75,"efa":2/3,"efn":2,"cp":.70,"cfa":2/3,"cfn":2}
def fam(model,tok,d,names,tpl):
 vals=d["vals"];ids={v:tok.encode(" "+v,add_special_tokens=False) for v in vals}
 if any(len(z)!=1 for z in ids.values()):raise RuntimeError(ids)
 ids={k:v[0] for k,v in ids.items()};rows=[]
 for p in itertools.permutations(vals):
  for qi,q in enumerate(names):
   item=tpl.format(A=names[0],B=names[1],C=names[2],Va=p[0],Vb=p[1],Vc=p[2],Q=q)
   e=tok(d["prefix"]+item,return_tensors="pt").to("cuda")
   with torch.inference_mode():z=model(**e,use_cache=False).logits[0,-1].float()
   sc={v:float(z[i]) for v,i in ids.items()};pred=max(vals,key=lambda v:sc[v]);rows.append(pred==p[qi])
 return {"n":len(rows),"accuracy":float(np.mean(rows))}
def main():
 tok=AutoTokenizer.from_pretrained(MODEL);model=AutoModelForCausalLM.from_pretrained(MODEL,torch_dtype=torch.float16).cuda().eval()
 out={"protocol":"Pass26 independent-model behavior-only screen; frozen color and animal gates","model":MODEL,"revision":getattr(model.config,"_commit_hash",None),"domains":{}}
 for name,d in DOMAINS.items():
  e={k:fam(model,tok,d,*v) for k,v in d["ef"].items()};c={k:fam(model,tok,d,*v) for k,v in d["cf"].items()}
  ep=float(np.mean([x["accuracy"] for x in e.values()]));cp=float(np.mean([x["accuracy"] for x in c.values()]))
  ef=sum(x["accuracy"]>=G["efa"] for x in e.values());cf=sum(x["accuracy"]>=G["cfa"] for x in c.values())
  gate=bool(ep>=G["ep"] and ef>=G["efn"] and cp>=G["cp"] and cf>=G["cfn"])
  out["domains"][name]={"eligibility":e,"confirmation":c,"eligibility_pooled":ep,"confirmation_pooled":cp,"eligibility_families_passing":ef,"confirmation_families_passing":cf,"pass":gate}
  print(name,json.dumps(out["domains"][name],separators=(",",":")),flush=True)
 out["mechanistic_allowed"]=bool(out["domains"]["color"]["pass"]);out["dual_domain_allowed"]=bool(out["domains"]["color"]["pass"] and out["domains"]["animal"]["pass"])
 Path("/tmp/pass26.json").write_text(json.dumps(out,indent=2));print("PASS26_SUMMARY",json.dumps({"model":MODEL,"revision":out["revision"],"mechanistic_allowed":out["mechanistic_allowed"],"dual_domain_allowed":out["dual_domain_allowed"],"domains":out["domains"]},separators=(",",":")),flush=True)
if __name__=="__main__":main()
