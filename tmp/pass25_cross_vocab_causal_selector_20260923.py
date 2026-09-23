import itertools,json
from pathlib import Path
import numpy as np, torch
from transformers import AutoTokenizer,AutoModelForCausalLM
MODEL="Qwen/Qwen2.5-3B";REV="3aab1f1954e9cc14eb9509a215f9e5ca08227a9b";LAYERS=[20,27,28,31,34];SEED=2525
DOMAINS={
"color":{"vals":["red","blue","green"],"prefix":"Facts: Ada's mug is yellow. Bo's mug is purple. Cy's mug is orange.\nQuestion: What color is Bo's mug?\nAnswer: purple\n\nFacts: Dan's ring is black. Eve's ring is white. Fox's ring is brown.\nQuestion: What color is Fox's ring?\nAnswer: brown\n\n",
"fams":{"ball":("eligibility",["Lily","Tom","Ben"],"Facts: {A}'s ball is {Va}. {B}'s ball is {Vb}. {C}'s ball is {Vc}.\nQuestion: What color is {Q}'s ball?\nAnswer:"),"hat":("eligibility",["Lily","Tom","Ben"],"Facts: {A} has a {Va} hat. {B} has a {Vb} hat. {C} has a {Vc} hat.\nQuestion: What color is {Q}'s hat?\nAnswer:"),"bag":("eligibility",["Lily","Tom","Ben"],"Facts: {A} carries a {Va} bag. {B} carries a {Vb} bag. {C} carries a {Vc} bag.\nQuestion: What color is the bag carried by {Q}?\nAnswer:"),"coat":("confirmation",["Anna","Max","Sam"],"Records: {A} -> coat={Va}; {B} -> coat={Vb}; {C} -> coat={Vc}.\nQuery: coat color for {Q} ="),"cup":("confirmation",["Anna","Max","Sam"],"Records: {A} -> chosen cup={Va}; {B} -> chosen cup={Vb}; {C} -> chosen cup={Vc}.\nQuery: chosen cup color for {Q} =")}},
"animal":{"vals":["cat","dog","bird"],"prefix":"Facts: Ada's mascot is a horse. Bo's mascot is a rabbit. Cy's mascot is a fish.\nQuestion: What animal is Bo's mascot?\nAnswer: rabbit\n\nFacts: Dan's companion is a wolf. Eve's companion is a fox. Fay's companion is a deer.\nQuestion: What animal is Fay's companion?\nAnswer: deer\n\n",
"fams":{"pet":("eligibility",["Lily","Tom","Ben"],"Facts: {A}'s pet is a {Va}. {B}'s pet is a {Vb}. {C}'s pet is a {Vc}.\nQuestion: What animal is {Q}'s pet?\nAnswer:"),"mascot":("eligibility",["Lily","Tom","Ben"],"Facts: {A} has a {Va} mascot. {B} has a {Vb} mascot. {C} has a {Vc} mascot.\nQuestion: What animal is {Q}'s mascot?\nAnswer:"),"token":("eligibility",["Lily","Tom","Ben"],"Facts: {A} chose the {Va} token. {B} chose the {Vb} token. {C} chose the {Vc} token.\nQuestion: Which animal token did {Q} choose?\nAnswer:"),"companion":("confirmation",["Anna","Max","Sam"],"Records: {A} -> companion={Va}; {B} -> companion={Vb}; {C} -> companion={Vc}.\nQuery: companion animal for {Q} ="),"assigned":("confirmation",["Anna","Max","Sam"],"Records: {A} -> assigned animal={Va}; {B} -> assigned animal={Vb}; {C} -> assigned animal={Vc}.\nQuery: assigned animal for {Q} =")}}}

def build(dom):
 d=DOMAINS[dom];out=[]
 for fam,(sp,names,tpl) in d["fams"].items():
  for pi,v in enumerate(itertools.permutations(d["vals"])):
   for qi,q in enumerate(names):
    item=tpl.format(A=names[0],B=names[1],C=names[2],Va=v[0],Vb=v[1],Vc=v[2],Q=q)
    out.append({"family":fam,"split":sp,"perm":pi,"qi":qi,"target":v[qi],"prompt":d["prefix"]+item})
 return out
def center(x,rr):
 o=np.empty_like(x);g={}
 for i,r in enumerate(rr):g.setdefault((r["family"],r["perm"]),[]).append(i)
 for ix in g.values():o[ix]=x[ix]-x[ix].mean(0,keepdims=True)
 return o
def basis(x,y,classes):
 m=np.stack([x[np.array(y,dtype=object)==c].mean(0) for c in classes]);m-=m.mean(0,keepdims=True)
 _,s,vt=np.linalg.svd(m,full_matrices=False);return vt[:min(2,int(np.sum(s>1e-7)))].T
def orth(a,b):
 if b.size:a=a-b@(b.T@a)
 q,r=np.linalg.qr(a);keep=np.abs(np.diag(r))>1e-6;return q[:,keep]
def proj(d,b):return b@(b.T@d) if b.shape[1] else np.zeros_like(d)
def scores(logits,cids,vals):return np.array([float(logits[cids[v]]) for v in vals])
def run(model,tok,prompt,l,vec,cids,vals):
 e=tok(prompt,return_tensors="pt").to("cuda");block=model.model.layers[l-1]
 def hk(m,i,o):
  h=o[0] if isinstance(o,tuple) else o;h=h.clone();h[:,-1,:]=torch.as_tensor(vec,device=h.device,dtype=h.dtype);return (h,)+o[1:] if isinstance(o,tuple) else h
 hd=block.register_forward_hook(hk)
 try:
  with torch.inference_mode():z=model(**e,use_cache=False).logits[0,-1].float()
 finally:hd.remove()
 return scores(z,cids,vals)
def boot(a,b,rng,n=1500):
 d=np.asarray(a)-np.asarray(b);N=len(d);m=[float(d[rng.integers(0,N,N)].mean()) for _ in range(n)]
 return {"mean":float(d.mean()),"lo":float(np.quantile(m,.025)),"hi":float(np.quantile(m,.975))}
def summ(rs,t):
 z=[r for r in rs if r["type"]==t];return {"mean":float(np.mean([r["dm"] for r in z])),"positive":float(np.mean([r["dm"]>0 for r in z])),"donor_pred":float(np.mean([r["pred"]==r["donor"] for r in z]))}

def main():
 np.random.seed(SEED);torch.manual_seed(SEED);rng=np.random.default_rng(SEED)
 tok=AutoTokenizer.from_pretrained(MODEL,revision=REV);model=AutoModelForCausalLM.from_pretrained(MODEL,revision=REV,torch_dtype=torch.float16).cuda().eval()
 data={d:build(d) for d in DOMAINS};states={};clean={};cids={}
 for dom in DOMAINS:
  vals=DOMAINS[dom]["vals"];cids[dom]={v:tok.encode(" "+v,add_special_tokens=False)[0] for v in vals};states[dom]={l:[] for l in LAYERS};clean[dom]=[]
  for r in data[dom]:
   e=tok(r["prompt"],return_tensors="pt").to("cuda")
   with torch.inference_mode():o=model(**e,use_cache=False,output_hidden_states=True)
   for l in LAYERS:states[dom][l].append(o.hidden_states[l][0,-1].float().cpu().numpy())
   clean[dom].append(scores(o.logits[0,-1].float(),cids[dom],vals))
  states[dom]={l:np.stack(v) for l,v in states[dom].items()};clean[dom]=np.stack(clean[dom]);print("CAPTURED",dom,flush=True)
 results={}
 for source,target in (("color","animal"),("animal","color")):
  key=source+"_to_"+target;results[key]={};vals=DOMAINS[target]["vals"];rr=data[target];src=data[source]
  si=np.array([i for i,r in enumerate(src) if r["split"]=="eligibility"]);ti=np.array([i for i,r in enumerate(rr) if r["split"]=="eligibility"]);tc=[i for i,r in enumerate(rr) if r["split"]=="confirmation"]
  sq=np.array([r["qi"] for r in src],dtype=object);tq=np.array([r["qi"] for r in rr],dtype=object);tv=np.array([r["target"] for r in rr],dtype=object)
  for l in LAYERS:
   So=center(states[source][l],src);To=center(states[target][l],rr)
   Qsrc=basis(So[si],sq[si],[0,1,2]);Qnative=basis(To[ti],tq[ti],[0,1,2]);Vtarget=basis(To[ti],tv[ti],vals)
   Qx=orth(Qsrc,Vtarget);Qn=orth(Qnative,Vtarget);rs=[]
   for ri in tc:
    r=rr[ri];dq=(r["qi"]+1)%3;di=next(j for j,x in enumerate(rr) if x["family"]==r["family"] and x["perm"]==r["perm"] and x["qi"]==dq);d=rr[di];diff=states[target][l][di]-states[target][l][ri]
    xd=proj(diff,Qx);nd=proj(diff,Qn);rand=rng.normal(size=diff.shape).astype(np.float32);both=np.concatenate([Qx,Vtarget],axis=1)
    if both.shape[1]:rand-=both@(both.T@rand)
    rand=rand/(np.linalg.norm(rand)+1e-12)*(np.linalg.norm(xd)+1e-12)
    patches={"cross_query":states[target][l][ri]+xd,"native_query":states[target][l][ri]+nd,"random":states[target][l][ri]+rand,"full":states[target][l][di]}
    a=vals.index(r["target"]);b=vals.index(d["target"]);base=float(clean[target][ri,b]-clean[target][ri,a])
    for typ,v in patches.items():
     sc=run(model,tok,r["prompt"],l,v,cids[target],vals);rs.append({"type":typ,"dm":float((sc[b]-sc[a])-base),"pred":vals[int(np.argmax(sc))],"donor":d["target"]})
   s={t:summ(rs,t) for t in ("cross_query","native_query","random","full")}
   ca=[r["dm"] for r in rs if r["type"]=="cross_query"];ra=[r["dm"] for r in rs if r["type"]=="random"];na=[r["dm"] for r in rs if r["type"]=="native_query"]
   s["cross_minus_random"]=boot(ca,ra,rng);s["cross_minus_native"]=boot(ca,na,rng)
   s["gate"]=bool(l<=28 and s["full"]["positive"]>=.85 and s["cross_query"]["positive"]>=.80 and s["cross_query"]["donor_pred"]>=.50 and s["cross_minus_random"]["lo"]>0 and s["cross_query"]["mean"]>=.5*max(s["native_query"]["mean"],1e-9))
   results[key][str(l)]=s;print(key,l,json.dumps(s,separators=(",",":")),flush=True)
 both=[l for l in LAYERS if results["color_to_animal"][str(l)]["gate"] and results["animal_to_color"][str(l)]["gate"]]
 bestearly=max([results["color_to_animal"][str(l)]["cross_query"]["mean"]+results["animal_to_color"][str(l)]["cross_query"]["mean"] for l in LAYERS if l<=28])
 late=results["color_to_animal"]["34"]["cross_query"]["mean"]+results["animal_to_color"]["34"]["cross_query"]["mean"]
 out={"protocol":"Pass25 cross-vocabulary causal selector transfer; source-domain query basis, target-domain held-out interventions","model":MODEL,"revision":REV,"layers":LAYERS,"results":results,"bidirectional_passing_layers":both,"shared_causal_selector_gate":bool(both),"late_selector_silencing_ratio":float(late/(bestearly+1e-12))}
 Path("/tmp/pass25.json").write_text(json.dumps(out,indent=2));print("PASS25_SUMMARY",json.dumps({"bidirectional_passing_layers":both,"shared_causal_selector_gate":out["shared_causal_selector_gate"],"late_selector_silencing_ratio":out["late_selector_silencing_ratio"]},separators=(",",":")),flush=True)
if __name__=="__main__":main()
