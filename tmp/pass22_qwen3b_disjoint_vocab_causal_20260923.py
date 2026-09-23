import itertools, json
from pathlib import Path
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL="Qwen/Qwen2.5-3B"; REVISION="3aab1f1954e9cc14eb9509a215f9e5ca08227a9b"
VALUES=["cat","dog","bird"]; LAYERS=[23,28,29,31,33,34]; SEED=2222
DEMO_PREFIX=(
"Facts: Ada's mascot is a horse. Bo's mascot is a rabbit. Cy's mascot is a fish.\n"
"Question: What animal is Bo's mascot?\nAnswer: rabbit\n\n"
"Facts: Dan's companion is a wolf. Eve's companion is a fox. Fay's companion is a deer.\n"
"Question: What animal is Fay's companion?\nAnswer: deer\n\n")
FAMILIES={
"possessive_pet":("eligibility",["Lily","Tom","Ben"],"Facts: {A}'s pet is a {Va}. {B}'s pet is a {Vb}. {C}'s pet is a {Vc}.\nQuestion: What animal is {Q}'s pet?\nAnswer:"),
"mascot_qa":("eligibility",["Lily","Tom","Ben"],"Facts: {A} has a {Va} mascot. {B} has a {Vb} mascot. {C} has a {Vc} mascot.\nQuestion: What animal is {Q}'s mascot?\nAnswer:"),
"chosen_token":("eligibility",["Lily","Tom","Ben"],"Facts: {A} chose the {Va} token. {B} chose the {Vb} token. {C} chose the {Vc} token.\nQuestion: Which animal token did {Q} choose?\nAnswer:"),
"companion_record":("confirmation",["Anna","Max","Sam"],"Records: {A} -> companion={Va}; {B} -> companion={Vb}; {C} -> companion={Vc}.\nQuery: companion animal for {Q} ="),
"assigned_animal":("confirmation",["Anna","Max","Sam"],"Records: {A} -> assigned animal={Va}; {B} -> assigned animal={Vb}; {C} -> assigned animal={Vc}.\nQuery: assigned animal for {Q} =")}

def rows():
 out=[]
 for fam,(split,names,tpl) in FAMILIES.items():
  for pi,vals in enumerate(itertools.permutations(VALUES)):
   for qi,qn in enumerate(names):
    item=tpl.format(A=names[0],B=names[1],C=names[2],Va=vals[0],Vb=vals[1],Vc=vals[2],Q=qn)
    out.append({"family":fam,"split":split,"perm_i":pi,"qi":qi,"target":vals[qi],"prompt":DEMO_PREFIX+item})
 return out

def center(x,rr):
 out=np.empty_like(x); g={}
 for i,r in enumerate(rr): g.setdefault((r["family"],r["perm_i"]),[]).append(i)
 for ix in g.values(): out[ix]=x[ix]-x[ix].mean(0,keepdims=True)
 return out

def basis(x,labels,classes):
 m=np.stack([x[np.array(labels,dtype=object)==c].mean(0) for c in classes]); m-=m.mean(0,keepdims=True)
 _,s,vt=np.linalg.svd(m,full_matrices=False); k=min(2,int(np.sum(s>1e-7))); return vt[:k].T

def orth(a,b):
 if b.size: a=a-b@(b.T@a)
 q,r=np.linalg.qr(a); keep=np.abs(np.diag(r))>1e-6; return q[:,keep]

def proj(d,b): return b@(b.T@d) if b.shape[1] else np.zeros_like(d)

def cs(logits,cids): return np.array([float(logits[cids[v]]) for v in VALUES])

def patch(model,tok,prompt,layer,vec,cids):
 enc=tok(prompt,return_tensors="pt").to("cuda"); block=model.model.layers[layer-1]
 def hook(mod,inp,out):
  h=out[0] if isinstance(out,tuple) else out; h=h.clone(); h[:,-1,:]=torch.as_tensor(vec,device=h.device,dtype=h.dtype)
  return (h,)+out[1:] if isinstance(out,tuple) else h
 hd=block.register_forward_hook(hook)
 try:
  with torch.inference_mode(): z=model(**enc,use_cache=False).logits[0,-1].float()
 finally: hd.remove()
 return cs(z,cids)

def boot(a,b,rng,n=2000):
 d=np.asarray(a)-np.asarray(b); N=len(d); m=[float(d[rng.integers(0,N,N)].mean()) for _ in range(n)]
 return {"mean":float(d.mean()),"lo":float(np.quantile(m,.025)),"hi":float(np.quantile(m,.975))}

def summ(rs,p):
 z=[r for r in rs if r["patch"]==p]
 o={"n":len(z),"mean_delta_margin":float(np.mean([r["dm"] for r in z])),
    "positive_fraction":float(np.mean([r["dm"]>0 for r in z])),
    "donor_pred_fraction":float(np.mean([r["pred"]==r["donor_target"] for r in z]))}
 for fam in ("companion_record","assigned_animal"):
  q=[r for r in z if r["family"]==fam]
  o[fam]={"mean_delta_margin":float(np.mean([r["dm"] for r in q])),
          "positive_fraction":float(np.mean([r["dm"]>0 for r in q])),
          "donor_pred_fraction":float(np.mean([r["pred"]==r["donor_target"] for r in q]))}
 return o

def main():
 np.random.seed(SEED); torch.manual_seed(SEED); rng=np.random.default_rng(SEED)
 tok=AutoTokenizer.from_pretrained(MODEL,revision=REVISION)
 model=AutoModelForCausalLM.from_pretrained(MODEL,revision=REVISION,torch_dtype=torch.float16).cuda().eval()
 cids={v:tok.encode(" "+v,add_special_tokens=False)[0] for v in VALUES}
 rr=rows(); states={l:[] for l in LAYERS}; clean=[]
 for i,r in enumerate(rr):
  enc=tok(r["prompt"],return_tensors="pt").to("cuda")
  with torch.inference_mode(): o=model(**enc,use_cache=False,output_hidden_states=True)
  for l in LAYERS: states[l].append(o.hidden_states[l][0,-1].float().cpu().numpy())
  clean.append(cs(o.logits[0,-1].float(),cids))
  if (i+1)%18==0: print("CAPTURED",i+1,"/",len(rr),flush=True)
 states={l:np.stack(v) for l,v in states.items()}; clean=np.stack(clean)
 elig=np.array([i for i,r in enumerate(rr) if r["split"]=="eligibility"]); conf=[i for i,r in enumerate(rr) if r["split"]=="confirmation"]
 yl=np.array([r["target"] for r in rr],dtype=object); ql=np.array([r["qi"] for r in rr],dtype=object)
 results={}
 for l in LAYERS:
  off=center(states[l],rr); V=basis(off[elig],yl[elig],VALUES); Q=basis(off[elig],ql[elig],[0,1,2]); Vp=orth(V,Q); Qp=orth(Q,V)
  rs=[]
  for ri in conf:
   r=rr[ri]; dq=(r["qi"]+1)%3
   di=next(j for j,x in enumerate(rr) if x["family"]==r["family"] and x["perm_i"]==r["perm_i"] and x["qi"]==dq); d=rr[di]
   diff=states[l][di]-states[l][ri]; vd=proj(diff,Vp); qd=proj(diff,Qp)
   rand=rng.normal(size=diff.shape).astype(np.float32); both=np.concatenate([Vp,Qp],axis=1)
   if both.shape[1]: rand-=both@(both.T@rand)
   rand=rand/(np.linalg.norm(rand)+1e-12)*(np.linalg.norm(vd)+1e-12)
   patches={"value":states[l][ri]+vd,"query":states[l][ri]+qd,"random":states[l][ri]+rand,"full":states[l][di]}
   a=VALUES.index(r["target"]); b=VALUES.index(d["target"]); base=float(clean[ri,b]-clean[ri,a])
   for typ,v in patches.items():
    sc=patch(model,tok,r["prompt"],l,v,cids); dm=float((sc[b]-sc[a])-base)
    rs.append({"family":r["family"],"perm_i":r["perm_i"],"recipient_q":r["qi"],"donor_q":dq,
               "recipient_target":r["target"],"donor_target":d["target"],"patch":typ,"dm":dm,
               "pred":VALUES[int(np.argmax(sc))]})
  s={p:summ(rs,p) for p in ("value","query","random","full")}
  va=[x["dm"] for x in rs if x["patch"]=="value"]; ra=[x["dm"] for x in rs if x["patch"]=="random"]; qa=[x["dm"] for x in rs if x["patch"]=="query"]
  s["value_minus_random_bootstrap"]=boot(va,ra,rng); s["value_minus_query_bootstrap"]=boot(va,qa,rng)
  s["gate"]=bool(s["full"]["positive_fraction"]>=.85 and s["value"]["positive_fraction"]>=.75 and
                 s["value"]["companion_record"]["positive_fraction"]>=.70 and s["value"]["assigned_animal"]["positive_fraction"]>=.70 and
                 s["value_minus_random_bootstrap"]["lo"]>0)
  results[str(l)]={"summary":s,"records":rs}; print("LAYER",l,json.dumps(s,separators=(",",":")),flush=True)
 out={"protocol":"Pass22 disjoint-vocabulary causal replication; eligibility-trained subspaces; confirmation-only interventions",
      "model":MODEL,"revision":REVISION,"values":VALUES,"layers":LAYERS,"seed":SEED,"results":results,
      "passing_layers":[l for l in LAYERS if results[str(l)]["summary"]["gate"]]}
 Path("/tmp/pass22.json").write_text(json.dumps(out,indent=2))
 print("PASS22_SUMMARY",json.dumps({"passing_layers":out["passing_layers"],"layers":{k:v["summary"] for k,v in results.items()}},separators=(",",":")),flush=True)

if __name__=="__main__": main()
