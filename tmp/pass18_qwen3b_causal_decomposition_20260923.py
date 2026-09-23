import itertools, json, math
from pathlib import Path
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL="Qwen/Qwen2.5-3B"
REVISION="3aab1f1954e9cc14eb9509a215f9e5ca08227a9b"
COLORS=["red","blue","green"]
LAYERS=[23,28,29,31,33,34]
SEED=1818
QA_PREFIX=(
"Facts: Ada's mug is yellow. Bo's mug is purple. Cy's mug is orange.\n"
"Question: What color is Bo's mug?\nAnswer: purple\n\n"
"Facts: Dan's ring is black. Eve's ring is white. Fox's ring is brown.\n"
"Question: What color is Fox's ring?\nAnswer: brown\n\n")
FAMILIES={
"possessive_ball_qa":("eligibility",["Lily","Tom","Ben"],"Facts: {A}'s ball is {Va}. {B}'s ball is {Vb}. {C}'s ball is {Vc}.\nQuestion: What color is {Q}'s ball?\nAnswer:"),
"hat_qa":("eligibility",["Lily","Tom","Ben"],"Facts: {A} has a {Va} hat. {B} has a {Vb} hat. {C} has a {Vc} hat.\nQuestion: What color is {Q}'s hat?\nAnswer:"),
"bag_qa":("eligibility",["Lily","Tom","Ben"],"Facts: {A} carries a {Va} bag. {B} carries a {Vb} bag. {C} carries a {Vc} bag.\nQuestion: What color is the bag carried by {Q}?\nAnswer:"),
"coat_record":("confirmation",["Anna","Max","Sam"],"Records: {A} -> coat={Va}; {B} -> coat={Vb}; {C} -> coat={Vc}.\nQuery: coat color for {Q} ="),
"cup_record":("confirmation",["Anna","Max","Sam"],"Records: {A} -> chosen cup={Va}; {B} -> chosen cup={Vb}; {C} -> chosen cup={Vc}.\nQuery: chosen cup color for {Q} =")}

def rows():
 out=[]
 for fam,(split,names,tpl) in FAMILIES.items():
  for pi,vals in enumerate(itertools.permutations(COLORS)):
   for qi,qn in enumerate(names):
    item=tpl.format(A=names[0],B=names[1],C=names[2],Va=vals[0],Vb=vals[1],Vc=vals[2],Q=qn)
    out.append({"family":fam,"split":split,"perm_i":pi,"qi":qi,"target":vals[qi],"prompt":QA_PREFIX+item})
 return out

def context_offsets(x,rr):
 out=np.empty_like(x); groups={}
 for i,r in enumerate(rr): groups.setdefault((r["family"],r["perm_i"]),[]).append(i)
 for ix in groups.values(): out[ix]=x[ix]-x[ix].mean(0,keepdims=True)
 return out

def basis_from_means(x, labels, classes):
 ms=np.stack([x[np.array(labels,dtype=object)==c].mean(0) for c in classes])
 ms=ms-ms.mean(0,keepdims=True)
 _,s,vt=np.linalg.svd(ms,full_matrices=False)
 k=min(2,int(np.sum(s>1e-7)))
 return vt[:k].T

def orthogonalize(a, against):
 if against.size: a=a-against@(against.T@a)
 q,r=np.linalg.qr(a)
 keep=np.abs(np.diag(r))>1e-6
 return q[:,keep]

def project_delta(diff,basis):
 return basis@(basis.T@diff) if basis.shape[1] else np.zeros_like(diff)

def candidate_scores(logits,cids):
 return np.array([float(logits[cids[c]]) for c in COLORS])

def run_patch(model,tok,prompt,layer,patched_vec,cids):
 enc=tok(prompt,return_tensors="pt").to("cuda")
 block=model.model.layers[layer-1]
 def hook(mod,inp,out):
  h=out[0] if isinstance(out,tuple) else out
  h2=h.clone(); h2[:,-1,:]=torch.as_tensor(patched_vec,device=h.device,dtype=h.dtype)
  if isinstance(out,tuple): return (h2,)+out[1:]
  return h2
 handle=block.register_forward_hook(hook)
 try:
  with torch.inference_mode(): logits=model(**enc,use_cache=False).logits[0,-1].float()
 finally: handle.remove()
 return candidate_scores(logits,cids)

def bootstrap_diff(a,b,rng,n=2000):
 d=np.asarray(a)-np.asarray(b); N=len(d); means=[]
 for _ in range(n): means.append(float(d[rng.integers(0,N,N)].mean()))
 return {"mean":float(d.mean()),"lo":float(np.quantile(means,.025)),"hi":float(np.quantile(means,.975))}

def summarize(records,ptype):
 z=[r for r in records if r["patch"]==ptype]
 out={"n":len(z),"mean_delta_margin":float(np.mean([r["delta_margin"] for r in z])),
      "positive_fraction":float(np.mean([r["delta_margin"]>0 for r in z])),
      "donor_pred_fraction":float(np.mean([r["pred"]==r["donor_target"] for r in z]))}
 for fam in ("coat_record","cup_record"):
  q=[r for r in z if r["family"]==fam]
  out[fam]={"mean_delta_margin":float(np.mean([r["delta_margin"] for r in q])),
            "positive_fraction":float(np.mean([r["delta_margin"]>0 for r in q])),
            "donor_pred_fraction":float(np.mean([r["pred"]==r["donor_target"] for r in q]))}
 return out

def main():
 np.random.seed(SEED); torch.manual_seed(SEED)
 tok=AutoTokenizer.from_pretrained(MODEL,revision=REVISION)
 model=AutoModelForCausalLM.from_pretrained(MODEL,revision=REVISION,torch_dtype=torch.float16).cuda().eval()
 cids={}
 for c in COLORS:
  ids=tok.encode(" "+c,add_special_tokens=False)
  if len(ids)!=1: raise RuntimeError((c,ids))
  cids[c]=ids[0]
 rr=rows(); states={l:[] for l in LAYERS}; clean=[]
 for i,r in enumerate(rr):
  enc=tok(r["prompt"],return_tensors="pt").to("cuda")
  with torch.inference_mode(): o=model(**enc,use_cache=False,output_hidden_states=True)
  for l in LAYERS: states[l].append(o.hidden_states[l][0,-1].float().cpu().numpy())
  sc=candidate_scores(o.logits[0,-1].float(),cids); clean.append(sc)
  if (i+1)%18==0: print("CAPTURED",i+1,"/",len(rr),flush=True)
 states={l:np.stack(v) for l,v in states.items()}; clean=np.stack(clean)
 elig=np.array([i for i,r in enumerate(rr) if r["split"]=="eligibility"])
 conf=[i for i,r in enumerate(rr) if r["split"]=="confirmation"]
 target_labels=np.array([r["target"] for r in rr],dtype=object)
 query_labels=np.array([r["qi"] for r in rr],dtype=object)
 rng=np.random.default_rng(SEED)
 results={}
 for l in LAYERS:
  off=context_offsets(states[l],rr)
  V=basis_from_means(off[elig],target_labels[elig],COLORS)
  Q=basis_from_means(off[elig],query_labels[elig],[0,1,2])
  Vp=orthogonalize(V,Q); Qp=orthogonalize(Q,V)
  recs=[]
  for ri in conf:
   r=rr[ri]
   donor_q=(r["qi"]+1)%3
   di=next(j for j,x in enumerate(rr) if x["family"]==r["family"] and x["perm_i"]==r["perm_i"] and x["qi"]==donor_q)
   d=rr[di]; diff=states[l][di]-states[l][ri]
   value_delta=project_delta(diff,Vp); query_delta=project_delta(diff,Qp)
   n=float(np.linalg.norm(value_delta))
   rand=rng.normal(size=diff.shape).astype(np.float32)
   both=np.concatenate([Vp,Qp],axis=1)
   if both.shape[1]: rand=rand-both@(both.T@rand)
   rand=rand/(np.linalg.norm(rand)+1e-12)*n
   patches={"value":states[l][ri]+value_delta,
            "query":states[l][ri]+query_delta,
            "random":states[l][ri]+rand,
            "full":states[l][di]}
   rec_idx=COLORS.index(r["target"]); don_idx=COLORS.index(d["target"])
   base=float(clean[ri,don_idx]-clean[ri,rec_idx])
   for ptype,pvec in patches.items():
    sc=run_patch(model,tok,r["prompt"],l,pvec,cids)
    dm=float((sc[don_idx]-sc[rec_idx])-base)
    recs.append({"family":r["family"],"perm_i":r["perm_i"],"recipient_q":r["qi"],"donor_q":donor_q,
                 "recipient_target":r["target"],"donor_target":d["target"],"patch":ptype,
                 "delta_margin":dm,"pred":COLORS[int(np.argmax(sc))],"patch_norm":float(np.linalg.norm(pvec-states[l][ri]))})
  s={p:summarize(recs,p) for p in ("value","query","random","full")}
  vals=[x["delta_margin"] for x in recs if x["patch"]=="value"]
  rands=[x["delta_margin"] for x in recs if x["patch"]=="random"]
  queries=[x["delta_margin"] for x in recs if x["patch"]=="query"]
  s["value_minus_random_bootstrap"]=bootstrap_diff(vals,rands,rng)
  s["value_minus_query_bootstrap"]=bootstrap_diff(vals,queries,rng)
  strong=(s["full"]["positive_fraction"]>=.85 and s["value"]["positive_fraction"]>=.75
          and s["value"]["coat_record"]["positive_fraction"]>=.70
          and s["value"]["cup_record"]["positive_fraction"]>=.70
          and s["value_minus_random_bootstrap"]["lo"]>0)
  s["value_component_causal_gate"]=bool(strong)
  s["value_basis_rank"]=int(Vp.shape[1]); s["query_basis_rank"]=int(Qp.shape[1])
  results[str(l)]={"summary":s,"records":recs}
  print("LAYER",l,json.dumps(s,separators=(",",":")),flush=True)
 out={"protocol":"Pass18 held-out causal decomposition; eligibility-trained value/query subspaces; confirmation-only interventions",
      "model":MODEL,"revision":REVISION,"layers":LAYERS,"seed":SEED,
      "predeclared_gate":"full donor positive>=.85; value positive>=.75 overall and >=.70 each confirmation family; paired bootstrap value-random lower95>0",
      "results":results,
      "passing_layers":[l for l in LAYERS if results[str(l)]["summary"]["value_component_causal_gate"]]}
 Path("/tmp/pass18.json").write_text(json.dumps(out,indent=2))
 print("PASS18_SUMMARY",json.dumps({"passing_layers":out["passing_layers"],"layers":{k:v["summary"] for k,v in results.items()}},separators=(",",":")),flush=True)

if __name__=="__main__": main()
