import itertools, json
from pathlib import Path
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL="Qwen/Qwen2.5-3B"
REVISION="3aab1f1954e9cc14eb9509a215f9e5ca08227a9b"
VALUES=["cat","dog","bird"]
SEED=2121
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
    out.append({"family":fam,"split":split,"perm_i":pi,"query_index":qi,"target":vals[qi],"prompt":DEMO_PREFIX+item})
 return out

def centroid_predict(train_x,train_y,test_x,labels):
 mu=train_x.mean(0,keepdims=True); tx=train_x-mu; qx=test_x-mu
 cents=[]
 for lab in labels:
  c=tx[np.array(train_y,dtype=object)==lab].mean(0); cents.append(c/(np.linalg.norm(c)+1e-12))
 cents=np.stack(cents); qx=qx/np.maximum(np.linalg.norm(qx,axis=1,keepdims=True),1e-12)
 sc=qx@cents.T
 return np.array([labels[i] for i in sc.argmax(1)])

def acc(a,b): return float(np.mean(np.asarray(a)==np.asarray(b)))

def metrics(x,rr,key):
 elig=[i for i,r in enumerate(rr) if r["split"]=="eligibility"]
 conf=[i for i,r in enumerate(rr) if r["split"]=="confirmation"]
 labels=sorted({r[key] for r in rr}); y=[r[key] for r in rr]
 p=centroid_predict(x[elig],[y[i] for i in elig],x[conf],labels)
 out={"confirmation_pooled":acc(p,[y[i] for i in conf])}
 for fam in ("companion_record","assigned_animal"):
  jj=[j for j,i in enumerate(conf) if rr[i]["family"]==fam]
  out[fam]=acc(p[jj],[y[conf[j]] for j in jj])
 vals=[]
 for held in ("possessive_pet","mascot_qa","chosen_token"):
  tr=[i for i,r in enumerate(rr) if r["split"]=="eligibility" and r["family"]!=held]
  te=[i for i,r in enumerate(rr) if r["family"]==held]
  pp=centroid_predict(x[tr],[y[i] for i in tr],x[te],labels); vals.append(acc(pp,[y[i] for i in te]))
 out["eligibility_leave_family_out_mean"]=float(np.mean(vals))
 out["eligibility_leave_family_out"]=dict(zip(("possessive_pet","mascot_qa","chosen_token"),vals))
 return out

def center(x,rr):
 out=np.empty_like(x); groups={}
 for i,r in enumerate(rr): groups.setdefault((r["family"],r["perm_i"]),[]).append(i)
 for ix in groups.values(): out[ix]=x[ix]-x[ix].mean(0,keepdims=True)
 return out

def value_basis(model,tok):
 ids=[tok.encode(" "+v,add_special_tokens=False)[0] for v in VALUES]
 w=model.lm_head.weight.detach().float().cpu().numpy()[ids]; w-=w.mean(0,keepdims=True)
 q,_=np.linalg.qr(w.T); return q[:,:2]

def overlap(off,rr,V):
 zs=[]
 for fam in FAMILIES:
  for pi in range(6):
   ix=[i for i,r in enumerate(rr) if r["family"]==fam and r["perm_i"]==pi]
   q,_=np.linalg.qr(off[ix].T); q=q[:,:2]
   s=np.linalg.svd(q.T@V,compute_uv=False); zs.append(float(np.mean(s*s)))
 return float(np.mean(zs))

def shuffled_null(x,rr,rng,n=100):
 elig=[i for i,r in enumerate(rr) if r["split"]=="eligibility"]; conf=[i for i,r in enumerate(rr) if r["split"]=="confirmation"]
 y=np.array([r["target"] for r in rr],dtype=object); labels=sorted(set(y)); vals=[]
 for _ in range(n):
  yy=y.copy(); rng.shuffle(yy); p=centroid_predict(x[elig],yy[elig],x[conf],labels); vals.append(acc(p,yy[conf]))
 return {"mean":float(np.mean(vals)),"p95":float(np.quantile(vals,.95)),"max":float(np.max(vals))}

def main():
 np.random.seed(SEED); torch.manual_seed(SEED)
 tok=AutoTokenizer.from_pretrained(MODEL,revision=REVISION)
 model=AutoModelForCausalLM.from_pretrained(MODEL,revision=REVISION,torch_dtype=torch.float16).cuda().eval()
 rr=rows(); hs=[]
 for i,r in enumerate(rr):
  enc=tok(r["prompt"],return_tensors="pt").to("cuda")
  with torch.inference_mode(): o=model(**enc,use_cache=False,output_hidden_states=True)
  a=torch.stack([h[0,-1].float().cpu() for h in o.hidden_states]).numpy()
  if not hs: hs=[[] for _ in range(len(a))]
  for l in range(len(a)): hs[l].append(a[l])
  if (i+1)%18==0: print("CAPTURED",i+1,"/",len(rr),flush=True)
 hs=[np.stack(z) for z in hs]; V=value_basis(model,tok); rng=np.random.default_rng(SEED)
 curves=[]
 for l,raw in enumerate(hs):
  off=center(raw,rr); q=metrics(off,rr,"query_index"); v=metrics(off,rr,"target")
  curves.append({"layer":l,"query":q,"value":v,"value_plane_overlap":overlap(off,rr,V)})
 best=max(curves,key=lambda c:(c["value"]["confirmation_pooled"],c["value"]["eligibility_leave_family_out_mean"],c["value_plane_overlap"]))
 null=shuffled_null(center(hs[best["layer"]],rr),rr,rng)
 # Predeclared analogue criterion does not require query loss: sequence itself is tested.
 early_query=next((c["layer"] for c in curves if c["query"]["confirmation_pooled"]>=.8 and c["query"]["eligibility_leave_family_out_mean"]>=.8),None)
 value_layer=next((c["layer"] for c in curves if c["value"]["confirmation_pooled"]>=.75 and c["value"]["eligibility_leave_family_out_mean"]>=.75),None)
 peak=max(curves,key=lambda c:c["value_plane_overlap"])
 analogue=bool(early_query is not None and value_layer is not None and early_query<value_layer and peak["layer"]>=value_layer and null["p95"]<best["value"]["confirmation_pooled"])
 out={"protocol":"Pass21 disjoint-vocabulary operational analogue geometry; no causality claim",
      "model":MODEL,"revision":REVISION,"values":VALUES,"n_prompts":len(rr),"curves":curves,
      "early_query_layer":early_query,"value_emergence_layer":value_layer,
      "peak_output_alignment_layer":peak["layer"],"peak_output_alignment":peak["value_plane_overlap"],
      "best_value_layer":best["layer"],"best_value_metrics":best["value"],"best_null":null,
      "operational_analogue_gate":analogue}
 Path("/tmp/pass21.json").write_text(json.dumps(out,indent=2))
 print("PASS21_SUMMARY",json.dumps({k:out[k] for k in ("early_query_layer","value_emergence_layer","peak_output_alignment_layer","peak_output_alignment","best_value_layer","best_value_metrics","best_null","operational_analogue_gate")},separators=(",",":")),flush=True)
 print("PASS21_CURVES",json.dumps([{"l":c["layer"],"q":c["query"]["confirmation_pooled"],"v":c["value"]["confirmation_pooled"],"qloo":c["query"]["eligibility_leave_family_out_mean"],"vloo":c["value"]["eligibility_leave_family_out_mean"],"plane":c["value_plane_overlap"]} for c in curves],separators=(",",":")),flush=True)

if __name__=="__main__": main()
