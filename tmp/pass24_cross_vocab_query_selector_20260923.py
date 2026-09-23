import itertools,json
from pathlib import Path
import numpy as np, torch
from transformers import AutoTokenizer,AutoModelForCausalLM
MODEL="Qwen/Qwen2.5-3B"; REV="3aab1f1954e9cc14eb9509a215f9e5ca08227a9b"
COLOR=["red","blue","green"]; ANIMAL=["cat","dog","bird"]; SEED=2424
CP=("Facts: Ada's mug is yellow. Bo's mug is purple. Cy's mug is orange.\nQuestion: What color is Bo's mug?\nAnswer: purple\n\nFacts: Dan's ring is black. Eve's ring is white. Fox's ring is brown.\nQuestion: What color is Fox's ring?\nAnswer: brown\n\n")
AP=("Facts: Ada's mascot is a horse. Bo's mascot is a rabbit. Cy's mascot is a fish.\nQuestion: What animal is Bo's mascot?\nAnswer: rabbit\n\nFacts: Dan's companion is a wolf. Eve's companion is a fox. Fay's companion is a deer.\nQuestion: What animal is Fay's companion?\nAnswer: deer\n\n")
COLOR_F={
"ball":("eligibility",["Lily","Tom","Ben"],"Facts: {A}'s ball is {Va}. {B}'s ball is {Vb}. {C}'s ball is {Vc}.\nQuestion: What color is {Q}'s ball?\nAnswer:"),
"hat":("eligibility",["Lily","Tom","Ben"],"Facts: {A} has a {Va} hat. {B} has a {Vb} hat. {C} has a {Vc} hat.\nQuestion: What color is {Q}'s hat?\nAnswer:"),
"bag":("eligibility",["Lily","Tom","Ben"],"Facts: {A} carries a {Va} bag. {B} carries a {Vb} bag. {C} carries a {Vc} bag.\nQuestion: What color is the bag carried by {Q}?\nAnswer:"),
"coat":("confirmation",["Anna","Max","Sam"],"Records: {A} -> coat={Va}; {B} -> coat={Vb}; {C} -> coat={Vc}.\nQuery: coat color for {Q} ="),
"cup":("confirmation",["Anna","Max","Sam"],"Records: {A} -> chosen cup={Va}; {B} -> chosen cup={Vb}; {C} -> chosen cup={Vc}.\nQuery: chosen cup color for {Q} =")}
ANIMAL_F={
"pet":("eligibility",["Lily","Tom","Ben"],"Facts: {A}'s pet is a {Va}. {B}'s pet is a {Vb}. {C}'s pet is a {Vc}.\nQuestion: What animal is {Q}'s pet?\nAnswer:"),
"mascot":("eligibility",["Lily","Tom","Ben"],"Facts: {A} has a {Va} mascot. {B} has a {Vb} mascot. {C} has a {Vc} mascot.\nQuestion: What animal is {Q}'s mascot?\nAnswer:"),
"token":("eligibility",["Lily","Tom","Ben"],"Facts: {A} chose the {Va} token. {B} chose the {Vb} token. {C} chose the {Vc} token.\nQuestion: Which animal token did {Q} choose?\nAnswer:"),
"companion":("confirmation",["Anna","Max","Sam"],"Records: {A} -> companion={Va}; {B} -> companion={Vb}; {C} -> companion={Vc}.\nQuery: companion animal for {Q} ="),
"assigned":("confirmation",["Anna","Max","Sam"],"Records: {A} -> assigned animal={Va}; {B} -> assigned animal={Vb}; {C} -> assigned animal={Vc}.\nQuery: assigned animal for {Q} =")}

def build(domain,vals,prefix,fams):
 out=[]
 for fam,(split,names,tpl) in fams.items():
  for pi,v in enumerate(itertools.permutations(vals)):
   for qi,q in enumerate(names):
    item=tpl.format(A=names[0],B=names[1],C=names[2],Va=v[0],Vb=v[1],Vc=v[2],Q=q)
    out.append({"domain":domain,"family":fam,"split":split,"perm":pi,"qi":qi,"prompt":prefix+item})
 return out

def center(x,rr):
 o=np.empty_like(x);g={}
 for i,r in enumerate(rr):g.setdefault((r["family"],r["perm"]),[]).append(i)
 for ix in g.values():o[ix]=x[ix]-x[ix].mean(0,keepdims=True)
 return o

def basis(x,y):
 ms=np.stack([x[np.array(y)==k].mean(0) for k in (0,1,2)]);ms-=ms.mean(0,keepdims=True)
 q,_=np.linalg.qr(ms.T);return q[:,:2]

def centroids(x,y):
 mu=x.mean(0,keepdims=True);z=x-mu
 cs=np.stack([z[np.array(y)==k].mean(0) for k in (0,1,2)])
 cs/=np.maximum(np.linalg.norm(cs,axis=1,keepdims=True),1e-12)
 return mu,cs

def predict(x,mu,cs):
 z=x-mu;z/=np.maximum(np.linalg.norm(z,axis=1,keepdims=True),1e-12);return (z@cs.T).argmax(1)

def acc(p,y):return float(np.mean(np.asarray(p)==np.asarray(y)))

def main():
 np.random.seed(SEED);torch.manual_seed(SEED)
 tok=AutoTokenizer.from_pretrained(MODEL,revision=REV);model=AutoModelForCausalLM.from_pretrained(MODEL,revision=REV,torch_dtype=torch.float16).cuda().eval()
 data={"color":build("color",COLOR,CP,COLOR_F),"animal":build("animal",ANIMAL,AP,ANIMAL_F)};states={}
 for dom,rr in data.items():
  hs=[]
  for i,r in enumerate(rr):
   e=tok(r["prompt"],return_tensors="pt").to("cuda")
   with torch.inference_mode():o=model(**e,use_cache=False,output_hidden_states=True)
   a=torch.stack([h[0,-1].float().cpu() for h in o.hidden_states]).numpy()
   if not hs:hs=[[] for _ in range(len(a))]
   for l in range(len(a)):hs[l].append(a[l])
  states[dom]=[np.stack(z) for z in hs];print("CAPTURED",dom,len(rr),flush=True)
 curves=[]
 for l in range(len(states["color"])):
  C=center(states["color"][l],data["color"]);A=center(states["animal"][l],data["animal"])
  ci=[i for i,r in enumerate(data["color"]) if r["split"]=="eligibility"];cc=[i for i,r in enumerate(data["color"]) if r["split"]=="confirmation"]
  ai=[i for i,r in enumerate(data["animal"]) if r["split"]=="eligibility"];ac=[i for i,r in enumerate(data["animal"]) if r["split"]=="confirmation"]
  cy=np.array([r["qi"] for r in data["color"]]);ay=np.array([r["qi"] for r in data["animal"]])
  cmu,ccs=centroids(C[ci],cy[ci]);amu,acs=centroids(A[ai],ay[ai])
  within_c=acc(predict(C[cc],cmu,ccs),cy[cc]);within_a=acc(predict(A[ac],amu,acs),ay[ac])
  c2a=acc(predict(A[ac],cmu,ccs),ay[ac]);a2c=acc(predict(C[cc],amu,acs),cy[cc])
  Bc=basis(C[ci],cy[ci]);Ba=basis(A[ai],ay[ai]);s=np.linalg.svd(Bc.T@Ba,compute_uv=False)
  overlap=float(np.mean(s*s))
  curves.append({"layer":l,"within_color":within_c,"within_animal":within_a,"color_to_animal":c2a,"animal_to_color":a2c,"query_plane_overlap":overlap})
 gate_layers=[c["layer"] for c in curves if c["layer"]<=27 and c["within_color"]>=.9 and c["within_animal"]>=.9 and c["color_to_animal"]>=.75 and c["animal_to_color"]>=.75]
 best=max(curves,key=lambda c:min(c["color_to_animal"],c["animal_to_color"]))
 out={"protocol":"Pass24 cross-vocabulary relational selector transfer; query geometry trained in one domain tested on held-out syntax in other","model":MODEL,"revision":REV,"curves":curves,"gate_layers":gate_layers,"best_bidirectional":best,"shared_selector_gate":bool(gate_layers)}
 Path("/tmp/pass24.json").write_text(json.dumps(out,indent=2))
 print("PASS24_SUMMARY",json.dumps({"gate_layers":gate_layers,"best_bidirectional":best,"shared_selector_gate":out["shared_selector_gate"]},separators=(",",":")),flush=True)
 print("PASS24_CURVES",json.dumps(curves,separators=(",",":")),flush=True)

if __name__=="__main__":main()
