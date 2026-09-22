import argparse, hashlib, itertools, json, time, urllib.request
from pathlib import Path
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL = "Qwen/Qwen2.5-3B"
REVISION = "3aab1f1954e9cc14eb9509a215f9e5ca08227a9b"
COLORS = ["red", "blue", "green"]
NAMES_A = ["Lily", "Tom", "Ben"]
NAMES_B = ["Anna", "Max", "Sam"]
TEMPLATES = {
    "facts_question_ball": (NAMES_A, "Facts:\n{A}'s ball is {Va}.\n{B}'s ball is {Vb}.\n{C}'s ball is {Vc}.\nQuestion: What color is {Q}'s ball?\nAnswer:"),
    "worked_example_box": (NAMES_A, "Example: Nora's key is yellow. Omar's key is purple. Pia's key is orange.\nQuestion: What color is Omar's key? Answer: purple\n\nNew facts: {A}'s box is {Va}. {B}'s box is {Vb}. {C}'s box is {Vc}.\nQuestion: What color is {Q}'s box? Answer:"),
    "facts_question_coat": (NAMES_B, "Facts:\n{A} wears a {Va} coat.\n{B} wears a {Vb} coat.\n{C} wears a {Vc} coat.\nQuestion: What color coat does {Q} wear?\nAnswer:"),
}
CRITERIA = {
    "full_donor_closer_fraction_min": 0.80,
    "full_donor_candidate_accuracy_min": 0.80,
    "plane_donor_closer_fraction_min": 0.80,
    "plane_mean_donor_cosine_min": 0.80,
    "centroid_recipient_closer_fraction_min": 0.80,
    "centroid_mean_recipient_cosine_min": 0.80,
    "min_families_with_candidate_stage": 2,
}

def center(x):
    return x - x.mean(0, keepdim=True)

def cosflat(a, b):
    a = a.reshape(-1).float(); b = b.reshape(-1).float()
    return float((a @ b / (torch.linalg.norm(a) * torch.linalg.norm(b) + 1e-12)).item())

def donor_for(vals):
    cands = [v for v in itertools.permutations(COLORS) if v != vals]
    cands.sort(key=lambda v: (-sum(a != b for a, b in zip(v, vals)), v))
    return cands[0]

def stage_candidate(modes):
    full = modes["full"]; plane = modes["plane"]; centroid = modes["centroid"]
    return bool(
        full["donor_closer_fraction"] >= CRITERIA["full_donor_closer_fraction_min"] and
        full["donor_candidate_accuracy"] >= CRITERIA["full_donor_candidate_accuracy_min"] and
        plane["donor_closer_fraction"] >= CRITERIA["plane_donor_closer_fraction_min"] and
        plane["mean_donor_cosine"] >= CRITERIA["plane_mean_donor_cosine_min"] and
        centroid["recipient_closer_fraction"] >= CRITERIA["centroid_recipient_closer_fraction_min"] and
        centroid["mean_recipient_cosine"] >= CRITERIA["centroid_mean_recipient_cosine_min"]
    )

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default="/tmp/pass20b.json"); ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu"); args = ap.parse_args()
    device = args.device
    tok = AutoTokenizer.from_pretrained(MODEL, revision=REVISION)
    dtype = torch.float16 if device.startswith("cuda") else None
    model = AutoModelForCausalLM.from_pretrained(MODEL, revision=REVISION, torch_dtype=dtype).to(device).eval()
    torch.set_grad_enabled(False)
    layers = model.model.layers
    cids = {}
    for c in COLORS:
        ids = tok.encode(" " + c, add_special_tokens=False)
        if len(ids) != 1: raise RuntimeError((c, ids))
        cids[c] = ids[0]

    def prompt(names, tpl, vals, q):
        return tpl.format(A=names[0], B=names[1], C=names[2], Va=vals[0], Vb=vals[1], Vc=vals[2], Q=names[q])
    def forward(p, hidden=False):
        enc = tok(p, return_tensors="pt"); enc = {k: v.to(device) for k, v in enc.items()}
        return model(**enc, output_hidden_states=hidden, use_cache=False)
    def logits3(o):
        return torch.tensor([float(o.logits[0, -1, cids[c]].item()) for c in COLORS])
    def run_replaced(p, block_idx, repl):
        block = layers[block_idx]
        def hook(mod, inp, out):
            if isinstance(out, tuple):
                y = out[0].clone(); y[:, -1, :] = repl.to(device=y.device, dtype=y.dtype); return (y,) + out[1:]
            y = out.clone(); y[:, -1, :] = repl.to(device=y.device, dtype=y.dtype); return y
        h = block.register_forward_hook(hook)
        try: o = forward(p, hidden=False)
        finally: h.remove()
        return logits3(o)

    result = {"protocol": "Pass20b Qwen3B causal affine-component donor sweep; behaviorally qualified by frozen Pass20a", "model": MODEL, "revision": REVISION, "criteria": CRITERIA, "templates": {}, "overall_candidate_analogue": False}
    t0 = time.time()
    for tn, (names, tpl) in TEMPLATES.items():
        print(f"=== {tn} ===", flush=True)
        baseline = {}
        behavioral = []
        for vals in itertools.permutations(COLORS):
            hs_by_q, logs = [], []
            for q in range(3):
                o = forward(prompt(names, tpl, vals, q), hidden=True)
                hs_by_q.append([x[0, -1].detach().float().cpu() for x in o.hidden_states])
                l = logits3(o).cpu(); logs.append(l)
                behavioral.append(COLORS[int(l.argmax())] == vals[q])
            baseline[vals] = {"hs": hs_by_q, "logits": torch.stack(logs)}
        stages = []
        for stage in range(1, len(layers) + 1):
            metrics = {m: {"donor_cos": [], "recipient_cos": [], "donor_query": 0, "recipient_query": 0, "nq": 0} for m in ["plane", "centroid", "full"]}
            for vals in itertools.permutations(COLORS):
                donor = donor_for(vals); R = baseline[vals]; D = baseline[donor]
                qr = torch.stack([R["hs"][q][stage] for q in range(3)])
                qd = torch.stack([D["hs"][q][stage] for q in range(3)])
                mr = qr.mean(0, keepdim=True); md = qd.mean(0, keepdim=True); cr = qr - mr; cd = qd - md
                repls = {"plane": mr + cd, "centroid": md + cr, "full": qd}
                rec_base = center(R["logits"]); don_base = center(D["logits"])
                for mode, repl in repls.items():
                    logs = []
                    for q in range(3): logs.append(run_replaced(prompt(names, tpl, vals, q), stage - 1, repl[q:q+1]).cpu())
                    L = torch.stack(logs); CL = center(L)
                    metrics[mode]["donor_cos"].append(cosflat(CL, don_base)); metrics[mode]["recipient_cos"].append(cosflat(CL, rec_base))
                    pred = [COLORS[int(x.argmax())] for x in L]
                    metrics[mode]["donor_query"] += sum(a == b for a, b in zip(pred, donor)); metrics[mode]["recipient_query"] += sum(a == b for a, b in zip(pred, vals)); metrics[mode]["nq"] += 3
            summary = {}
            for mode, m in metrics.items():
                dc = np.array(m["donor_cos"]); rc = np.array(m["recipient_cos"])
                summary[mode] = {"donor_closer_fraction": float(np.mean(dc > rc)), "recipient_closer_fraction": float(np.mean(rc > dc)), "mean_donor_cosine": float(dc.mean()), "mean_recipient_cosine": float(rc.mean()), "donor_candidate_accuracy": m["donor_query"] / m["nq"], "recipient_candidate_accuracy": m["recipient_query"] / m["nq"]}
            stages.append({"stage": stage, "after_block_index": stage - 1, "candidate_analogue": stage_candidate(summary), "modes": summary})
        candidates = [s["stage"] for s in stages if s["candidate_analogue"]]
        result["templates"][tn] = {"behavioral_candidate_accuracy": float(np.mean(behavioral)), "candidate_stages": candidates, "stages": stages}
        print(json.dumps({"template": tn, "behavioral_candidate_accuracy": result["templates"][tn]["behavioral_candidate_accuracy"], "candidate_stages": candidates}, indent=2), flush=True)
    nfamilies = sum(bool(v["candidate_stages"]) for v in result["templates"].values())
    result["families_with_candidate_stage"] = nfamilies
    result["overall_candidate_analogue"] = nfamilies >= CRITERIA["min_families_with_candidate_stage"]
    result["seconds"] = time.time() - t0
    Path(args.out).write_text(json.dumps(result, indent=2))
    compact = {tn: {"behavioral": d["behavioral_candidate_accuracy"], "candidate_stages": d["candidate_stages"]} for tn, d in result["templates"].items()}
    print("PASS18_SUMMARY", json.dumps({"overall_candidate_analogue": result["overall_candidate_analogue"], "families_with_candidate_stage": nfamilies, "templates": compact, "criteria": CRITERIA}, separators=(",", ":")), flush=True)

if __name__ == "__main__":
    main()
