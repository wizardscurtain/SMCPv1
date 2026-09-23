import argparse, itertools, json, time
from pathlib import Path
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODELS = [
    "Qwen/Qwen2.5-0.5B",
    "Qwen/Qwen2.5-1.5B",
    "Qwen/Qwen2.5-3B",
]
COLORS = ["red", "blue", "green"]

QA_PREFIX = (
    "Facts: Ada's mug is yellow. Bo's mug is purple. Cy's mug is orange.\n"
    "Question: What color is Bo's mug?\nAnswer: purple\n\n"
    "Facts: Dan's ring is black. Eve's ring is white. Fox's ring is brown.\n"
    "Question: What color is Fox's ring?\nAnswer: brown\n\n"
)

ELIGIBILITY = {
    "possessive_ball_qa": {
        "names": ["Lily", "Tom", "Ben"],
        "template": "Facts: {A}'s ball is {Va}. {B}'s ball is {Vb}. {C}'s ball is {Vc}.\nQuestion: What color is {Q}'s ball?\nAnswer:",
    },
    "hat_qa": {
        "names": ["Lily", "Tom", "Ben"],
        "template": "Facts: {A} has a {Va} hat. {B} has a {Vb} hat. {C} has a {Vc} hat.\nQuestion: What color is {Q}'s hat?\nAnswer:",
    },
    "bag_qa": {
        "names": ["Lily", "Tom", "Ben"],
        "template": "Facts: {A} carries a {Va} bag. {B} carries a {Vb} bag. {C} carries a {Vc} bag.\nQuestion: What color is the bag carried by {Q}?\nAnswer:",
    },
}

CONFIRMATION = {
    "coat_record": {
        "names": ["Anna", "Max", "Sam"],
        "template": "Records: {A} -> coat={Va}; {B} -> coat={Vb}; {C} -> coat={Vc}.\nQuery: coat color for {Q} =",
    },
    "cup_record": {
        "names": ["Anna", "Max", "Sam"],
        "template": "Records: {A} -> chosen cup={Va}; {B} -> chosen cup={Vb}; {C} -> chosen cup={Vc}.\nQuery: chosen cup color for {Q} =",
    },
}

GATE = {
    "eligibility_pooled_min": 0.75,
    "eligibility_families_min_accuracy": 2/3,
    "eligibility_min_families": 2,
    "confirmation_pooled_min": 0.70,
    "confirmation_family_min_accuracy": 2/3,
    "confirmation_min_families": 2,
}

def eval_family(model, tok, spec, device):
    names = spec["names"]
    cand_ids = {}
    for c in COLORS:
        ids = tok.encode(" " + c, add_special_tokens=False)
        if len(ids) != 1:
            raise RuntimeError(f"Color {c!r} is not one token: {ids}")
        cand_ids[c] = ids[0]
    rows = []
    for vals in itertools.permutations(COLORS):
        for qi, qn in enumerate(names):
            item = spec["template"].format(A=names[0], B=names[1], C=names[2], Va=vals[0], Vb=vals[1], Vc=vals[2], Q=qn)
            prompt = QA_PREFIX + item
            enc = tok(prompt, return_tensors="pt").to(device)
            with torch.inference_mode():
                logits = model(**enc, use_cache=False).logits[0, -1].float()
            scores = {c: float(logits[i].item()) for c, i in cand_ids.items()}
            pred = max(COLORS, key=lambda c: scores[c])
            target = vals[qi]
            order = sorted(COLORS, key=lambda c: scores[c], reverse=True)
            topid = int(torch.argmax(logits).item())
            rows.append({
                "values": list(vals), "query": qn, "target": target,
                "candidate_pred": pred, "candidate_correct": pred == target,
                "target_candidate_rank": order.index(target) + 1,
                "full_top1_token": tok.decode([topid]),
                "full_top1_is_target_color": topid == cand_ids[target],
                "candidate_scores": scores, "prompt": prompt,
            })
    return {
        "n": len(rows),
        "candidate_accuracy": float(np.mean([r["candidate_correct"] for r in rows])),
        "full_top1_target_color_accuracy": float(np.mean([r["full_top1_is_target_color"] for r in rows])),
        "mean_target_candidate_rank": float(np.mean([r["target_candidate_rank"] for r in rows])),
        "candidate_prediction_counts": {c: sum(r["candidate_pred"] == c for r in rows) for c in COLORS},
        "rows": rows,
    }

def pooled(d):
    rows = [r for fam in d.values() for r in fam["rows"]]
    return float(np.mean([r["candidate_correct"] for r in rows]))

def gate(elig, conf):
    ep, cp = pooled(elig), pooled(conf)
    ef = sum(v["candidate_accuracy"] >= GATE["eligibility_families_min_accuracy"] for v in elig.values())
    cf = sum(v["candidate_accuracy"] >= GATE["confirmation_family_min_accuracy"] for v in conf.values())
    ok = (ep >= GATE["eligibility_pooled_min"] and ef >= GATE["eligibility_min_families"] and
          cp >= GATE["confirmation_pooled_min"] and cf >= GATE["confirmation_min_families"])
    return {"pass": bool(ok), "eligibility_pooled": ep, "eligibility_families_passing": ef,
            "confirmation_pooled": cp, "confirmation_families_passing": cf, "rule": GATE}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results/pass16_qwen_base.json")
    ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu")
    args = ap.parse_args()
    outp = Path(args.out); outp.parent.mkdir(parents=True, exist_ok=True)
    result = {"protocol": "behavior-only redesigned QA observable; no hidden-state inspection", "models": {}, "selected_model": None}
    for mid in MODELS:
        t0 = time.time(); print(f"=== {mid} ===", flush=True)
        tok = AutoTokenizer.from_pretrained(mid)
        model = AutoModelForCausalLM.from_pretrained(mid).to(args.device).eval()
        elig = {k: eval_family(model, tok, v, args.device) for k, v in ELIGIBILITY.items()}
        conf = {k: eval_family(model, tok, v, args.device) for k, v in CONFIRMATION.items()}
        g = gate(elig, conf)
        cfg = {"hidden_size": getattr(model.config, "hidden_size", None), "num_hidden_layers": getattr(model.config, "num_hidden_layers", None), "num_attention_heads": getattr(model.config, "num_attention_heads", None), "revision": getattr(model.config, "_commit_hash", None)}
        result["models"][mid] = {"config": cfg, "eligibility": elig, "confirmation": conf, "gate": g, "seconds": time.time()-t0}
        print(json.dumps({"model": mid, "gate": g, "config": cfg}, indent=2), flush=True)
        outp.write_text(json.dumps(result, indent=2))
        del model
        if torch.cuda.is_available(): torch.cuda.empty_cache()
        if g["pass"]:
            result["selected_model"] = mid
            break
    outp.write_text(json.dumps(result, indent=2))
    Path(outp.parent / "SELECTED_MODEL.txt").write_text((result["selected_model"] or "NONE") + "\n")
    print(json.dumps({"selected_model": result["selected_model"], "output": str(outp)}, indent=2))

if __name__ == "__main__":
    main()
