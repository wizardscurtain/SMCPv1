import argparse, itertools, json, time
from pathlib import Path
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL = "EleutherAI/pythia-1b"
COLORS = ["red", "blue", "green"]

ELIGIBILITY = {
    "facts_question_ball": {
        "names": ["Lily", "Tom", "Ben"],
        "template": "Facts:\n{A}'s ball is {Va}.\n{B}'s ball is {Vb}.\n{C}'s ball is {Vc}.\nQuestion: What color is {Q}'s ball?\nAnswer:",
    },
    "plain_sentences_hat": {
        "names": ["Lily", "Tom", "Ben"],
        "template": "{A} has a {Va} hat. {B} has a {Vb} hat. {C} has a {Vc} hat. Which color hat belongs to {Q}? Answer:",
    },
    "worked_example_box": {
        "names": ["Lily", "Tom", "Ben"],
        "template": (
            "Example: Nora's key is yellow. Omar's key is purple. Pia's key is orange.\n"
            "Question: What color is Omar's key? Answer: purple\n\n"
            "New facts: {A}'s box is {Va}. {B}'s box is {Vb}. {C}'s box is {Vc}.\n"
            "Question: What color is {Q}'s box? Answer:"
        ),
    },
}

CONFIRMATION = {
    "facts_question_coat": {
        "names": ["Anna", "Max", "Sam"],
        "template": "Facts:\n{A} wears a {Va} coat.\n{B} wears a {Vb} coat.\n{C} wears a {Vc} coat.\nQuestion: What color coat does {Q} wear?\nAnswer:",
    },
    "plain_sentences_mug": {
        "names": ["Anna", "Max", "Sam"],
        "template": "{A} owns a {Va} mug. {B} owns a {Vb} mug. {C} owns a {Vc} mug. What is the color of {Q}'s mug? Answer:",
    },
    "worked_example_ring": {
        "names": ["Anna", "Max", "Sam"],
        "template": (
            "Example: Ivy chose a yellow scarf. Leo chose a purple scarf. Mia chose an orange scarf.\n"
            "Question: What color scarf did Leo choose? Answer: purple\n\n"
            "New facts: {A} chose a {Va} ring. {B} chose a {Vb} ring. {C} chose a {Vc} ring.\n"
            "Question: What color ring did {Q} choose? Answer:"
        ),
    },
}

GATE = {
    "pooled_min": 0.80,
    "family_accuracy_min": 0.80,
    "family_complete_permutation_fraction_min": 0.50,
    "min_families_each_split": 2,
}

def eval_family(model, tok, spec, device):
    names = spec["names"]
    ids = {}
    for color in COLORS:
        encoded = tok.encode(" " + color, add_special_tokens=False)
        if len(encoded) != 1:
            raise RuntimeError(f"candidate {color!r} is not one token: {encoded}")
        ids[color] = encoded[0]
    rows = []
    for values in itertools.permutations(COLORS):
        for qi, query in enumerate(names):
            prompt = spec["template"].format(A=names[0], B=names[1], C=names[2], Va=values[0], Vb=values[1], Vc=values[2], Q=query)
            enc = tok(prompt, return_tensors="pt").to(device)
            with torch.inference_mode():
                logits = model(**enc, use_cache=False).logits[0, -1].float()
            scores = {c: float(logits[i].item()) for c, i in ids.items()}
            pred = max(COLORS, key=lambda c: scores[c])
            target = values[qi]
            rows.append({"values": list(values), "query": query, "target": target, "pred": pred, "correct": pred == target, "scores": scores, "prompt": prompt})
    complete = []
    for values in itertools.permutations(COLORS):
        group = [r for r in rows if tuple(r["values"]) == values]
        complete.append(all(r["correct"] for r in group))
    accuracy = float(np.mean([r["correct"] for r in rows]))
    complete_fraction = float(np.mean(complete))
    family_pass = accuracy >= GATE["family_accuracy_min"] and complete_fraction >= GATE["family_complete_permutation_fraction_min"]
    return {"n": len(rows), "accuracy": accuracy, "complete_permutation_fraction": complete_fraction, "family_pass": bool(family_pass), "prediction_counts": {c: sum(r["pred"] == c for r in rows) for c in COLORS}, "rows": rows}

def pooled(families):
    rows = [r for f in families.values() for r in f["rows"]]
    return float(np.mean([r["correct"] for r in rows]))

def evaluate_gate(elig, conf):
    ep, cp = pooled(elig), pooled(conf)
    ef = sum(v["family_pass"] for v in elig.values())
    cf = sum(v["family_pass"] for v in conf.values())
    ok = ep >= GATE["pooled_min"] and cp >= GATE["pooled_min"] and ef >= GATE["min_families_each_split"] and cf >= GATE["min_families_each_split"]
    return {"pass": bool(ok), "eligibility_pooled": ep, "eligibility_families_passing": ef, "confirmation_pooled": cp, "confirmation_families_passing": cf, "rule": GATE}

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default="/tmp/pass16.json"); ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu"); args = ap.parse_args()
    tok = AutoTokenizer.from_pretrained(MODEL)
    model = AutoModelForCausalLM.from_pretrained(MODEL).to(args.device).eval()
    t0 = time.time()
    elig = {k: eval_family(model, tok, v, args.device) for k, v in ELIGIBILITY.items()}
    conf = {k: eval_family(model, tok, v, args.device) for k, v in CONFIRMATION.items()}
    gate = evaluate_gate(elig, conf)
    result = {"protocol": "Pass16 behavior-only paraphrase invariance; no hidden-state inspection", "model": MODEL, "config": {"hidden_size": getattr(model.config, "hidden_size", None), "num_hidden_layers": getattr(model.config, "num_hidden_layers", None), "num_attention_heads": getattr(model.config, "num_attention_heads", None), "revision": getattr(model.config, "_commit_hash", None)}, "eligibility": elig, "confirmation": conf, "gate": gate, "seconds": time.time() - t0}
    Path(args.out).write_text(json.dumps(result, indent=2))
    print(json.dumps({"model": MODEL, "gate": gate, "families": {"eligibility": {k: {"accuracy": v["accuracy"], "complete_permutation_fraction": v["complete_permutation_fraction"], "family_pass": v["family_pass"]} for k, v in elig.items()}, "confirmation": {k: {"accuracy": v["accuracy"], "complete_permutation_fraction": v["complete_permutation_fraction"], "family_pass": v["family_pass"]} for k, v in conf.items()}}, "config": result["config"]}, indent=2), flush=True)

if __name__ == "__main__":
    main()
