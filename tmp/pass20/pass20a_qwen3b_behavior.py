import argparse, hashlib, json, time, urllib.request
from pathlib import Path
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

PASS16_URL = "https://raw.githubusercontent.com/wizardscurtain/SMCPv1/91e08a51446b082ee0c222e4a6645fe0e5de3dd4/tmp/pass16/pass16_paraphrase_invariance.py"
PASS16_SHA256 = "4d6c7087ee253f8f3ae9a3b64259663425bd4666d110182cafd8657b6e4a69a0"
MODELS = ["Qwen/Qwen2.5-3B"]

raw = urllib.request.urlopen(PASS16_URL, timeout=30).read()
assert hashlib.sha256(raw).hexdigest() == PASS16_SHA256
ns = {"__name__": "pass16_frozen"}
exec(compile(raw, PASS16_URL, "exec"), ns)

ELIGIBILITY = ns["ELIGIBILITY"]
CONFIRMATION = ns["CONFIRMATION"]
eval_family = ns["eval_family"]
evaluate_gate = ns["evaluate_gate"]

def compact(fams):
    return {k: {"accuracy": v["accuracy"], "complete_permutation_fraction": v["complete_permutation_fraction"], "family_pass": v["family_pass"]} for k, v in fams.items()}

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default="/tmp/pass20a.json"); ap.add_argument("--device", default="cuda" if torch.cuda.is_available() else "cpu"); args = ap.parse_args()
    out = Path(args.out)
    result = {"protocol": "Pass20a frozen Pass16 paraphrase-invariance Qwen2.5-3B qualification; no hidden-state inspection", "pass16_sha256": PASS16_SHA256, "models": {}, "selected_model": None}
    for mid in MODELS:
        print(f"=== {mid} ===", flush=True)
        tok = AutoTokenizer.from_pretrained(mid)
        model = AutoModelForCausalLM.from_pretrained(mid, torch_dtype=torch.float16 if args.device.startswith("cuda") else None).to(args.device).eval()
        t0 = time.time()
        elig = {k: eval_family(model, tok, v, args.device) for k, v in ELIGIBILITY.items()}
        conf = {k: eval_family(model, tok, v, args.device) for k, v in CONFIRMATION.items()}
        gate = evaluate_gate(elig, conf)
        cfg = {"hidden_size": getattr(model.config, "hidden_size", None), "num_hidden_layers": getattr(model.config, "num_hidden_layers", None), "num_attention_heads": getattr(model.config, "num_attention_heads", None), "revision": getattr(model.config, "_commit_hash", None)}
        result["models"][mid] = {"config": cfg, "eligibility": elig, "confirmation": conf, "gate": gate, "seconds": time.time() - t0}
        print(json.dumps({"model": mid, "gate": gate, "families": {"eligibility": compact(elig), "confirmation": compact(conf)}, "config": cfg}, indent=2), flush=True)
        out.write_text(json.dumps(result, indent=2))
        del model
        if torch.cuda.is_available(): torch.cuda.empty_cache()
        if gate["pass"]:
            result["selected_model"] = mid
            break
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps({"selected_model": result["selected_model"]}, indent=2), flush=True)

if __name__ == "__main__":
    main()
