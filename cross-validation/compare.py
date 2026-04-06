#!/usr/bin/env python3
"""Compare Python and TypeScript results for divergences."""
import json

py = {r['id']: r for r in json.load(open('/home/user/workspace/smcp-review/cross-validation/python_results.json'))}
ts = {r['id']: r for r in json.load(open('/home/user/workspace/smcp-review/cross-validation/typescript_results.json'))}

print("=" * 70)
print("SMCP Cross-Validation: Python vs TypeScript Behavioral Parity")
print("=" * 70)

divergences = []
py_wrong = []
ts_wrong = []

for pid in sorted(py.keys()):
    pr = py[pid]
    tr = ts.get(pid, {})
    
    py_correct = pr['match']
    ts_correct = tr.get('match', False)
    both_agree = pr['actual'] == tr.get('actual', 'MISSING')
    
    if not both_agree:
        divergences.append({'id': pid, 'python': pr['actual'], 'typescript': tr.get('actual', 'MISSING'), 'expected': pr['expected'], 'description': pr['description']})
    if not py_correct:
        py_wrong.append(pid)
    if not ts_correct:
        ts_wrong.append(pid)

print(f"\n✓ Total payloads: {len(py)}")
print(f"✓ Python vs expected: {len(py)-len(py_wrong)}/{len(py)} correct")
print(f"✓ TypeScript vs expected: {len(ts)-len(ts_wrong)}/{len(ts)} correct")
print(f"✓ Behavioral divergences: {len(divergences)}")

if divergences:
    print("\n⚠️  DIVERGENCES (Python and TypeScript disagree):")
    for d in divergences:
        print(f"  [{d['id']}] {d['description'][:60]}")
        print(f"       Expected: {d['expected']} | Python: {d['python']} | TypeScript: {d['typescript']}")
else:
    print("\n✅ Full behavioral parity — Python and TypeScript agree on all payloads")

if py_wrong:
    print(f"\n⚠️  Python wrong on: {py_wrong}")
if ts_wrong:
    print(f"\n⚠️  TypeScript wrong on: {ts_wrong}")

# Save summary
summary = {
    'total': len(py),
    'divergences': len(divergences),
    'python_incorrect': py_wrong,
    'typescript_incorrect': ts_wrong,
    'divergence_details': divergences,
    'parity': len(divergences) == 0
}
json.dump(summary, open('/home/user/workspace/smcp-review/cross-validation/summary.json', 'w'), indent=2)
print("\nSummary saved to cross-validation/summary.json")
