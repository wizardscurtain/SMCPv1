#!/usr/bin/env python3
"""Run adversarial payloads through Python SMCP implementation."""
import sys, json, asyncio
sys.path.insert(0, '/home/user/workspace/smcp-review/libraries/python')

from smcp_security.input_validation import InputValidator, CommandInjectionPrevention, PromptInjectionDetector
from smcp_security.exceptions import SecurityError, ValidationError

PAYLOADS_FILE = '/home/user/workspace/smcp-review/cross-validation/payloads.json'
RESULTS_FILE = '/home/user/workspace/smcp-review/cross-validation/python_results.json'

def run_payload(payload_entry):
    """Run a single payload through Python validation layers."""
    payload = payload_entry['payload']
    category = payload_entry['category']
    
    # Determine context from method
    method = payload.get('method', '')
    context = None
    if 'tools/call' in method:
        context = 'shell'
    elif 'resources' in method:
        context = 'file_system'  
    elif 'database' in method:
        context = 'database'
    
    try:
        # Layer 1: Schema validation + prompt injection + command injection
        validator = InputValidator(strictness='standard')
        validator.validate_request(payload)
        return {'result': 'allow', 'exception': None, 'layer': None}
    except (SecurityError, ValidationError) as e:
        return {'result': 'block', 'exception': type(e).__name__, 'layer': 'input_validation', 'message': str(e)}
    except Exception as e:
        return {'result': 'error', 'exception': type(e).__name__, 'layer': 'unknown', 'message': str(e)}

def main():
    with open(PAYLOADS_FILE) as f:
        payloads = json.load(f)
    
    results = []
    for entry in payloads:
        outcome = run_payload(entry)
        results.append({
            'id': entry['id'],
            'category': entry['category'],
            'description': entry['description'],
            'expected': entry['expected_result'],
            'actual': outcome['result'],
            'match': outcome['result'] == entry['expected_result'],
            'exception': outcome.get('exception'),
            'message': outcome.get('message', '')
        })
        status = '✓' if outcome['result'] == entry['expected_result'] else '✗ DIVERGENCE'
        print(f"[{status}] {entry['id']}: {entry['description'][:60]} → {outcome['result']}")
    
    with open(RESULTS_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    
    matched = sum(1 for r in results if r['match'])
    print(f"\nPython: {matched}/{len(results)} match expected")
    return results

if __name__ == '__main__':
    main()
