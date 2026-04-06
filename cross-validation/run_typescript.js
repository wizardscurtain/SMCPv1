#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

// Must run after: cd libraries/nodejs && npm run build
const distPath = '/home/user/workspace/smcp-review/libraries/nodejs/dist';
const { InputValidator } = require(path.join(distPath, 'validation/InputValidator'));
const { ValidationError } = require(path.join(distPath, 'exceptions/index'));
// SecurityError is the base
let SecurityError;
try {
  SecurityError = require(path.join(distPath, 'exceptions/index')).SecurityError;
} catch(e) { SecurityError = Error; }

const PAYLOADS_FILE = '/home/user/workspace/smcp-review/cross-validation/payloads.json';
const RESULTS_FILE = '/home/user/workspace/smcp-review/cross-validation/typescript_results.json';

async function runPayload(entry) {
  const payload = entry.payload;
  const method = payload.method || '';
  
  try {
    const validator = new InputValidator({ strictness: 'standard' });
    validator.validateRequest(payload);
    return { result: 'allow', exception: null, message: '' };
  } catch (e) {
    return { 
      result: 'block', 
      exception: e.constructor.name, 
      message: e.message 
    };
  }
}

async function main() {
  const payloads = JSON.parse(fs.readFileSync(PAYLOADS_FILE, 'utf8'));
  const results = [];
  
  for (const entry of payloads) {
    const outcome = await runPayload(entry);
    const match = outcome.result === entry.expected_result;
    results.push({
      id: entry.id,
      category: entry.category,
      description: entry.description,
      expected: entry.expected_result,
      actual: outcome.result,
      match,
      exception: outcome.exception,
      message: outcome.message
    });
    const status = match ? '✓' : '✗ DIVERGENCE';
    console.log(`[${status}] ${entry.id}: ${entry.description.slice(0,60)} → ${outcome.result}`);
  }
  
  fs.writeFileSync(RESULTS_FILE, JSON.stringify(results, null, 2));
  const matched = results.filter(r => r.match).length;
  console.log(`\nTypeScript: ${matched}/${results.length} match expected`);
  return results;
}

main().catch(console.error);
