#!/usr/bin/env python3
"""
Deduplicate Batch 2 BLOCK rules against Batch 1 already-applied rules.
Extract source IPs from both checkpoints, identify overlaps, and generate
a deduplicated rule list for Batch 2 application.
"""

import json
import sys

def load_checkpoint(path):
    with open(path, 'r') as f:
        return json.load(f)

def extract_block_ips(checkpoint):
    """Extract source IPs from BLOCK rule_details"""
    ips = set()
    for rule in checkpoint.get('rule_details', []):
        if rule.get('action') == 'BLOCK':
            ips.add(rule['source_ip'])
    return ips

def main():
    batch1 = load_checkpoint('batch1_checkpoint.json')
    batch2 = load_checkpoint('batch2_cumulative_checkpoint.json')

    batch1_ips = extract_block_ips(batch1)
    batch2_ips = extract_block_ips(batch2)

    overlap = batch1_ips & batch2_ips
    batch2_new = batch2_ips - batch1_ips

    print(f"Batch 1 BLOCK rules (already applied): {len(batch1_ips)}")
    print(f"Batch 2 BLOCK candidates: {len(batch2_ips)}")
    print(f"Overlapping IPs (already blocked): {len(overlap)}")
    print(f"New IPs to block from Batch 2: {len(batch2_new)}")
    print()

    if overlap:
        print("Overlapping IPs (will skip):")
        for ip in sorted(overlap):
            print(f"  {ip}")
        print()

    # Extract deduplicated rules
    new_rules = [
        rule for rule in batch2.get('rule_details', [])
        if rule.get('action') == 'BLOCK' and rule['source_ip'] in batch2_new
    ]

    # Write deduplicated checkpoint
    dedupe_checkpoint = batch2.copy()
    dedupe_checkpoint['rule_details'] = new_rules
    dedupe_checkpoint['rules_generated'] = len(new_rules)
    dedupe_checkpoint['deduplication'] = {
        'batch1_existing': len(batch1_ips),
        'batch2_candidates': len(batch2_ips),
        'overlaps_skipped': len(overlap),
        'new_rules': len(batch2_new)
    }

    with open('batch2_deduplicated_checkpoint.json', 'w') as f:
        json.dump(dedupe_checkpoint, f, indent=2)

    print(f"Wrote deduplicated checkpoint: batch2_deduplicated_checkpoint.json")
    print(f"Ready to apply {len(new_rules)} new BLOCK rules")

if __name__ == '__main__':
    main()
