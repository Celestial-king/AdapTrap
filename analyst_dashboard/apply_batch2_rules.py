#!/usr/bin/env python3
"""
Apply deduplicated Batch 2 BLOCK rules to live nftables firewall.
Reads batch2_deduplicated_checkpoint.json and applies each rule via nft insert.
Must run with sudo to modify firewall.
"""

import json
import subprocess
import sys
from datetime import datetime, timezone

def load_checkpoint(path):
    with open(path, 'r') as f:
        return json.load(f)

def apply_rule(rule_cmd):
    """Execute nft command and return result"""
    try:
        result = subprocess.run(
            rule_cmd.split(),
            check=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        return {
            "command": rule_cmd,
            "applied": True,
            "status": "ok",
            "stdout": result.stdout.strip()
        }
    except subprocess.CalledProcessError as e:
        return {
            "command": rule_cmd,
            "applied": False,
            "status": "error",
            "stderr": e.stderr.strip()
        }
    except Exception as e:
        return {
            "command": rule_cmd,
            "applied": False,
            "status": "error",
            "stderr": str(e)
        }

def main():
    checkpoint = load_checkpoint('batch2_deduplicated_checkpoint.json')
    rules = checkpoint.get('rule_details', [])

    print(f"Applying {len(rules)} deduplicated BLOCK rules to nftables...")
    print(f"Started at: {datetime.now(timezone.utc).isoformat()}")
    print()

    applied_count = 0
    failed_count = 0
    results = []

    for i, rule in enumerate(rules, 1):
        cmd = rule['command']
        print(f"[{i}/{len(rules)}] {cmd}")

        result = apply_rule(cmd)
        result.update({
            'source_ip': rule['source_ip'],
            'dest_port': rule['dest_port'],
            'anomaly_score': rule['anomaly_score'],
            'action': 'BLOCK'
        })
        results.append(result)

        if result['applied']:
            applied_count += 1
            print(f"  ✓ Applied")
        else:
            failed_count += 1
            print(f"  ✗ Failed: {result.get('stderr', 'unknown error')}")

    print()
    print(f"Applied: {applied_count}/{len(rules)}")
    print(f"Failed: {failed_count}/{len(rules)}")

    # Update checkpoint with application results
    final_checkpoint = checkpoint.copy()
    final_checkpoint['rule_details'] = results
    final_checkpoint['applied_at'] = datetime.now(timezone.utc).isoformat()
    final_checkpoint['dry_run'] = False
    final_checkpoint['application_summary'] = {
        'total': len(rules),
        'applied': applied_count,
        'failed': failed_count
    }

    output_path = 'batch2_applied_checkpoint.json'
    with open(output_path, 'w') as f:
        json.dump(final_checkpoint, f, indent=2)

    print(f"\nFinal checkpoint written to: {output_path}")

    return 0 if failed_count == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
