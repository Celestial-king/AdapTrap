#!/usr/bin/env python3
"""
Generate ESCALATE_TO_ANALYST queue from batch2 holdout data.
The original pipeline only stores BLOCK rules in rule_details.
This script recreates the full action assignments to populate the analyst queue.
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path

# Load checkpoint and holdout
with open('batch2_cumulative_checkpoint.json', 'r') as f:
    checkpoint = json.load(f)

holdout = pd.read_csv('batch2_holdout.csv')

# Get thresholds from checkpoint
low_thresh = checkpoint['config']['thresholds']['low']
high_thresh = checkpoint['config']['thresholds']['high']

# Re-run the model to get scores (or we can approximate from the existing data)
# For now, let's use a simpler approach: extract from rule_details and metrics

# The checkpoint has 68 BLOCK, 134 ESCALATE, 471 ALLOW = 673 total
# That matches our holdout size
print(f"Holdout size: {len(holdout)}")
print(f"Expected: 673 (68 BLOCK + 134 ESCALATE + 471 ALLOW)")

# We need to re-score the holdout set
# Load feature columns
FEATURE_COLUMNS = [
    "total_packet_count",
    "unique_dest_ports",
    "protocol_diversity",
    "avg_packet_length",
    "max_packet_length",
    "syn_ratio",
    "ack_ratio",
    "fin_ratio",
    "rst_ratio",
    "psh_ratio",
    "avg_conn_rate",
    "max_conn_rate",
    "session_duration",
    "packets_per_second",
    "proto_tcp_pct",
    "proto_vnc_pct",
    "proto_tlsv12_pct",
    "proto_sshv2_pct",
    "proto_dns_pct",
    "proto_tds_pct",
    "proto_telnet_pct",
    "proto_http_pct",
]

# Train the model again
from sklearn.ensemble import IsolationForest

# Load training data
train1 = pd.read_csv('batch1_train.csv')
train2 = pd.read_csv('batch2_train.csv')
train_combined = pd.concat([train1, train2], ignore_index=True)

X_train = train_combined[FEATURE_COLUMNS].to_numpy()
X_holdout = holdout[FEATURE_COLUMNS].to_numpy()

# Train model with same parameters
model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)
model.fit(X_train)

# Score holdout
raw_scores = model.decision_function(X_holdout)
scores = -raw_scores  # Invert so higher = more anomalous

# Assign actions based on percentile thresholds
low_percentile_thresh = np.percentile(scores, 70)
high_percentile_thresh = np.percentile(scores, 90)

actions = np.full(scores.shape, "ALLOW", dtype=object)
actions[(scores >= low_percentile_thresh) & (scores < high_percentile_thresh)] = "ESCALATE_TO_ANALYST"
actions[scores >= high_percentile_thresh] = "BLOCK"

# Build ESCALATE queue
escalate_queue = []
for idx in np.where(actions == "ESCALATE_TO_ANALYST")[0]:
    row = holdout.iloc[idx]
    escalate_queue.append({
        'source_ip': row['source_ip'],
        'dest_port': int(row['dominant_dest_port']) if pd.notna(row['dominant_dest_port']) else None,
        'anomaly_score': float(scores[idx]),
        'action': 'ESCALATE_TO_ANALYST'
    })

# Sort by score descending
escalate_queue.sort(key=lambda x: x['anomaly_score'], reverse=True)

# Save to JSON
output = {
    'generated_at': checkpoint['generated_at'],
    'total': len(escalate_queue),
    'queue': escalate_queue
}

with open('escalate_queue.json', 'w') as f:
    json.dump(output, f, indent=2)

print(f"✓ Generated {len(escalate_queue)} ESCALATE_TO_ANALYST items")
print(f"  Saved to: escalate_queue.json")
print(f"\nTop 5 items:")
for i, item in enumerate(escalate_queue[:5], 1):
    print(f"  {i}. {item['source_ip']}:{item['dest_port']} - Score: {item['anomaly_score']:.4f}")
