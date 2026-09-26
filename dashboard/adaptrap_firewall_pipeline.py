#!/usr/bin/env python3
"""
AdapTrap Firewall Rule Generation Pipeline (scoring-only, M3 checkpoint)
=========================================================================
Scores a newly uploaded honeypot capture against the published M3
continual-learning checkpoint (Sections 3.3-3.3.6). M3 is treated as
final/frozen: this script does NOT retrain — it loads the saved
IsolationForest, StandardScaler, and feature column list from Hugging
Face, and applies them to new data only.

Rule engine is two-tier (ALLOW / ESCALATE_TO_ANALYST), per Section
3.3.6.1 — there is no BLOCK tier. No record is ever auto-enforced;
blocking is an analyst decision made through the dashboard's Analyst
Review tab, not something this script decides.

Usage:
  python3 adaptrap_firewall_pipeline.py \\
      --raw-csv new_batch.csv \\
      --out-report batch_checkpoint.json
"""

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
import sys

import joblib
import numpy as np
from huggingface_hub import hf_hub_download
from sklearn.metrics import silhouette_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "models"))
from adaptrap_pipeline import generate_rules, load_and_clean, parse_packets, compute_conn_rate, build_ip_profiles

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("adaptrap")

REPO_NAME = "RnzB6/AdapTrap-m3"


# ---------------------------------------------------------------------------
# Load the published M3 checkpoint once, at import time
# ---------------------------------------------------------------------------
from pathlib import Path
SAVED_MODELS_DIR = Path(__file__).resolve().parent.parent / "saved_models"

model = joblib.load(SAVED_MODELS_DIR / "m3_IF_model")
scaler = joblib.load(SAVED_MODELS_DIR / "m3_scaler")
FEATURE_COLUMNS = joblib.load(SAVED_MODELS_DIR / "m3_feature_cols")


# ---------------------------------------------------------------------------
# Metrics (Section 3.4.1)
# ---------------------------------------------------------------------------

def flagging_rate(actions: np.ndarray) -> float:
    return float(np.mean(actions == "ESCALATE_TO_ANALYST") * 100)


def anomaly_score_distribution(scores: np.ndarray) -> dict:
    return {
        "mean": float(np.mean(scores)),
        "std": float(np.std(scores)),
        "min": float(np.min(scores)),
        "max": float(np.max(scores)),
    }


def silhouette_coefficient(model, X: np.ndarray) -> float | None:
    """
    Computed using the model's own contamination-based decision
    (model.predict), matching the evaluation methodology used in the
    thesis notebooks (Section 3.4.1) — NOT the 70th-percentile
    escalation threshold used by the rule engine (generate_rules).
    These are two different, intentionally separate things: this
    metric reports model quality; generate_rules decides operational
    firewall actions.
    """
    flags = (model.predict(X) == -1).astype(int)
    if len(set(flags)) < 2:
        log.warning("Silhouette Coefficient undefined: only one class present.")
        return None
    return float(silhouette_score(X, flags))


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Score a new honeypot capture against the M3 checkpoint")
    parser.add_argument("--raw-csv", required=True, help="Raw Wireshark-exported capture CSV")
    parser.add_argument("--out-report", default=None,
                         help="Path to write this batch's JSON report")
    args = parser.parse_args()

    log.info("Scoring %s against published M3 checkpoint (%s)", args.raw_csv, REPO_NAME)

    # Build attacker profiles the same way M3's training data was built
    raw = load_and_clean(args.raw_csv)          # cleaned packet-level frame
    raw = parse_packets(raw)
    raw = compute_conn_rate(raw)
    profiles = build_ip_profiles(raw)           # same aggregated result as before

    # Guard against a batch missing a protocol column M3 was trained on
    for col in FEATURE_COLUMNS:
        if col not in profiles.columns:
            profiles[col] = 0

    X_scaled = scaler.transform(profiles[FEATURE_COLUMNS])

    # No port lookup: enforcement blocks the full IP, not a specific port
    rules_df = generate_rules(model, X_scaled, profiles, {}, label="New batch vs M3")

    scores = rules_df["anomaly_score"].to_numpy()
    actions = rules_df["action"].to_numpy()

    n_escalate = int(np.sum(actions == "ESCALATE_TO_ANALYST"))
    n_allow = int(np.sum(actions == "ALLOW"))
    total = len(actions)

    profile_lookup = profiles.set_index("source_ip")

    escalate_details = []
    for _, row in rules_df[rules_df["action"] == "ESCALATE_TO_ANALYST"].iterrows():
        ip = row["source_ip"]

        profile_row = {}
        if ip in profile_lookup.index:
            p = profile_lookup.loc[ip].to_dict()
            profile_row = {k: (float(v) if isinstance(v, (int, float)) else v)
                            for k, v in p.items() if k != "dominant_protocol"}

        ip_packets = raw[raw["source_ip"] == ip][["time_sec", "source_ip", "protocol", "length", "info"]]
        packet_rows = ip_packets.head(50).to_dict(orient="records")  # cap at 50 rows per IP — see note below

        escalate_details.append({
            "source_ip": ip,
            "dest_port": None,
            "anomaly_score": float(row["anomaly_score"]),
            "action": "ESCALATE_TO_ANALYST",
            "profile": profile_row,
            "packets": packet_rows,
        })

    metrics = {
        "flagging_rate_pct": round(flagging_rate(actions), 2),
        "anomaly_score_distribution": anomaly_score_distribution(scores),
        "silhouette_coefficient": silhouette_coefficient(model, X_scaled),
        "action_breakdown": {
            "ESCALATE_TO_ANALYST": {"count": n_escalate, "pct": round(n_escalate / total * 100, 1)},
            "ALLOW": {"count": n_allow, "pct": round(n_allow / total * 100, 1)},
        },
    }

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "model_source": REPO_NAME,
            "low_percentile": 70,
        },
        "metrics": metrics,
        "rules_generated": 0,
        "rule_details": [],
        "escalate_details": escalate_details,
        "dry_run": True,
    }

    print(json.dumps(report, indent=2, default=str))

    if args.out_report:
        Path(args.out_report).write_text(json.dumps(report, indent=2, default=str))
        log.info("Report written to %s", args.out_report)


if __name__ == "__main__":
    main()