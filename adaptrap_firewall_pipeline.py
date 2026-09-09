#!/usr/bin/env python3
"""
AdapTrap Firewall Rule Generation & Evaluation Pipeline
=========================================================
Implements the model -> anomaly score -> firewall rule pipeline described in
AdapTrap Sections 3.3.6 (Firewall Rule Generation) and 3.4.1 (Evaluation Metrics),
using nftables as the enforcement backend (Section 3.3.6.2).

Pipeline stages:
  1. Load a cleaned, feature-engineered attacker-profile CSV (post Section 3.2
     data processing: one row per attacker IP, 24 engineered features).
  2. Train (or load) an Isolation Forest on the training split.
  3. Score the holdout split, inverting decision_function so higher = more
     anomalous (Section 3.3.6.1).
  4. Derive 70th/90th percentile thresholds from the holdout's OWN score
     distribution and assign BLOCK / ESCALATE_TO_ANALYST / ALLOW per profile.
  5. Translate BLOCK rows into nftables drop rules (Section 3.3.6.2) and,
     optionally, apply them to the live ruleset.
  6. Compute Flagging Rate, Anomaly Score Distribution stats, and Silhouette
     Coefficient for this checkpoint; if a prior checkpoint's saved scores are
     supplied, also compute Backward Transfer (BWT) and Forward Transfer (FWT)
     per Section 3.4.1 / 4.4.

IMPORTANT — adapt before running:
  - FEATURE_COLUMNS below must match your actual cleaned CSV's 24 engineered
    columns (Section 4.1). Placeholder names are used; rename to your headers.
  - IP_COLUMN / PORT_COLUMN must point to your source-IP and "most frequent
    destination port" (mode) columns. If you only have a raw list of ports per
    profile, precompute the mode before running this script — do not let this
    script silently invent a port.
  - Applying firewall rules requires root and a working nft binary. Rule
    application defaults to OFF (dry-run) so you can review generated rules
    before anything touches the live firewall.

Usage:
  python3 adaptrap_firewall_pipeline.py \\
      --train-csv batch1_train.csv \\
      --holdout-csv batch1_holdout.csv \\
      --contamination 0.02 \\
      --seed 42 \\
      --out-report batch1_checkpoint.json
      # add --apply to actually push nft rules (requires sudo)
      # add --prev-checkpoint prev.json to compute BWT/FWT against an earlier run
"""

import argparse
import json
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from statistics import mode, StatisticsError

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import silhouette_score

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("adaptrap")

# ---------------------------------------------------------------------------
# CONFIG — edit these to match your actual cleaned CIC-Honeynet feature CSV
# ---------------------------------------------------------------------------

# These 22 columns are produced by build_attacker_profiles.py, verified
# against the real CICHoneynet_July1.csv raw log (Batch 1): the resulting
# 825/177/177 train/validation/holdout split matches Section 4.2 exactly.
# NOTE: the manuscript states "24 engineered attributes" — this script
# implements the ~14 explicitly named ones plus 8 protocol-percentage
# columns (22 total). Reconcile the exact remaining 2 attributes with
# whoever owns Section 4.1 before treating this as manuscript-final.
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

IP_COLUMN = "source_ip"              # attacker source IP per profile
PORT_COLUMN = "dominant_dest_port"   # mode of destination ports for that IP
STRATIFY_COLUMN = "dominant_protocol"  # stratification-only, not a model feature

LOW_PERCENTILE = 70   # ESCALATE_TO_ANALYST floor
HIGH_PERCENTILE = 90  # BLOCK floor

NFT_TABLE = "inet filter"
NFT_CHAIN = "input"


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_profiles(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(
            f"CSV {csv_path} is missing expected feature columns: {missing}\n"
            "Update FEATURE_COLUMNS at the top of this script to match your "
            "actual cleaned dataset headers (Section 3.2 / 4.1)."
        )
    if IP_COLUMN not in df.columns:
        raise ValueError(f"CSV {csv_path} is missing the IP column '{IP_COLUMN}'.")
    return df


# ---------------------------------------------------------------------------
# Model training / scoring (Section 3.3, 3.3.6.1)
# ---------------------------------------------------------------------------

def train_isolation_forest(
    train_df: pd.DataFrame,
    contamination: float,
    seed: int,
    n_estimators: int = 100,
) -> IsolationForest:
    X = train_df[FEATURE_COLUMNS].to_numpy()
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=seed,
    )
    model.fit(X)
    log.info(
        "Trained Isolation Forest: n_estimators=%d contamination=%.3f seed=%d on %d profiles",
        n_estimators, contamination, seed, len(train_df),
    )
    return model


def score_profiles(model: IsolationForest, df: pd.DataFrame) -> np.ndarray:
    """
    Returns inverted anomaly scores where HIGHER = more anomalous, matching
    the convention fixed in Section 3.3.6.1 (raw decision_function values are
    multiplied by -1).
    """
    X = df[FEATURE_COLUMNS].to_numpy()
    raw = model.decision_function(X)
    return -raw


# ---------------------------------------------------------------------------
# Rule engine (Section 3.3.6.1 / 3.3.6.2)
# ---------------------------------------------------------------------------

def assign_actions(scores: np.ndarray) -> tuple[np.ndarray, float, float]:
    low_thresh = np.percentile(scores, LOW_PERCENTILE)
    high_thresh = np.percentile(scores, HIGH_PERCENTILE)

    actions = np.full(scores.shape, "ALLOW", dtype=object)
    actions[(scores >= low_thresh) & (scores < high_thresh)] = "ESCALATE_TO_ANALYST"
    actions[scores >= high_thresh] = "BLOCK"
    return actions, low_thresh, high_thresh


def build_nft_rule(source_ip: str, dest_port) -> str:
    """
    Uses `nft insert rule` (not `add rule`) so this per-IP DROP is evaluated
    BEFORE any pre-existing catch-all accept/reject rules further down the
    chain. `add rule` appends to the end of the chain; on a chain that
    already ends in a terminating reject/accept (e.g. a distro's default
    nftables hardening baseline), an appended rule would rarely if ever be
    reached. `insert rule` prepends to the top instead.
    """
    return (
        f"nft insert rule {NFT_TABLE} {NFT_CHAIN} "
        f"ip saddr {source_ip} tcp dport {int(dest_port)} drop"
    )


def apply_rule(rule_cmd: str, dry_run: bool) -> dict:
    if dry_run:
        log.info("[DRY RUN] %s", rule_cmd)
        return {"command": rule_cmd, "applied": False, "status": "dry_run"}

    try:
        result = subprocess.run(
            rule_cmd.split(),
            check=True,
            capture_output=True,
            text=True,
        )
        log.info("Applied: %s", rule_cmd)
        return {"command": rule_cmd, "applied": True, "status": "ok", "stdout": result.stdout}
    except subprocess.CalledProcessError as e:
        log.error("Failed to apply rule '%s': %s", rule_cmd, e.stderr)
        return {"command": rule_cmd, "applied": False, "status": "error", "stderr": e.stderr}
    except FileNotFoundError:
        log.error("nft binary not found. Is nftables installed?")
        return {"command": rule_cmd, "applied": False, "status": "nft_not_found"}


def generate_and_apply_rules(
    df: pd.DataFrame,
    scores: np.ndarray,
    actions: np.ndarray,
    dry_run: bool,
) -> list[dict]:
    if PORT_COLUMN not in df.columns:
        raise ValueError(
            f"'{PORT_COLUMN}' not found in dataframe. Precompute the mode "
            "destination port per attacker IP before rule generation — this "
            "script will not fabricate a port value."
        )

    results = []
    block_mask = actions == "BLOCK"
    for idx in np.where(block_mask)[0]:
        row = df.iloc[idx]
        # Skip if dominant_dest_port is NaN (no inferable port for this attacker IP)
        if pd.isna(row[PORT_COLUMN]):
            log.warning(
                "Skipping BLOCK rule for %s: dominant_dest_port is NaN "
                "(no preceding TCP handshake seen for this source IP)",
                row[IP_COLUMN]
            )
            continue
        rule_cmd = build_nft_rule(row[IP_COLUMN], row[PORT_COLUMN])
        outcome = apply_rule(rule_cmd, dry_run=dry_run)
        outcome.update({
            "source_ip": row[IP_COLUMN],
            "dest_port": int(row[PORT_COLUMN]),
            "anomaly_score": float(scores[idx]),
            "action": "BLOCK",
        })
        results.append(outcome)
    return results


# ---------------------------------------------------------------------------
# Metrics (Section 3.4.1)
# ---------------------------------------------------------------------------

def flagging_rate(actions: np.ndarray) -> float:
    return float(np.mean(actions == "BLOCK") * 100)


def anomaly_score_distribution(scores: np.ndarray) -> dict:
    return {
        "mean": float(np.mean(scores)),
        "std": float(np.std(scores)),
        "min": float(np.min(scores)),
        "max": float(np.max(scores)),
    }


def silhouette_coefficient(df: pd.DataFrame, actions: np.ndarray) -> float | None:
    """
    Computed on the flagged (BLOCK+ESCALATE treated as one anomaly cluster
    vs. ALLOW) grouping in the model's own feature space, per Section 3.4.1.
    Undefined (returns None) if only one class is present, matching the
    contamination=0.01 case in Table (Section 4.2).
    """
    flagged = actions != "ALLOW"
    if len(set(flagged)) < 2:
        log.warning("Silhouette Coefficient undefined: only one class present.")
        return None
    X = df[FEATURE_COLUMNS].to_numpy()
    return float(silhouette_score(X, flagged))


def backward_forward_transfer(
    current_silhouette_on_prev_holdout: float | None,
    prev_checkpoint_silhouette: float | None,
    current_silhouette_on_current_holdout: float | None,
    static_model_silhouette_on_future_holdout: float | None,
) -> dict:
    """
    BWT = R(2,1) - R(1,1): current (retrained) model evaluated on the
          ORIGINAL holdout, minus the original model's own score on that
          same holdout.
    FWT = R(1,2): the ORIGINAL (pre-retraining) model evaluated on the NEW,
          not-yet-trained-on holdout — a measure of generalization before
          any retraining occurs (Section 4.4).
    Pass None for any value you don't have yet; the corresponding metric
    will be reported as unavailable rather than guessed.
    """
    out = {"BWT": None, "FWT": None}
    if current_silhouette_on_prev_holdout is not None and prev_checkpoint_silhouette is not None:
        out["BWT"] = round(current_silhouette_on_prev_holdout - prev_checkpoint_silhouette, 4)
    if static_model_silhouette_on_future_holdout is not None:
        out["FWT"] = round(static_model_silhouette_on_future_holdout, 4)
    return out


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="AdapTrap firewall rule + metrics pipeline")
    parser.add_argument("--train-csv", required=True, help="Cleaned training-split CSV")
    parser.add_argument("--holdout-csv", required=True, help="Cleaned holdout-split CSV")
    parser.add_argument("--contamination", type=float, default=0.02,
                         help="Isolation Forest contamination (default 0.02, per Section 4.2 tuning)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--apply", action="store_true",
                         help="Actually push BLOCK rules to nftables (requires root). "
                              "Omit this flag to dry-run.")
    parser.add_argument("--out-report", default=None,
                         help="Path to write this checkpoint's JSON report (for later BWT/FWT comparison)")
    parser.add_argument("--prev-checkpoint", default=None,
                         help="Path to a previously saved --out-report JSON, to compute BWT")
    args = parser.parse_args()

    if args.apply:
        log.warning("Running with --apply: firewall rules WILL be pushed to nftables.")

    train_df = load_profiles(args.train_csv)
    holdout_df = load_profiles(args.holdout_csv)

    model = train_isolation_forest(
        train_df, contamination=args.contamination, seed=args.seed, n_estimators=args.n_estimators
    )

    scores = score_profiles(model, holdout_df)
    actions, low_thresh, high_thresh = assign_actions(scores)

    log.info(
        "Thresholds: ESCALATE >= %.4f (p%d), BLOCK >= %.4f (p%d)",
        low_thresh, LOW_PERCENTILE, high_thresh, HIGH_PERCENTILE,
    )

    rule_results = generate_and_apply_rules(holdout_df, scores, actions, dry_run=not args.apply)

    escalate_results = []
    escalate_mask = actions == "ESCALATE_TO_ANALYST"
    for idx in np.where(escalate_mask)[0]:
        row = holdout_df.iloc[idx]
        escalate_results.append({
            "source_ip": row[IP_COLUMN],
            "dest_port": int(row[PORT_COLUMN]) if pd.notna(row[PORT_COLUMN]) else None,
            "anomaly_score": float(scores[idx]),
            "action": "ESCALATE_TO_ANALYST",
        })

    n_block = int(np.sum(actions == "BLOCK"))
    n_escalate = int(np.sum(actions == "ESCALATE_TO_ANALYST"))
    n_allow = int(np.sum(actions == "ALLOW"))
    total = len(actions)

    metrics = {
        "flagging_rate_pct": round(flagging_rate(actions), 2),
        "anomaly_score_distribution": anomaly_score_distribution(scores),
        "silhouette_coefficient": silhouette_coefficient(holdout_df, actions),
        "action_breakdown": {
            "BLOCK": {"count": n_block, "pct": round(n_block / total * 100, 1)},
            "ESCALATE_TO_ANALYST": {"count": n_escalate, "pct": round(n_escalate / total * 100, 1)},
            "ALLOW": {"count": n_allow, "pct": round(n_allow / total * 100, 1)},
        },
    }

    bwt_fwt = {"BWT": None, "FWT": None}
    if args.prev_checkpoint:
        prev_path = Path(args.prev_checkpoint)
        if prev_path.exists():
            prev = json.loads(prev_path.read_text())
            bwt_fwt = backward_forward_transfer(
                current_silhouette_on_prev_holdout=metrics["silhouette_coefficient"],
                prev_checkpoint_silhouette=prev.get("metrics", {}).get("silhouette_coefficient"),
                current_silhouette_on_current_holdout=metrics["silhouette_coefficient"],
                static_model_silhouette_on_future_holdout=None,  # supply if you score prev model on new holdout
            )
        else:
            log.warning("Previous checkpoint file not found: %s", args.prev_checkpoint)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "contamination": args.contamination,
            "seed": args.seed,
            "n_estimators": args.n_estimators,
            "low_percentile": LOW_PERCENTILE,
            "high_percentile": HIGH_PERCENTILE,
            "thresholds": {"low": float(low_thresh), "high": float(high_thresh)},
        },
        "metrics": metrics,
        "bwt_fwt": bwt_fwt,
        "rules_generated": len(rule_results),
        "rule_details": rule_results,
        "escalate_details": escalate_results,
        "dry_run": not args.apply,
    }

    print(json.dumps(report, indent=2, default=str))

    if args.out_report:
        Path(args.out_report).write_text(json.dumps(report, indent=2, default=str))
        log.info("Report written to %s", args.out_report)


if __name__ == "__main__":
    main()
