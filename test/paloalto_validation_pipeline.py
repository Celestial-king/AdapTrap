"""
paloalto_native_pipeline.py

Same AdapTrap METHODOLOGY as adaptrap_pipeline.py (per-source-IP
behavioral profiling -> silhouette-tuned Isolation Forest contamination
-> 70th-percentile two-tier escalation), but the FEATURES are built
natively from what log_4 (TRAFFIC) and log_5 (THREAT) actually contain
-- nothing here is a proxy for a CICHoneynet field that Palo Alto
doesn't have. Every feature below is something these logs genuinely,
directly measure.

Two real signals CICHoneynet had that these logs also genuinely have:
  - real timestamps (Receive Time)      -> conn_rate_60s is computed
    the same way adaptrap_pipeline.compute_conn_rate does, on real
    observed times, not estimated.
  - a real severity/signature system    -> THREAT log rows carry an
    actual analyst-relevant severity and named signature, which
    CICHoneynet's raw captures never had at all. This pipeline uses
    that as new, native signal rather than discarding it to force a
    CICHoneynet-shaped feature set.

What's deliberately NOT here: no syn/ack/fin/rst/psh ratios. Palo
Alto's Flags field is session metadata, not TCP flags, and there is no
faithful way to recover per-packet flags from a session-summary log --
so rather than proxy them again, they're left out entirely.
"""
import numpy as np
import pandas as pd

TARGET_IP = "202.57.49.243"

SEVERITY_SCORE = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

FEATURE_COLS = [
    "total_records",
    "total_traffic_sessions",
    "total_threat_alerts",
    "unique_dst_ports",
    "unique_applications",
    "port_to_record_ratio",
    "avg_bytes_per_session",
    "avg_packets_per_session",
    "avg_elapsed_time",
    "pct_incomplete",
    "pct_tcp_fin",
    "pct_rst",
    "pct_aged_out",
    "threat_alert_rate",
    "avg_severity_score",
    "unique_threat_signatures",
    "conn_rate_60s_max",
    "conn_rate_60s_avg",
]


def is_private(ip: str) -> bool:
    try:
        parts = str(ip).split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
    except ValueError:
        return False


def load_and_merge(traffic_csv: str, threat_csv: str, target_ip: str = TARGET_IP) -> pd.DataFrame:
    traffic = pd.read_csv(traffic_csv)
    threat = pd.read_csv(threat_csv)
    traffic["_kind"] = "traffic"
    threat["_kind"] = "threat"

    merged = pd.concat([traffic, threat], ignore_index=True, sort=False)
    merged = merged[merged["Destination address"] == target_ip].copy()
    merged = merged[~merged["Source address"].apply(is_private)]
    merged["time_sec"] = pd.to_datetime(merged["Receive Time"]).astype("int64") / 1e9
    merged = merged.sort_values("time_sec").reset_index(drop=True)
    return merged


def _conn_rate_60s(merged: pd.DataFrame, window_seconds: int = 60) -> np.ndarray:
    """Same rolling-window logic as adaptrap_pipeline.compute_conn_rate,
    applied here to real Receive Time values across BOTH logs merged."""
    conn_rate = np.zeros(len(merged), dtype=int)
    for ip, group in merged.groupby("Source address"):
        times = group["time_sec"].values
        idx = group.index.values
        left = np.searchsorted(times, times - window_seconds, side="right")
        right = np.searchsorted(times, times, side="right")
        conn_rate[idx] = right - left
    return conn_rate


def _build_ip_profile(g: pd.DataFrame) -> pd.Series:
    is_traffic = g["_kind"] == "traffic"
    is_threat = g["_kind"] == "threat"
    n = len(g)
    traffic_rows = g[is_traffic]
    threat_rows = g[is_threat]

    severity_scores = threat_rows["Severity"].map(SEVERITY_SCORE) if len(threat_rows) else pd.Series([], dtype=float)
    ser_end = traffic_rows.get("Session End Reason", pd.Series(dtype=object)).fillna("")

    return pd.Series({
        "total_records": n,
        "total_traffic_sessions": len(traffic_rows),
        "total_threat_alerts": len(threat_rows),
        "unique_dst_ports": g["Destination Port"].nunique(),
        "unique_applications": g["Application"].nunique(),
        "port_to_record_ratio": g["Destination Port"].nunique() / max(n, 1),
        "avg_bytes_per_session": traffic_rows["Bytes"].mean() if len(traffic_rows) else 0.0,
        "avg_packets_per_session": traffic_rows["Packets"].mean() if len(traffic_rows) else 0.0,
        "avg_elapsed_time": traffic_rows["Elapsed Time (sec)"].mean() if len(traffic_rows) else 0.0,
        "pct_incomplete": (traffic_rows["Application"] == "incomplete").mean() if len(traffic_rows) else 0.0,
        "pct_tcp_fin": (ser_end == "tcp-fin").mean() if len(traffic_rows) else 0.0,
        "pct_rst": ser_end.isin(["tcp-rst-from-client", "tcp-rst-from-server"]).mean() if len(traffic_rows) else 0.0,
        "pct_aged_out": (ser_end == "aged-out").mean() if len(traffic_rows) else 0.0,
        "threat_alert_rate": len(threat_rows) / max(n, 1),
        "avg_severity_score": severity_scores.mean() if len(severity_scores) else 0.0,
        "unique_threat_signatures": threat_rows["Threat/Content Name"].nunique() if len(threat_rows) else 0,
        "conn_rate_60s_max": g["conn_rate_60s"].max(),
        "conn_rate_60s_avg": g["conn_rate_60s"].mean(),
    })


def build_ip_profiles(merged: pd.DataFrame) -> pd.DataFrame:
    merged = merged.copy()
    merged["conn_rate_60s"] = _conn_rate_60s(merged)
    profiles = merged.groupby("Source address").apply(_build_ip_profile).reset_index()
    profiles = profiles.rename(columns={"Source address": "source_ip"})
    return profiles.fillna(0)


def three_way_split(profiles: pd.DataFrame, train_size=0.70, val_size=0.15, test_size=0.15, random_state=42):
    """Random split -- same fallback adaptrap_pipeline uses when a
    dataset is too small/uniform to stratify meaningfully."""
    from sklearn.model_selection import train_test_split
    assert abs((train_size + val_size + test_size) - 1.0) < 1e-9
    idx = np.arange(len(profiles))
    train_idx, temp_idx = train_test_split(idx, train_size=train_size, random_state=random_state)
    val_idx, test_idx = train_test_split(
        temp_idx, train_size=val_size / (val_size + test_size), random_state=random_state
    )
    return train_idx, val_idx, test_idx


def run(traffic_csv: str, threat_csv: str, score_full_population: bool = True):
    from sklearn.preprocessing import StandardScaler
    from adaptrap_pipeline import tune_contamination, generate_rules

    merged = load_and_merge(traffic_csv, threat_csv)
    profiles = build_ip_profiles(merged)
    print(f"Merged: {len(merged)} records, {profiles.shape[0]} unique source IPs")
    print(f"Native features used: {FEATURE_COLS}")

    train_idx, val_idx, test_idx = three_way_split(profiles)
    print(f"Split -> train:{len(train_idx)} val:{len(val_idx)} holdout:{len(test_idx)}")

    scaler = StandardScaler().fit(profiles.iloc[train_idx][FEATURE_COLS])
    X_train = scaler.transform(profiles.iloc[train_idx][FEATURE_COLS])
    X_val = scaler.transform(profiles.iloc[val_idx][FEATURE_COLS])

    contamination, model, sweep = tune_contamination(X_train, X_val)
    print(f"\nContamination sweep:\n{sweep}")
    print(f"\nSelected contamination: {contamination}")

    score_idx = np.arange(len(profiles)) if score_full_population else test_idx
    X_score = scaler.transform(profiles.iloc[score_idx][FEATURE_COLS])

    port_lookup = merged.groupby("Source address")["Destination Port"] \
        .agg(lambda x: x.mode().iloc[0] if len(x.mode()) else None).to_dict()

    rules_df = generate_rules(model, X_score, profiles.iloc[score_idx].reset_index(drop=True),
                               port_lookup, label="Palo Alto NATIVE features")

    split_label = {}
    for i in train_idx: split_label[profiles.iloc[i]["source_ip"]] = "train"
    for i in val_idx: split_label[profiles.iloc[i]["source_ip"]] = "val"
    for i in test_idx: split_label[profiles.iloc[i]["source_ip"]] = "holdout"
    rules_df["split"] = rules_df["source_ip"].map(split_label)

    return merged, profiles, rules_df, contamination, sweep


if __name__ == "__main__":
    merged, profiles, rules_df, contamination, sweep = run(
        "/mnt/user-data/uploads/log_4__truncated.csv",
        "/mnt/user-data/uploads/log_5__2.csv",
    )
    rules_df.to_csv("/mnt/user-data/outputs/paloalto_native_rules.csv", index=False)
