import re
import numpy as np
import pandas as pd
from scipy import stats
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.metrics import silhouette_score

HONEYPOT_IP = "192.168.10.111"
TOP_PROTOCOLS = ["TCP", "VNC", "TLSv1.2", "SSHv2", "DNS", "TDS", "TELNET", "HTTP"]

_PORT_PATTERN = re.compile(r"(\d+)\s*>\s*(\d+)")
_FLAG_PATTERN = re.compile(r"\[([^\]]+)\]")


def is_private(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
    except ValueError:
        return False


def load_and_clean(csv_path: str, honeypot_ip: str = HONEYPOT_IP) -> pd.DataFrame:
    """
    # Section 3.2.1-3.2.2: load a CIC-Honeynet capture CSV, keep only
    # inbound attacker->honeypot packets, clean, and return a tidy frame
    # with one row per packet.
    """
    raw = pd.read_csv(csv_path, encoding="latin1")
    raw["src_private"] = raw["Source"].apply(is_private)

    inbound = raw[(raw["Destination"] == honeypot_ip) & (~raw["src_private"])].copy()
    inbound = inbound.drop(columns=["src_private"])
    inbound = inbound.rename(columns={
        "Source": "source_ip",
        "Time": "time_sec",
        "Protocol": "protocol",
        "Length": "length",
        "Info": "info",
    })

    inbound = inbound.drop_duplicates()
    inbound["info"] = inbound["info"].fillna("")
    inbound = inbound.dropna(subset=["source_ip", "time_sec"])
    inbound = inbound.sort_values("time_sec").reset_index(drop=True)
    return inbound


def parse_packets(frame: pd.DataFrame) -> pd.DataFrame:
    frame = frame.copy()
    ports = frame["info"].str.extract(_PORT_PATTERN)
    frame["src_port"] = pd.to_numeric(ports[0], errors="coerce")
    frame["dst_port"] = pd.to_numeric(ports[1], errors="coerce")

    flag_str = frame["info"].str.extract(_FLAG_PATTERN)[0].fillna("")
    frame["has_syn"] = flag_str.str.contains("SYN", regex=False).astype(int)
    frame["has_ack"] = flag_str.str.contains("ACK", regex=False).astype(int)
    frame["has_fin"] = flag_str.str.contains("FIN", regex=False).astype(int)
    frame["has_rst"] = flag_str.str.contains("RST", regex=False).astype(int)
    frame["has_psh"] = flag_str.str.contains("PSH", regex=False).astype(int)
    return frame


def compute_conn_rate(frame: pd.DataFrame, window_seconds: int = 60) -> pd.DataFrame:
    """
    Section 3.2.4: vectorized 60-second rolling connection count per
    source IP, using the numeric time_sec column.
    """
    frame = frame.sort_values(["source_ip", "time_sec"]).reset_index(drop=True)
    conn_rate = np.zeros(len(frame), dtype=int)
    for ip, group in frame.groupby("source_ip"):
        times = group["time_sec"].values
        idx = group.index.values
        left = np.searchsorted(times, times - window_seconds, side="right")
        right = np.searchsorted(times, times, side="right")
        conn_rate[idx] = right - left
    frame["conn_rate"] = conn_rate
    return frame


def _build_ip_profile(group: pd.DataFrame) -> pd.Series:
    n = len(group)
    duration = max(group["time_sec"].max() - group["time_sec"].min(), 1e-6)
    profile = {
        "total_packets": n,
        "unique_dst_ports": group["dst_port"].nunique(),
        "protocol_diversity": group["protocol"].nunique(),
        "avg_length": group["length"].mean(),
        "std_length": group["length"].std(skipna=True) or 0.0,
        "max_length": group["length"].max(),
        "syn_ratio": group["has_syn"].mean(),
        "ack_ratio": group["has_ack"].mean(),
        "fin_ratio": group["has_fin"].mean(),
        "rst_ratio": group["has_rst"].mean(),
        "psh_ratio": group["has_psh"].mean(),
        "avg_conn_rate": group["conn_rate"].mean(),
        "max_conn_rate": group["conn_rate"].max(),
        "session_duration": duration,
        "packets_per_second": n / duration,
    }
    for proto in TOP_PROTOCOLS:
        profile[f"pct_{proto.lower().replace('.', '')}"] = (group["protocol"] == proto).mean()
    return pd.Series(profile)


def build_ip_profiles(frame: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate cleaned, parsed, conn_rate-annotated packets into one row
    per attacker IP - the feature matrix Isolation Forest trains on.
    """
    profiles = frame.groupby("source_ip").apply(_build_ip_profile).reset_index()
    return profiles.fillna(0)


def process_batch(csv_path: str, honeypot_ip: str = HONEYPOT_IP) -> pd.DataFrame:
    frame = load_and_clean(csv_path, honeypot_ip)
    frame = parse_packets(frame)
    frame = compute_conn_rate(frame)
    return build_ip_profiles(frame)


def get_feature_cols(profiles: pd.DataFrame) -> list:
    non_feature_cols = {"source_ip", "dominant_protocol"}
    return [c for c in profiles.columns if c not in non_feature_cols]


def fit_scaler(profiles: pd.DataFrame, feature_cols: list) -> StandardScaler:
    scaler = StandardScaler()
    scaler.fit(profiles[feature_cols])
    return scaler


def assign_dominant_protocol(profiles: pd.DataFrame) -> pd.DataFrame:
    """
    Section 3.4.2: adds a 'dominant_protocol' column per attacker IP -
    the stratification label used by stratified_three_way_split.

    The raw capture (CICHoneynet CSVs) has no ground-truth attack-type
    label, so this pipeline derives a traffic-class proxy from the
    features it already computes: whichever TOP_PROTOCOLS pct_* column
    is highest for that IP. IPs whose traffic falls entirely outside
    TOP_PROTOCOLS are labeled 'other'.
    """
    profiles = profiles.copy()
    pct_cols = [f"pct_{p.lower().replace('.', '')}" for p in TOP_PROTOCOLS]
    pct_cols = [c for c in pct_cols if c in profiles.columns]

    dominant = profiles[pct_cols].idxmax(axis=1).str.replace("pct_", "", regex=False)
    all_zero = (profiles[pct_cols] == 0).all(axis=1)
    dominant = dominant.mask(all_zero, "other")

    profiles["dominant_protocol"] = dominant
    return profiles


def stratified_three_way_split(
    profiles: pd.DataFrame,
    stratify_col: str = "dominant_protocol",
    train_size: float = 0.70,
    val_size: float = 0.15,
    test_size: float = 0.15,
    random_state: int = 42,
    min_class_count: int = 3,
):
    """
    Section 3.4.2: 70% train / 15% validation / 15% holdout split,
    stratified on `stratify_col` so each subset is representative of
    the overall traffic-class distribution.

    sklearn's stratify option requires every class to have enough
    members to land in all three splits; classes with fewer than
    `min_class_count` attacker IPs are folded into 'other' first so a
    rare protocol doesn't crash the first split. A class can still
    have enough members to survive that first check but end up with
    too few (e.g. 0 or 1) inside the 30% temp pool used for the
    second split, purely from how the first split happened to land -
    this is checked and re-merged separately before the second split,
    so the fix is not just "raise min_class_count" but "re-check
    after every split", since no single threshold guarantees safety
    against uneven splitting of a small class.

    Returns (train_idx, val_idx, test_idx) - positional indices into
    `profiles`, matching the train_idx/test_idx pattern already used
    in 01_initial_static_model.ipynb.
    """
    assert abs((train_size + val_size + test_size) - 1.0) < 1e-9, \
        "train/val/test sizes must sum to 1.0"

    counts = profiles[stratify_col].value_counts()
    rare_classes = counts[counts < min_class_count].index
    strat_labels = profiles[stratify_col].where(
        ~profiles[stratify_col].isin(rare_classes), "other"
    )

    idx = np.arange(len(profiles))
    train_idx, temp_idx = train_test_split(
        idx, train_size=train_size, stratify=strat_labels, random_state=random_state,
    )

    temp_labels = strat_labels.iloc[temp_idx]
    temp_counts = temp_labels.value_counts()
    still_rare = temp_counts[temp_counts < 2].index
    if len(still_rare) > 0:
        temp_labels = temp_labels.where(~temp_labels.isin(still_rare), "other")
        if temp_labels.value_counts().min() < 2:
            val_idx, test_idx = train_test_split(
                temp_idx, train_size=val_size / (val_size + test_size),
                random_state=random_state,
            )
            return train_idx, val_idx, test_idx

    relative_val_size = val_size / (val_size + test_size)
    val_idx, test_idx = train_test_split(
        temp_idx,
        train_size=relative_val_size,
        stratify=temp_labels,
        random_state=random_state,
    )
    return train_idx, val_idx, test_idx



def tune_contamination(
    X_train: np.ndarray,
    X_val: np.ndarray,
    candidates=(0.01, 0.0125, 0.015, 0.0175, 0.02, 0.05, 0.075, 0.1, 0.125, 0.15, 0.2),
    random_state: int = 42,
):
    """
    Section 3.3.3: sweeps candidate Isolation Forest contamination
    values, scoring each on the validation set with Flagging Rate and
    Silhouette Coefficient - Silhouette is the primary selection
    criterion. The winning value is fixed here, before the holdout
    set is ever touched.

    Returns (best_contamination, fitted_model, results_df). The
    fitted_model is already trained on X_train at best_contamination,
    so no separate .fit() call is needed afterward.
    """
    rows = []
    for c in candidates:
        candidate_model = IsolationForest(
            n_estimators=100, contamination=c, max_samples="auto",
            random_state=random_state,
        )
        candidate_model.fit(X_train)
        flags = (candidate_model.predict(X_val) == -1).astype(int)
        flagging_rate = flags.mean()
        sil = silhouette_score(X_val, flags) if len(set(flags)) > 1 else np.nan
        rows.append({"contamination": c, "flagging_rate": flagging_rate, "silhouette": sil})

    results = pd.DataFrame(rows)
    scored = results.dropna(subset=["silhouette"])
    best_row = scored.loc[scored["silhouette"].idxmax()] if len(scored) else results.iloc[0]
    best_contamination = float(best_row["contamination"])

    best_model = IsolationForest(
        n_estimators=100, contamination=best_contamination, max_samples="auto",
        random_state=random_state,
    )
    best_model.fit(X_train)
    return best_contamination, best_model, results


def get_representative_ports(csv_path: str, honeypot_ip: str = HONEYPOT_IP) -> dict:
    """
    Recovers each attacker IP's most frequently targeted destination
    port from the packet-level data. This detail doesn't survive into
    the aggregated profile table build_ip_profiles() produces, so it
    has to be pulled separately from the packet-level frame - used by
    the rule engine (generate_rules) to attach a representative port
    to each generated firewall rule.

    Returns a dict mapping source_ip -> most common dst_port.
    """
    frame = load_and_clean(csv_path, honeypot_ip)
    frame = parse_packets(frame)
    frame = compute_conn_rate(frame)
    return (
        frame.groupby("source_ip")["dst_port"]
        .agg(lambda x: stats.mode(x.dropna(), keepdims=False).mode if x.dropna().size else None)
        .to_dict()
    )


def generate_rules(model, X_holdout, profiles_holdout: pd.DataFrame, port_lookup: dict, label: str = "") -> pd.DataFrame:
    """
    Two-label firewall rule generation: ALLOW / ESCALATE_TO_ANALYST.

    The label is driven by a single percentile cutoff on the
    holdout's own anomaly score distribution: at or above the 70th
    percentile -> ESCALATE_TO_ANALYST, below it -> ALLOW. This
    matches Section 3.3.6.1 of the methodology. There is no BLOCK
    tier - a percentile cutoff was previously used for a three-tier
    BLOCK/ESCALATE/ALLOW split (90th percentile BLOCK, 70th-90th
    ESCALATE); the BLOCK tier was removed so that no record is ever
    auto-enforced, only auto-flagged for human review.

    Parameters
    ----------
    model : fitted IsolationForest
    X_holdout : scaled feature array to score
    profiles_holdout : the (unscaled) profile DataFrame the rows in
        X_holdout correspond to, row-for-row - used to pull source_ip
    port_lookup : dict from get_representative_ports(), or {} if port
        information isn't available/needed
    label : optional string, used only for the printed summary and
        the CSV export filename

    Returns
    -------
    DataFrame with columns: source_ip, port, anomaly_score, action -
    sorted by anomaly_score descending so the highest-priority
    escalations are first.
    """
    anomaly_scores = -model.decision_function(X_holdout)
    threshold = np.percentile(anomaly_scores, 70)
    actions = np.where(anomaly_scores >= threshold, "ESCALATE_TO_ANALYST", "ALLOW")

    rules_df = pd.DataFrame({
        "source_ip": profiles_holdout["source_ip"].values,
        "port": [port_lookup.get(ip) for ip in profiles_holdout["source_ip"].values],
        "anomaly_score": anomaly_scores,
        "action": actions,
    }).sort_values("anomaly_score", ascending=False).reset_index(drop=True)

    if label:
        print(f"\n--- {label} ---")
        print(rules_df.head(10).to_string())
        print(f"\nESCALATE_TO_ANALYST: {(rules_df.action == 'ESCALATE_TO_ANALYST').sum()}, "
              f"ALLOW: {(rules_df.action == 'ALLOW').sum()}")
        print("(No records are auto-blocked. BLOCK is an analyst decision made after "
              "reviewing an ESCALATE_TO_ANALYST record, not an automated label.)")

    return rules_df