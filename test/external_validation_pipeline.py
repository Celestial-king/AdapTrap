"""
external_validation_pipeline.py

A standalone validation pipeline for the AdapTrap methodology, built to
run against the `malicious_network_dataset` (connection-level, labeled
malicious/benign) instead of the CICHoneynet packet captures the main
pipeline (adaptrap_pipeline.py) was built for.

This is NOT a drop-in reuse of the fitted M3 model. The two datasets
have incompatible schemas (no timestamps, no TCP-flag info string, and
`length` is on a different scale entirely -- see the shape-comparison
done in-conversation). Reusing M3's fitted scaler/model on this data
would be scientifically invalid. Instead, this module applies the SAME
METHODOLOGY -- per-source-IP behavioral profiling, silhouette-tuned
Isolation Forest contamination, percentile-based two-tier escalation --
independently, using only features this dataset's schema can support.

Ground-truth labels are used ONLY at the final evaluation step. Nothing
upstream of `evaluate_against_ground_truth()` ever sees the `class`
column, preserving the unsupervised design of the original pipeline.

Workflow:
    unlabeled_df = load_unlabeled("malicious_network_dataset_nolabel.numbers")
    profiles     = build_ip_profiles(unlabeled_df)
    train_idx, val_idx, test_idx = three_way_split(profiles)
    contamination, model = tune_contamination(profiles, feature_cols, train_idx, val_idx)
    rules_df     = generate_rules(model, profiles, feature_cols, test_idx)
    results      = evaluate_against_ground_truth(rules_df, "malicious_network_dataset.csv")
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    silhouette_score, confusion_matrix, precision_score,
    recall_score, accuracy_score, f1_score,
)
from sklearn.model_selection import train_test_split

TARGET_LOCAL_IP = "165.227.180.71"  # the one real target host in this dataset

# Features derivable from this dataset's schema. protocol_diversity is
# deliberately excluded -- it's a hard constant (every row is 'tcp'
# after cleaning), so it carries zero information here even though the
# column name matches something in adaptrap_pipeline.py's profile.
FEATURE_COLS = [
    "total_packets",
    "unique_remote_ports",
    "avg_length",
    "payload_ratio",
    "port_to_packet_ratio",
]


def load_unlabeled(path: str) -> pd.DataFrame:
    """
    Loads the nolabel dataset (.numbers or .csv) and applies the same
    cleaning rules used throughout: keep real TCP connections to the
    actual target host, drop rows missing the fields profiling needs.
    """
    if path.endswith(".numbers"):
        from numbers_parser import Document
        doc = Document(path)
        table = doc.sheets[0].tables[0]
        rows = table.rows(values_only=True)
        df = pd.DataFrame(rows[1:], columns=rows[0])
    else:
        df = pd.read_csv(path)

    df = df[(df["protocol"] == "tcp") & (df["local_ip"] == TARGET_LOCAL_IP)].copy()
    df = df.dropna(subset=["remote_ip", "local_port", "length"])
    return df.reset_index(drop=True)


def _build_ip_profile(g: pd.DataFrame) -> pd.Series:
    has_payload = g["data_hex"].notna()
    return pd.Series({
        "total_packets": len(g),
        "unique_remote_ports": g["remote_port"].nunique(),
        "avg_length": g["length"].mean(),
        "payload_ratio": has_payload.mean(),
        "port_to_packet_ratio": g["remote_port"].nunique() / max(len(g), 1),
    })


def build_ip_profiles(df: pd.DataFrame) -> pd.DataFrame:
    """One row per remote_ip -- the feature matrix Isolation Forest trains on."""
    profiles = df.groupby("remote_ip").apply(_build_ip_profile).reset_index()
    return profiles.fillna(0)


def three_way_split(profiles: pd.DataFrame, train_size=0.70, val_size=0.15,
                     test_size=0.15, random_state=42):
    """
    Plain random 70/15/15 split. Unlike adaptrap_pipeline's
    stratified_three_way_split, this can't stratify on dominant
    protocol -- protocol is a constant in this dataset (see
    FEATURE_COLS note above), so there's nothing to stratify on.
    """
    assert abs((train_size + val_size + test_size) - 1.0) < 1e-9
    idx = np.arange(len(profiles))
    train_idx, temp_idx = train_test_split(idx, train_size=train_size, random_state=random_state)
    val_idx, test_idx = train_test_split(
        temp_idx, train_size=val_size / (val_size + test_size), random_state=random_state
    )
    return train_idx, val_idx, test_idx


def tune_contamination(profiles: pd.DataFrame, feature_cols: list,
                        train_idx, val_idx,
                        candidates=(0.01, 0.0125, 0.015, 0.0175, 0.02, 0.05,
                                    0.075, 0.1, 0.125, 0.15, 0.2),
                        random_state: int = 42):
    """
    Same silhouette-selected contamination sweep as adaptrap_pipeline.py.
    Ground-truth labels are never touched here -- selection is purely
    unsupervised, exactly mirroring the original methodology.
    """
    X = profiles[feature_cols].fillna(0)
    scaler = StandardScaler().fit(X.iloc[train_idx])
    X_train = scaler.transform(X.iloc[train_idx])
    X_val = scaler.transform(X.iloc[val_idx])

    rows = []
    for c in candidates:
        m = IsolationForest(n_estimators=100, contamination=c, max_samples="auto",
                             random_state=random_state).fit(X_train)
        flags = (m.predict(X_val) == -1).astype(int)
        sil = silhouette_score(X_val, flags) if len(set(flags)) > 1 else np.nan
        rows.append({"contamination": c, "flagging_rate": flags.mean(), "silhouette": sil})

    results = pd.DataFrame(rows)
    scored = results.dropna(subset=["silhouette"])
    best_row = scored.loc[scored["silhouette"].idxmax()] if len(scored) else results.iloc[0]
    best_contamination = float(best_row["contamination"])

    best_model = IsolationForest(n_estimators=100, contamination=best_contamination,
                                  max_samples="auto", random_state=random_state).fit(X_train)
    return best_contamination, best_model, scaler, results


def generate_rules(model, scaler, profiles: pd.DataFrame, feature_cols: list,
                    test_idx, label: str = "") -> pd.DataFrame:
    """
    Same two-tier ALLOW / ESCALATE_TO_ANALYST logic as
    adaptrap_pipeline.generate_rules: 70th percentile of the holdout's
    own anomaly-score distribution is the escalation cutoff.
    """
    X_test = scaler.transform(profiles[feature_cols].fillna(0).iloc[test_idx])
    # Use the model's own thresholding logic
    # predict() returns -1 for anomalies (malicious) and 1 for inliers (benign)
    predictions = model.predict(X_test)
    actions = np.where(predictions == -1, "malicious", "benign")

    # We still calculate scores for sorting purposes,
    # but we don't force a percentile threshold anymore.
    scores = -model.decision_function(X_test)

    out = profiles.iloc[test_idx][["remote_ip"]].copy()
    out["anomaly_score"] = scores
    out["action"] = actions
    out = out.sort_values("anomaly_score", ascending=False).reset_index(drop=True)

    if label:
        print(f"\n--- {label} ---")
        print(f"Malicious: {(out.action=='malicious').sum()}, "
              f"Benign: {(out.action=='benign').sum()}")
    return out


def evaluate_against_ground_truth(rules_df: pd.DataFrame, labeled_csv_path: str) -> dict:
    """
    The ONLY function in this module that reads the `class` column.
    Aggregates the labeled dataset to per-IP ground truth (an IP is
    'malicious' if ANY of its connections were labeled malicious --
    a deliberate, conservative choice; document this if you change it),
    joins against rules_df's predictions, and reports the confusion
    matrix and standard classification metrics.
    """
    labeled = pd.read_csv(labeled_csv_path)
    labeled = labeled[(labeled["protocol"] == "tcp") & (labeled["local_ip"] == TARGET_LOCAL_IP)]
    truth = (
        labeled.groupby("remote_ip")["class"]
        .apply(lambda s: "malicious" if "malicious" in s.str.strip().str.lower().values else "benign")
        .reset_index().rename(columns={"class": "true_label"})
    )

    merged = rules_df.merge(truth, on="remote_ip", how="left")
    # Clean the true_label to ensure it is malicious/benign
    merged["true_label"] = merged["true_label"].str.strip().str.lower()
    # Map any value containing 'malicious' to 'malicious', else 'benign'
    merged["true_label"] = np.where(merged["true_label"].str.contains("malicious", na=False), "malicious", "benign")

    # The action output is already 'malicious' or 'benign' from generate_rules()
    merged["pred_label"] = merged["action"]
    merged = merged.dropna(subset=["true_label"])

    cm = confusion_matrix(merged["true_label"], merged["pred_label"], labels=["malicious", "benign"])
    metrics = {
        "n": len(merged),
        "confusion_matrix": cm,
        "confusion_matrix_labels": ["malicious", "benign"],
        "precision_malicious": precision_score(merged["true_label"], merged["pred_label"], pos_label="malicious"),
        "recall_malicious": recall_score(merged["true_label"], merged["pred_label"], pos_label="malicious"),
        "f1_malicious": f1_score(merged["true_label"], merged["pred_label"], pos_label="malicious"),
        "accuracy": accuracy_score(merged["true_label"], merged["pred_label"]),
        "baseline_majority_class_accuracy": merged["true_label"].value_counts(normalize=True).max(),
    }
    return merged, metrics


def run_full_validation(unlabeled_path: str, labeled_path: str, verbose: bool = True):
    """End-to-end: load -> profile -> split -> tune -> score -> evaluate."""
    df = load_unlabeled(unlabeled_path)
    profiles = build_ip_profiles(df)
    train_idx, val_idx, test_idx = three_way_split(profiles)
    contamination, model, scaler, sweep = tune_contamination(profiles, FEATURE_COLS, train_idx, val_idx)
    rules_df = generate_rules(model, scaler, profiles, FEATURE_COLS, test_idx,
                               label="External Validation (holdout)" if verbose else "")
    merged, metrics = evaluate_against_ground_truth(rules_df, labeled_path)

    if verbose:
        print(f"\nSelected contamination: {contamination}")
        print(f"\nHoldout n={metrics['n']}  |  majority-class baseline accuracy: "
              f"{metrics['baseline_majority_class_accuracy']:.3f}")
        print(f"Confusion matrix {metrics['confusion_matrix_labels']}:\n{metrics['confusion_matrix']}")
        print(f"Precision(malicious): {metrics['precision_malicious']:.3f}  "
              f"Recall(malicious): {metrics['recall_malicious']:.3f}  "
              f"F1: {metrics['f1_malicious']:.3f}  "
              f"Accuracy: {metrics['accuracy']:.3f}")

    return {
        "profiles": profiles, "contamination_sweep": sweep, "contamination": contamination,
        "rules_df": rules_df, "merged": merged, "metrics": metrics,
    }


if __name__ == "__main__":
    results = run_full_validation(
        unlabeled_path="/mnt/user-data/uploads/malicious_network_dataset_nolabel.numbers",
        labeled_path="/mnt/user-data/uploads/malicious_network_dataset.csv",
    )