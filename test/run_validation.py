import pandas as pd
import numpy as np
import sys
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.append('/Users/gabriellecabangcala/thesis/AdapTrap/models')
from adaptrap_pipeline import build_ip_profiles, get_feature_cols

# 1. Load Data
consolidated = pd.read_csv('/Users/gabriellecabangcala/thesis/AdapTrap/test/consolidated_dataset.csv')
log4 = pd.read_csv('/Users/gabriellecabangcala/thesis/AdapTrap/test/log(4).csv')
log5 = pd.read_csv('/Users/gabriellecabangcala/thesis/AdapTrap/test/log(5) 2.csv')

# 2. Adaptation logic
def adapt_schema(df):
    # Mapping logic...
    df = df.rename(columns={
        "Source address": "source_ip",
        "Time Logged": "time_sec",
        "Destination Port": "dst_port",
        "Bytes": "length",
        "Application": "protocol"
    })
    # Pre-parse flags if needed...
    # Simple adaptation for now
    df['dst_port'] = df['dst_port'].fillna(0)
    df['protocol'] = df['protocol'].fillna('other')
    df['length'] = df['length'].fillna(0)
    df['has_syn'] = 0 # Placeholder adaptation
    df['has_ack'] = 0
    df['has_fin'] = 0
    df['has_rst'] = 0
    df['has_psh'] = 0
    # ...
    return df

# 3. Pipeline
# 3. Pipeline (Reusing AdapTrap pipeline exactly)
from adaptrap_pipeline import (
    assign_dominant_protocol,
    stratified_three_way_split,
    tune_contamination,
    generate_rules
)

# A. Apply your schema adaptation to the unlabelled dataset
adapted_df = adapt_schema(consolidated)

# Fake compute_conn_rate logic so we don't crash the original profiler
# (Since PAN logs lack sub-second timestamps, we just set it to 0 or 1 for this adaptation)
adapted_df['conn_rate'] = 1

# B. Build Profiles using the ORIGINAL AdapTrap function
profiles = build_ip_profiles(adapted_df)

# C. Get Feature Columns (exclude IPs and labels)
feature_cols = get_feature_cols(profiles)

# D. Setup for Split (Original methodology uses stratified splitting based on dominant protocol)
profiles = assign_dominant_protocol(profiles)
train_idx, val_idx, test_idx = stratified_three_way_split(profiles, stratify_col="dominant_protocol")

# E. Unsupervised Training & Scaler Fitting
import joblib

# 1. Load the saved "Model 3" components
print("Loading Model 3...")
best_model = joblib.load('/Users/gabriellecabangcala/thesis/AdapTrap/saved_models/m3_IF_model')
scaler = joblib.load('/Users/gabriellecabangcala/thesis/AdapTrap/saved_models/m3_scaler')
# Note: Use these saved feature columns to ensure the input matches the model's training
feature_cols = joblib.load('/Users/gabriellecabangcala/thesis/AdapTrap/saved_models/m3_feature_cols')

# 2. Skip the fitting/tuning (use pre-fit components)
# X_holdout = scaler.transform(profiles.iloc[test_idx][feature_cols].values)
# Wait: since we are applying a saved model, we apply it to the whole profiles dataframe
X_processed = scaler.transform(profiles[feature_cols].values)
profiles_holdout = profiles.copy()

# 3. Generate Percentile-Based Rules using the LOADED model
rules_df = generate_rules(
    model=best_model,
    X_holdout=X_processed,
    profiles_holdout=profiles_holdout,
    port_lookup={},
    label="External Validation (Model 3)", percentile=50

# G. Generate Percentile-Based Rules on Holdout (Original 70th percentile escalation logic)
X_holdout = scaler.transform(profiles.iloc[test_idx][feature_cols].values)
profiles_holdout = profiles.iloc[test_idx].copy()

# Note: passing an empty dict for port_lookup as PAN logs might have multiple ports
rules_df = generate_rules(
    model=best_model,
    X_holdout=X_holdout,
    profiles_holdout=profiles_holdout,
    port_lookup={},
    label="External Validation (PAN Logs)"
)


# 4. Final Evaluation (Only access labels NOW)
print("
--- FINAL EVALUATION ---")

# Combine the ground truth logs
truth_df = pd.concat([log4, log5])

# Aggregate PAN log firewall actions to a per-IP basis.
# If an IP ever triggered a 'reset-both' or 'alert' firewall action, it is malicious.
# If it only ever triggered 'allow', it is benign.
malicious_firewall_actions = ['reset-both', 'alert']
is_malicious = truth_df['Action'].isin(malicious_firewall_actions)

truth_threat_ips = truth_df[is_malicious]['Source address'].unique()

# Direct mapping to uniform AdapTrap labels:
# Firewall "allow" -> AdapTrap "ALLOW"
# Firewall "reset-both"/"alert" -> AdapTrap "ESCALATE_TO_ANALYST"
rules_df['true_action'] = rules_df['source_ip'].isin(truth_threat_ips).map({
    True: 'ESCALATE_TO_ANALYST', 
    False: 'ALLOW'
})

from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
preds = rules_df['action'] # Already ALLOW / ESCALATE_TO_ANALYST
truth = rules_df['true_action']

print(f"Accuracy: {accuracy_score(truth, preds):.2%}")
print("
Confusion Matrix [Allow, Escalate]:")
print(confusion_matrix(truth, preds, labels=['ALLOW', 'ESCALATE_TO_ANALYST']))
print("
Classification Report:")
print(classification_report(truth, preds, labels=['ALLOW', 'ESCALATE_TO_ANALYST'], zero_division=0))
