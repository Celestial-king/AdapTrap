# AdapTrap 🛡️

**Adaptive Firewall via Continual Anomaly Learning from Honeypot Telemetry**

A BS Computer Science thesis project (Team Monolith, Asia Pacific College). AdapTrap is a honeypot-driven continual learning system that automatically classifies attacker profiles using Isolation Forest anomaly detection and enforces decisions through nftables firewall rules — with a real-time web dashboard for analyst oversight.

---

## Architecture

```
Raw Honeypot Capture (Wireshark CSV)
        │
        ▼
build_attacker_profiles.py   ← Feature engineering (24 attributes per attacker IP)
        │
        ▼
adaptrap_firewall_pipeline.py  ← Isolation Forest training + scoring
        │
        ├── ≥90th percentile → 🤖 AUTO-BLOCK   (nftables drop rule, zero-touch)
        ├── 70–90th          → 👤 ANALYST QUEUE (human Block / Allow decision)
        └── <70th            → 🤖 AUTO-ALLOW   (no further action)
```

The Flask dashboard (Tab 1: Overview, Tab 2: Analyst Review, Tab 3: Import Logs) ties every stage together with live streaming output, 1-click deployment, and automatically numbered batch tracking (Batch 1, Batch 2, Batch 3 …).

---

## Setup

### 1. Create and activate the virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure passwordless sudo for nftables
Add this line via `sudo visudo` (replace `sentry` with your username):
```
sentry ALL=(root) NOPASSWD: /usr/sbin/nft
```

### 3. Start the dashboard
```bash
./start_dashboard.sh
```
Open **http://127.0.0.1:5000** in your browser.

---

## Dataset

Raw honeypot captures (CIC-Honeynet dataset) are **not included** in this repository due to file size limits.

- **CICHoneynet_July1.csv** (~45 MB) — used for Batch 1
- **CICHoneynet_July2-9.csv** (~280 MB) — used for Batch 2

Download the CIC-Honeynet dataset from the [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/).

Pre-built split CSVs for Batch 1 and Batch 2 (`batch1_train.csv`, `batch1_holdout.csv`, `batch2_train.csv`, `batch2_holdout.csv`) are included so the pipeline can be run immediately without the raw captures.

---

## Usage

### Build attacker profiles from a raw capture
```bash
python3 build_attacker_profiles.py \
    --raw-csv CICHoneynet_July1.csv \
    --out-dir . \
    --prefix batch1
```

### Run the ML pipeline (dry-run, inspect results)
```bash
python3 adaptrap_firewall_pipeline.py \
    --train-csv batch1_train.csv \
    --holdout-csv batch1_holdout.csv \
    --contamination 0.02 \
    --out-report batch1_checkpoint.json
```

### Apply rules to nftables (requires sudo)
```bash
python3 adaptrap_firewall_pipeline.py \
    --train-csv batch1_train.csv \
    --holdout-csv batch1_holdout.csv \
    --contamination 0.02 \
    --apply
```

---

## Dashboard Tabs

| Tab | Purpose |
|-----|---------|
| **Overview** | Live firewall rule count per batch, automation metrics, attack pattern chart |
| **Analyst Review** | Interactive queue of 70–90th percentile threats — Block or Allow with one click |
| **Import Logs** | Upload a raw Wireshark CSV, stream profile generation, inspect model report, deploy to firewall |

---

## Key Files

| File | Description |
|------|-------------|
| `build_attacker_profiles.py` | Cleans raw Wireshark CSV → 24-feature attacker profiles, 70/15/15 split |
| `adaptrap_firewall_pipeline.py` | Isolation Forest training, scoring, nftables rule generation |
| `dashboard/app.py` | Flask backend — APIs, job runner, batch management |
| `dashboard/templates/` | Jinja2 templates for the 3-tab UI |
| `batch1_checkpoint.json` | Batch 1 model checkpoint (metrics + applied rules) |
| `batch2_applied_checkpoint.json` | Batch 2 model checkpoint |

---

## Evaluation Metrics

- **Flagging Rate** — % of holdout profiles classified as anomalous
- **Silhouette Coefficient** — Cluster quality of BLOCK vs ALLOW separation
- **Anomaly Score Distribution** — Mean / std / max of inverted Isolation Forest scores
- **Backward Transfer (BWT)** — Retention of Batch 1 performance after Batch 2 retraining
- **Forward Transfer (FWT)** — Generalization of Batch 1 model to unseen Batch 2 data
