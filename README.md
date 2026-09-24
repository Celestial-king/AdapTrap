# AdapTrap 🛡️

**Adaptive Firewall via Continual Anomaly Learning from Honeypot Telemetry**

A BS Computer Science thesis project (Team Monolith, Asia Pacific College). AdapTrap is a honeypot-driven continual learning system that classifies attacker profiles using Isolation Forest anomaly detection and presents the results in a real-time web dashboard for analyst review. Firewall BLOCK rules are applied only after an analyst approves them.

---

## Architecture

```
Raw Honeypot Capture (Wireshark CSV)
        │
        ▼
dashboard/build_attacker_profiles.py   ← Feature engineering (24 attributes per attacker IP)
        │
        ▼
dashboard/adaptrap_firewall_pipeline.py  ← Isolation Forest training + scoring
        │
        └── suspicious candidates → 👤 ANALYST QUEUE (human Block / Allow decision)
```

The Flask dashboard (Overview, Analyst Review, Import Logs, and Firewall Rules) ties every stage together with live streaming output, analyst-controlled deployment, and automatically numbered batch tracking (Batch 1, Batch 2, Batch 3 …). No firewall rules are applied automatically.

---

## Model Checkpoint

The trained Isolation Forest model checkpoint is available on [Hugging Face](https://huggingface.co/RnzB6/AdapTrap-m3) for reproducibility and model preservation.

## Setup

### 1. Create and activate the Python 3.11 virtual environment

The project uses Python 3.11 for its pinned dependencies. Fish users should use
the `activate.fish` script:

```fish
python3.11 -m venv venv
source venv/bin/activate.fish
pip install -r requirements.txt
```

If the environment has already been created, only activation is required:

```fish
source venv/bin/activate.fish
```

### 2. Configure optional nftables access

This is required only when an analyst approves a BLOCK rule or when querying
the live firewall rules. It is not required to run the dashboard or inspect
model results.

Add this line via `sudo visudo` (replace `sentry` with your username):

```
sentry ALL=(root) NOPASSWD: /usr/sbin/nft
```

### 3. Start the dashboard

```fish
python dashboard/app.py
```

Open **http://127.0.0.1:5000** in your browser.

---

## Dataset

Raw honeypot captures (CIC-Honeynet dataset) are **not included** in this repository due to file size limits.

- **CICHoneynet_July1.csv** (~45 MB) — used for Batch 1
- **CICHoneynet_July2-9.csv** (~280 MB) — used for Batch 2

Download the CIC-Honeynet dataset from the [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/).

The raw captures and split CSV files are not included in this checkout. Provide
the appropriate input CSVs when running the profile builder or pipeline.

---


The dashboard's deployment flow queues all candidates for analyst review.
Only an explicit analyst BLOCK decision can apply a rule to nftables.

---

## Dashboard Tabs

| Tab                | Purpose                                                                                         |
| ------------------ | ----------------------------------------------------------------------------------------------- |
| **Overview**       | Live firewall rule count per batch, model metrics, and attack pattern chart                       |
| **Analyst Review** | Interactive queue of 70–90th percentile threats — Block or Allow with one click                 |
| **Import Logs**    | Upload a raw Wireshark CSV, stream profile generation, inspect the model report, and queue candidates |
| **Firewall Rules**  | View active nftables rules and remove rules by handle                                               |

---

## Key Files

| File                             | Description                                                             |
| -------------------------------- | ----------------------------------------------------------------------- |
| `dashboard/build_attacker_profiles.py`     | Cleans raw Wireshark CSV → 24-feature attacker profiles, 70/15/15 split |
| `dashboard/adaptrap_firewall_pipeline.py`  | Isolation Forest training, scoring, and dry-run rule generation          |
| `dashboard/app.py`               | Flask backend — APIs, job runner, batch management                      |
| `dashboard/templates/`           | Jinja2 templates for the dashboard UI                                   |
| `batch3_applied_checkpoint.json` | Batch 3 model checkpoint and analyst-deployment metadata                |
| `escalate_queue.json`            | Candidates waiting for analyst review                                  |
| `reviewed_decisions.json`        | Analyst Block / Allow decisions                                         |

---

## Evaluation Metrics

- **Flagging Rate** — % of holdout profiles classified as anomalous
- **Silhouette Coefficient** — Cluster quality of BLOCK vs ALLOW separation
- **Anomaly Score Distribution** — Mean / std / max of inverted Isolation Forest scores
- **Backward Transfer (BWT)** — Retention of Batch 1 performance after Batch 2 retraining
- **Forward Transfer (FWT)** — Generalization of Batch 1 model to unseen Batch 2 data
