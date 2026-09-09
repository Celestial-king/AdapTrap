# AdapTrap Automation Demonstration Guide
**For Thesis Defense Panel - Team Monolith**

## Addressing the "Human Intervention" Concern

Your panel asked: **"Does the pipeline still have human intervention in analyzing whether to block or allow rules?"**

### Answer: NO - BLOCK rules are 100% automated. Human review exists only for ambiguous cases.

---

## The Three-Tier Decision System

AdapTrap uses **percentile-based thresholds** to automatically classify threats:

```
┌─────────────────────────────────────────────────────────┐
│  Honeypot Packets → Features → ML Model → Anomaly Score │
└─────────────────────────────────────────────────────────┘
                          ↓
              ┌───────────┼───────────┐
              ↓           ↓           ↓
         Score ≥90%   70%≤Score<90%  Score<70%
              ↓           ↓           ↓
          ┌───────┐   ┌────────┐   ┌───────┐
          │ BLOCK │   │ESCALATE│   │ ALLOW │
          │  🤖   │   │   👤   │   │  🤖   │
          └───┬───┘   └───┬────┘   └───────┘
              │           │
              ↓           ↓
         nftables    Human Review
        (AUTO)        (MANUAL)
```

### Tier 1: AUTO-BLOCK (≥90th Percentile) 🤖
- **Fully automated** - Zero human intervention
- Applied directly to nftables firewall
- **Current: 80 rules** auto-applied across Batch 1 + 2
- No approval workflow, no manual steps

### Tier 2: ESCALATE_TO_ANALYST (70th-90th Percentile) 👤
- **Human review required** - NOT auto-blocked
- Ambiguous threats queued for analyst decision
- **Current: 134 items** awaiting review
- Prevents false positives on borderline cases

### Tier 3: AUTO-ALLOW (<70th Percentile) 🤖
- **Fully automated** - Zero human intervention
- Low-risk profiles automatically allowed
- **Current: 471 profiles** auto-allowed
- No blocking action taken

---

## Proof of Automation

### 1. **Live Firewall Verification**

Show the panel that rules are actually in nftables:

```bash
# Count auto-applied BLOCK rules
sudo nft list chain inet filter input | grep -c "ip saddr.*drop"
# Output: 80

# Show actual rules (sample)
sudo nft list chain inet filter input | grep "ip saddr" | head -5
```

All 80 rules were **generated and applied by the pipeline** with zero manual intervention.

### 2. **Checkpoint JSON Evidence**

```bash
# Show all BLOCK rules have "applied": true
cat ~/adaptrap/batch2_applied_checkpoint.json | \
  jq '.rule_details[] | select(.action=="BLOCK") | {ip, score, applied}'
```

Every BLOCK rule shows `"applied": true` - proving automated application.

### 3. **Automation Metrics**

From `batch2_applied_checkpoint.json`:
- **Automation Rate: 80%** (68 BLOCK + 471 ALLOW out of 673 total)
- **Zero-Touch Blocks: 68** (60 applied after deduplication)
- **Human Queue: 134** (ESCALATE only, NOT auto-blocked)

### 4. **Pipeline Execution Logs**

```bash
cat ~/adaptrap/BATCH2_APPLICATION_REPORT.txt
```

Shows:
- 60 rules applied successfully
- 100% success rate
- Timestamp: 2026-09-05T11:54:24Z
- **Zero manual approval steps**

---

## Dashboard Demonstration

Start the enhanced dashboard:

```bash
cd ~/adaptrap
./start_dashboard.sh
# Open: http://127.0.0.1:5000
```

### Key Dashboard Features for Defense

#### 1. **Automation Workflow Visual** (Top of page)
Three-column layout showing:
- 🤖 AUTO-BLOCK (≥90th) - Zero human intervention
- 👤 ANALYST REVIEW (70th-90th) - Manual approval required  
- 🤖 AUTO-ALLOW (<70th) - Zero human intervention

#### 2. **Automation Metrics Card**
- **Automation Rate**: 80% of decisions are automated
- **Zero-Touch Blocks**: 68 threats blocked without human input
- **Analyst Queue Depth**: 134 awaiting human review

#### 3. **Threat Decision Breakdown**
Each action labeled with:
- 🤖 AUTOMATED badge (BLOCK + ALLOW)
- 👤 HUMAN REVIEW badge (ESCALATE only)
- Percentile thresholds shown

#### 4. **Automated BLOCK Rules Table**
Shows all 80 rules with "🤖 Auto-Applied" status

#### 5. **Analyst Review Queue Table**
Shows 134 ESCALATE items with "👤 Pending Review" status
- **Clearly separated** from auto-blocked rules
- Highlights these are NOT automatically applied

---

## Defense Panel Talking Points

### Opening Statement
*"Our system has **three automated tiers**. High-confidence threats at the 90th percentile or above are **automatically blocked** without any human intervention. We've applied **80 firewall rules** this way. Medium-confidence threats between the 70th and 90th percentile go to a **human analyst queue** for review. This ensures we maintain high precision while preventing false positives on ambiguous cases."*

### Key Arguments

**1. Percentile Thresholds Are Data-Driven**
- The 70th/90th cutoffs are derived from the holdout set's **own score distribution**
- Not arbitrary human decisions
- Adapts to each batch's unique threat landscape

**2. BLOCK = Fully Automated**
- Pipeline: `build_attacker_profiles.py` → `adaptrap_firewall_pipeline.py` → `apply_batch2_rules.py`
- Each script runs autonomously
- `nft insert rule` commands executed programmatically
- Zero approval gates in the code

**3. Human Review Is Strategic, Not Universal**
- Only 19.9% of decisions (134/673) require human input
- 80.1% are fully automated (BLOCK + ALLOW)
- Prevents false positives while maintaining automation

**4. Verifiable Evidence**
- Live nftables state matches checkpoint JSON
- Application timestamps prove automation
- No manual approval workflow in codebase

### Anticipated Questions

**Q: "But someone has to review the ESCALATE cases, right?"**
**A:** "Yes, that's by design. The 70th-90th percentile range represents ambiguous cases where the model isn't confident enough to auto-block. We deliberately send those to human analysts to prevent false positives. The high-confidence threats—90th percentile and above—are blocked automatically with zero human intervention."

**Q: "How do you ensure the automated blocks are accurate?"**
**A:** "We use a two-stage validation: (1) The Isolation Forest model is trained on labeled honeypot data where we know attacks occurred, and (2) the 90th percentile threshold ensures only the most anomalous profiles are auto-blocked. Our Silhouette Coefficient of 0.28 in Batch 2 shows clear cluster separation, indicating the model distinguishes attack patterns effectively."

**Q: "Can you show me the automation in action?"**
**A:** "Absolutely. [Open dashboard] Here you can see 80 rules currently active in our firewall, all applied automatically. The 'Last Auto-Applied' timestamp shows when Batch 2 rules were pushed—no manual approval occurred. And here [point to ESCALATE queue] are the 134 cases awaiting human review—clearly separated from the automated decisions."

---

## Technical Flow (For Technical Questions)

### End-to-End Pipeline

```bash
# 1. Generate attacker profiles from raw honeypot data
venv/bin/python3 build_attacker_profiles.py \
  --raw-csv CICHoneynet_July2-9.csv \
  --out-dir . --prefix batch2
# Output: batch2_train.csv, batch2_validation.csv, batch2_holdout.csv

# 2. Train model, score profiles, generate rules (dry-run)
venv/bin/python3 adaptrap_firewall_pipeline.py \
  --train-csv batch2_train.csv \
  --holdout-csv batch2_holdout.csv \
  --contamination 0.05 \
  --out-report batch2_cumulative_checkpoint.json
# Output: Checkpoint JSON with BLOCK/ESCALATE/ALLOW actions

# 3. Deduplicate against previous batches
venv/bin/python3 dedupe_rules.py
# Output: batch2_deduplicated_checkpoint.json

# 4. Apply to live firewall (AUTOMATED)
sudo venv/bin/python3 apply_batch2_rules.py
# Output: 60 rules applied to nftables, batch2_applied_checkpoint.json
```

**No human interaction in any of these steps.**

### Code Evidence: Zero Approval Gates

Check `apply_batch2_rules.py` lines 48-101:
- Reads checkpoint JSON
- Iterates through rules
- Executes `subprocess.run()` for each `nft insert rule` command
- No `input()` calls, no approval prompts, no manual gates

---

## Comparison to Signature-Based Systems

| Feature | AdapTrap | Traditional IDS/IPS |
|---------|----------|---------------------|
| **Rule Generation** | 🤖 Automated (ML-driven) | 👤 Manual (security analysts) |
| **Adaptation Speed** | Days (batch retraining) | Weeks/months (manual updates) |
| **Zero-Day Response** | Behavioral anomaly detection | Requires known signatures |
| **Human Intervention** | 19.9% (ambiguous cases only) | 100% (all rule writing) |
| **Scalability** | Processes 4,485 profiles automatically | Limited by analyst bandwidth |

---

## Live Demo Script (5 Minutes)

### Minute 1: Show the Dashboard
1. Open http://127.0.0.1:5000
2. Point out **Automation Workflow** section at top
3. Highlight "ZERO human intervention" labels

### Minute 2: Show Automation Metrics
1. Point to **Automation Rate: 80%**
2. Show **Zero-Touch Blocks: 68**
3. Explain **Analyst Queue: 134** (NOT auto-blocked)

### Minute 3: Show Applied Rules
1. Scroll to **Automated BLOCK Rules** table
2. Show "🤖 Auto-Applied" status on all entries
3. Note the variety of IPs/ports (proves real data)

### Minute 4: Show Analyst Queue
1. Scroll to **Analyst Review Queue**
2. Show "👤 Pending Review" status
3. Emphasize: "These are NOT automatically blocked"

### Minute 5: Verify in Live Firewall
```bash
# In terminal:
sudo nft list chain inet filter input | grep -c "ip saddr.*drop"
# Shows: 80 (matches dashboard)

# Show sample rule:
sudo nft list chain inet filter input | grep "52.44.177.92"
# Shows: actual nftables rule blocking this IP
```

**Conclusion**: "The dashboard matches the live firewall state, proving our automation works end-to-end."

---

## Files to Reference During Defense

1. **RESUME_SESSION.md** - Project overview and current state
2. **BATCH2_APPLICATION_REPORT.txt** - Detailed automation evidence
3. **batch2_applied_checkpoint.json** - Machine-readable proof
4. **adaptrap_firewall_pipeline.py** - Show lines 169-215 (rule generation logic)
5. **apply_batch2_rules.py** - Show lines 48-79 (automated application)

---

## Common Misconceptions to Address

### Misconception 1: "All rules need human approval"
**Reality**: Only 19.9% (ESCALATE tier) need human review. 80.1% are automated.

### Misconception 2: "The model just flags threats for humans to block"
**Reality**: The model DIRECTLY GENERATES and APPLIES nftables rules for high-confidence threats.

### Misconception 3: "Someone has to manually write firewall rules"
**Reality**: The pipeline GENERATES the exact `nft insert rule` commands programmatically.

---

## Success Criteria Met

✅ **Full automation for high-confidence threats** (≥90th percentile)  
✅ **Zero approval gates in pipeline code**  
✅ **80 live firewall rules** prove real-world deployment  
✅ **Verifiable evidence** (nftables state = checkpoint JSON)  
✅ **Strategic human review** (ambiguous cases only)  
✅ **End-to-end demonstration** (dashboard + live firewall)  

---

**AdapTrap demonstrates practical, deployable automation with human oversight only where it adds value—preventing false positives on borderline cases while automatically blocking clear threats.**

Team Monolith | Asia Pacific College | September 2026
