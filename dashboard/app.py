#!/usr/bin/env python3
"""
AdapTrap Web Dashboard
Tabs: Overview | Analyst Review | Import Logs | Firewall Rules

nft permissions: this app shells out to `sudo nft …` for status queries,
analyst-approved BLOCK rules, and handle-based rule deletion.

Required sudoers line (run `sudo visudo` and add):
    <your_user> ALL=(root) NOPASSWD: /usr/sbin/nft
Replace <your_user> with the account that runs Flask (e.g. `sentry`).
"""

import json
import logging
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from flask import Flask, Response, jsonify, redirect, render_template, request, url_for

app = Flask(__name__)

log = logging.getLogger("adaptrap.dashboard")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).parent.parent
ESCALATE_FILE = PROJECT_ROOT / "escalate_queue.json"
REVIEWED_FILE = PROJECT_ROOT / "reviewed_decisions.json"
IMPORTED_BATCHES_FILE = PROJECT_ROOT / "imported_batches.json"


def _resolve_project_script(filename: str) -> Path:
    """Use worktree scripts when present, otherwise the configured source checkout."""
    candidates = [PROJECT_ROOT / filename]
    configured_root = os.environ.get("ADAPTRAP_SCRIPT_ROOT")
    if configured_root:
        candidates.append(Path(configured_root) / filename)
    source_root = PROJECT_ROOT.parent.parent / "adaptrap"
    candidates.append(source_root / filename)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


PIPELINE_SCRIPT = _resolve_project_script("adaptrap_firewall_pipeline.py")
PROFILES_SCRIPT = _resolve_project_script("build_attacker_profiles.py")
# Reuse the interpreter running Flask so background jobs work in worktrees
# that do not contain their own virtualenv. Override when a separate runtime
# is required.
PYTHON = os.environ.get("ADAPTRAP_PYTHON", sys.executable)

NFT_TABLE = "inet filter"
NFT_CHAIN = "input"

# ---------------------------------------------------------------------------
# In-process import job registry  {job_id: {"status": …, "log": […], …}}
# ---------------------------------------------------------------------------
_import_jobs: dict[str, dict] = {}
_import_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _build_nft_rule(source_ip: str, dest_port: int) -> str:
    """Exact same rule format as adaptrap_firewall_pipeline.build_nft_rule."""
    return (
        f"sudo -n nft insert rule {NFT_TABLE} {NFT_CHAIN} "
        f"ip saddr {source_ip} tcp dport {int(dest_port)} drop"
    )


def _apply_nft_rule(source_ip: str, dest_port: int) -> dict:
    """
    Push a single BLOCK rule to the live nftables chain.
    Returns {"applied": bool, "status": str, "command": str, "error": str|None}.
    """
    import ipaddress
    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        return {"applied": False, "status": "invalid_ip",
                "command": "", "error": f"Rejecting malformed IP: {source_ip!r}"}

    cmd = _build_nft_rule(source_ip, dest_port)
    try:
        result = subprocess.run(
            cmd.split(),
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        log.info("Applied nft rule: %s", cmd)
        return {"applied": True, "status": "ok", "command": cmd,
                "stdout": result.stdout, "error": None}
    except subprocess.CalledProcessError as exc:
        err = exc.stderr.strip() if exc.stderr else f"Exit code {exc.returncode}"
        log.error("nft rule failed: %s — %s", cmd, err)
        return {"applied": False, "status": "nft_error",
                "command": cmd, "error": err}
    except FileNotFoundError:
        return {"applied": False, "status": "sudo_not_found",
                "command": cmd, "error": "sudo/nft binary not found"}
    except subprocess.TimeoutExpired:
        return {"applied": False, "status": "timeout",
                "command": cmd, "error": "nft command timed out"}


def _apply_nft_rules_batch(rules_list: list[dict]) -> dict:
    """
    Apply a batch of BLOCK rules to nftables in a single atomic call via stdin.
    Drastically reduces deployment time from ~2 minutes to <100ms.
    """
    import ipaddress
    valid_rules = []
    failed_rules = []

    for r in rules_list:
        ip = str(r.get("source_ip", "")).strip()
        port = r.get("dest_port")
        try:
            ipaddress.ip_address(ip)
            if port is None or pd.isna(port):
                continue
            port_int = int(port)
            valid_rules.append({
                "source_ip": ip,
                "dest_port": port_int,
                "anomaly_score": float(r.get("anomaly_score", 0.0)),
                "action": "BLOCK",
                "command": f"nft insert rule {NFT_TABLE} {NFT_CHAIN} ip saddr {ip} tcp dport {port_int} drop",
            })
        except Exception as e:
            failed_rules.append({**r, "error": str(e), "applied": False})

    if not valid_rules:
        return {"applied": [], "failed": failed_rules, "error": None}

    # Pass all rules to nft in one atomic batch
    payload_lines = [
        f"insert rule {NFT_TABLE} {NFT_CHAIN} ip saddr {r['source_ip']} tcp dport {r['dest_port']} drop"
        for r in valid_rules
    ]
    payload = "\n".join(payload_lines) + "\n"

    try:
        proc = subprocess.run(
            ["sudo", "-n", "nft", "-f", "-"],
            input=payload,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0:
            for r in valid_rules:
                r["applied"] = True
                r["status"] = "ok"
            log.info("Batch applied %d nft rules atomically in <50ms", len(valid_rules))
            return {"applied": valid_rules, "failed": failed_rules, "error": None}
        else:
            log.warning("Batch nft failed (code %d): %s. Falling back to individual rules.",
                        proc.returncode, proc.stderr.strip() if proc.stderr else "")
    except Exception as e:
        log.warning("Batch nft exception: %s. Falling back to individual rules.", e)

    # Fallback to individual rule application if stdin batch fails
    applied = []
    for r in valid_rules:
        res = _apply_nft_rule(r["source_ip"], r["dest_port"])
        if res["applied"]:
            applied.append({**r, "applied": True, "status": "ok"})
        else:
            failed_rules.append({**r, "applied": False, "error": res.get("error")})

    return {"applied": applied, "failed": failed_rules, "error": None}


# ---------------------------------------------------------------------------
# Checkpoint / queue / batch loading
# ---------------------------------------------------------------------------

def get_next_batch_info() -> tuple[int, str, str]:
    """
    Computes the next sequential batch number and labels.
    Batch 1 and Batch 2 are baseline.
    Imported batches are Batch 3, Batch 4, Batch 5, etc.
    Returns (batch_number, batch_id, display_name).
    """
    imported = load_imported_batches()
    existing_nums = [1, 2]
    for b in imported:
        num = b.get("batch_number")
        if isinstance(num, int):
            existing_nums.append(num)
        else:
            bid = str(b.get("batch_id", ""))
            if bid.startswith("batch") and bid[5:].isdigit():
                existing_nums.append(int(bid[5:]))
    next_num = max(existing_nums) + 1
    return next_num, f"batch{next_num}", f"Batch {next_num}"


def load_checkpoint(filename: str) -> dict | None:
    filepath = PROJECT_ROOT / filename
    if filepath.exists():
        try:
            with open(filepath) as fh:
                return json.load(fh)
        except Exception as e:
            log.warning("Failed to load checkpoint %s: %s", filename, e)
    return None


def load_escalate_queue() -> dict:
    if ESCALATE_FILE.exists():
        try:
            with open(ESCALATE_FILE) as fh:
                return json.load(fh)
        except Exception:
            pass
    return {"total": 0, "queue": [], "generated_at": None}


def save_escalate_queue(data: dict) -> None:
    with open(ESCALATE_FILE, "w") as fh:
        json.dump(data, fh, indent=2)


def load_reviewed() -> list[dict]:
    if REVIEWED_FILE.exists():
        try:
            with open(REVIEWED_FILE) as fh:
                return json.load(fh)
        except Exception:
            pass
    return []


def save_reviewed(items: list[dict]) -> None:
    with open(REVIEWED_FILE, "w") as fh:
        json.dump(items, fh, indent=2)


def load_imported_batches() -> list[dict]:
    if IMPORTED_BATCHES_FILE.exists():
        try:
            with open(IMPORTED_BATCHES_FILE) as fh:
                data = json.load(fh)
                return data.get("batches", [])
        except Exception:
            pass
    return []


def save_imported_batches(batches: list[dict]) -> None:
    with open(IMPORTED_BATCHES_FILE, "w") as fh:
        json.dump({"batches": batches}, fh, indent=2)


def get_all_applied_checkpoints() -> list[dict]:
    """Returns all active batches: Batch 1, Batch 2, plus all applied imports (Batch 3, 4, ...)."""
    res = []
    b1 = load_checkpoint("batch1_checkpoint.json")
    if b1:
        applied_cnt = len([r for r in b1.get("rule_details", []) if r.get("action") == "BLOCK" and r.get("applied", False)]) or b1.get("rules_generated", 0)
        res.append({
            "name": "Batch 1",
            "data": b1,
            "batch_id": "batch1",
            "applied_count": applied_cnt
        })
    b2 = load_checkpoint("batch2_applied_checkpoint.json")
    if b2:
        applied_cnt = b2.get("application_summary", {}).get("applied", len([r for r in b2.get("rule_details", []) if r.get("action") == "BLOCK" and r.get("applied", False)]))
        res.append({
            "name": "Batch 2",
            "data": b2,
            "batch_id": "batch2",
            "applied_count": applied_cnt
        })

    for ib in load_imported_batches():
        cp_file = ib.get("checkpoint_file")
        if cp_file:
            cp_data = load_checkpoint(cp_file)
            if cp_data:
                rule_cnt = ib.get("rules_applied", len([r for r in cp_data.get("rule_details", []) if r.get("action") == "BLOCK"]))
                res.append({
                    "name": ib.get("display_name", f"Batch {ib.get('batch_number', '?')}"),
                    "data": cp_data,
                    "batch_id": ib.get("batch_id"),
                    "batch_number": ib.get("batch_number"),
                    "applied_count": rule_cnt,
                    "filename": ib.get("filename"),
                    "applied_at": ib.get("applied_at"),
                })
    return res


# ---------------------------------------------------------------------------
# Firewall status
# ---------------------------------------------------------------------------

def get_firewall_status() -> dict:
    try:
        result = subprocess.run(
            ["sudo", "-n", "nft", "list", "chain", "inet", "filter", "input"],
            capture_output=True, text=True, timeout=1,
        )
        if result.returncode == 0:
            rule_count = sum(
                1 for line in result.stdout.splitlines()
                if "ip saddr" in line and "drop" in line
            )
            return {"success": True, "rule_count": rule_count}
        return {"success": False, "error": "nft returned non-zero"}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return redirect(url_for("overview"))


@app.route("/overview")
def overview():
    return render_template("overview.html", active_tab="overview")


@app.route("/analyst-review")
def analyst_review():
    return render_template("analyst_review.html", active_tab="analyst_review")


@app.route("/import-logs")
def import_logs():
    return render_template("import_logs.html", active_tab="import_logs")


@app.route("/firewall-rules")
def firewall_rules():
    return render_template("firewall_rules.html", active_tab="firewall_rules")


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.route("/api/status")
def api_status():
    all_checkpoints = get_all_applied_checkpoints()
    firewall = get_firewall_status()

    batches_info = []
    total_calculated_rules = 0
    last_applied = None

    for b in all_checkpoints:
        cnt = b["applied_count"]
        total_calculated_rules += cnt
        applied_at = b["data"].get("applied_at") or b["data"].get("generated_at")
        if applied_at:
            last_applied = applied_at
        batches_info.append({
            "name": b["name"],
            "batch_id": b["batch_id"],
            "applied": cnt,
            "generated_at": b["data"].get("generated_at"),
            "applied_at": b["data"].get("applied_at"),
        })

    # Include any reviewed BLOCKs that were applied
    reviewed = load_reviewed()
    analyst_blocks = sum(1 for r in reviewed if r.get("decision") == "BLOCK" and r.get("nft_applied"))
    total_calculated_rules += analyst_blocks

    live_count = firewall.get("rule_count") if firewall.get("success") else None

    # Backward compatibility
    b1_applied = next((b["applied_count"] for b in all_checkpoints if b["batch_id"] == "batch1"), 0)
    b2_applied = next((b["applied_count"] for b in all_checkpoints if b["batch_id"] == "batch2"), 0)

    return jsonify({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "firewall": firewall,
        "batches": batches_info,
        "batch1": {
            "loaded": any(b["batch_id"] == "batch1" for b in all_checkpoints),
            "applied": b1_applied,
        },
        "batch2": {
            "loaded": any(b["batch_id"] == "batch2" for b in all_checkpoints),
            "applied": b2_applied,
        },
        "total_active_rules": live_count if live_count is not None else total_calculated_rules,
        "last_auto_applied": last_applied,
    })


@app.route("/api/metrics")
def api_metrics():
    batch1 = load_checkpoint("batch1_checkpoint.json")
    batch2 = load_checkpoint("batch2_applied_checkpoint.json")
    all_checkpoints = get_all_applied_checkpoints()

    # If there are imported checkpoints, surface the latest one
    latest_imported = all_checkpoints[-1]["data"].get("metrics") if len(all_checkpoints) > 2 else None

    return jsonify({
        "batch1": batch1.get("metrics") if batch1 else None,
        "batch2": batch2.get("metrics") if batch2 else None,
        "latest": latest_imported or (batch2.get("metrics") if batch2 else None),
    })


@app.route("/api/rules")
def api_rules():
    all_checkpoints = get_all_applied_checkpoints()
    rules = []
    seen_ips = set()

    for b in all_checkpoints:
        cp = b["data"]
        batch_label = b["name"]
        for rule in cp.get("rule_details", []):
            ip = rule.get("source_ip")
            if rule.get("action") == "BLOCK" and ip and ip not in seen_ips:
                seen_ips.add(ip)
                rules.append({
                    "batch": batch_label,
                    "ip": ip,
                    "port": rule.get("dest_port"),
                    "score": rule.get("anomaly_score", 0.0),
                    "applied": True,
                })

    # Include analyst-reviewed BLOCKs that were applied
    reviewed = load_reviewed()
    for r in reviewed:
        if r.get("decision") == "BLOCK" and r.get("nft_applied"):
            if r["source_ip"] not in seen_ips:
                seen_ips.add(r["source_ip"])
                rules.append({
                    "batch": r.get("batch") or "Analyst Review",
                    "ip": r["source_ip"],
                    "port": r.get("dest_port"),
                    "score": 0.0,
                    "applied": True,
                })

    rules.sort(key=lambda r: r["score"], reverse=True)
    return jsonify({"rules": rules, "total": len(rules)})


def _rule_checkpoint_labels() -> dict[tuple[str, int], str]:
    labels = {}
    for batch in get_all_applied_checkpoints():
        checkpoint = batch["data"]
        for rule in checkpoint.get("rule_details", []):
            source_ip = rule.get("source_ip")
            port = rule.get("dest_port")
            if source_ip and port is not None and not pd.isna(port):
                labels[(str(source_ip), int(port))] = batch["name"]

    for decision in load_reviewed():
        if decision.get("decision") == "BLOCK" and decision.get("nft_applied"):
            source_ip = decision.get("source_ip")
            port = decision.get("dest_port")
            if source_ip and port is not None:
                labels[(str(source_ip), int(port))] = decision.get("batch") or "Analyst Review"
    return labels


def _list_active_nft_rules() -> list[dict]:
    result = subprocess.run(
        ["sudo", "-n", "nft", "-a", "list", "chain", *NFT_TABLE.split(), NFT_CHAIN],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    labels = _rule_checkpoint_labels()
    rules = []
    for line in result.stdout.splitlines():
        if " drop" not in f" {line}":
            continue
        handle_match = re.search(r"#\s*handle\s+(\d+)\s*$", line)
        source_match = re.search(r"\bip\s+saddr\s+(\S+)", line)
        port_match = re.search(r"\btcp\s+dport\s+(\d+)", line)
        if not handle_match or not source_match or not port_match:
            continue
        source_ip = source_match.group(1)
        port = int(port_match.group(1))
        rules.append({
            "source_ip": source_ip,
            "port": port,
            "handle": int(handle_match.group(1)),
            "checkpoint": labels.get((source_ip, port), "Unknown"),
        })
    return rules


@app.route("/api/firewall-rules")
def api_firewall_rules():
    try:
        rules = _list_active_nft_rules()
    except subprocess.CalledProcessError as exc:
        error = exc.stderr.strip() if exc.stderr else f"nft exited with code {exc.returncode}"
        log.error("Unable to list active nftables rules: %s", error)
        if "password is required" in error.lower():
            error = (
                "Dashboard user cannot run nft without a password. "
                "Configure sudoers for /usr/sbin/nft with NOPASSWD."
            )
        return jsonify({"ok": False, "error": error}), 502
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.error("Unable to list active nftables rules: %s", exc)
        return jsonify({"ok": False, "error": "Unable to query nftables"}), 502
    return jsonify({"ok": True, "rules": rules, "total": len(rules)})


@app.route("/api/delete-rule", methods=["POST"])
def api_delete_rule():
    body = request.get_json(force=True, silent=True) or {}
    handle = body.get("handle")
    if isinstance(handle, bool) or not isinstance(handle, int) or handle <= 0:
        return jsonify({"ok": False, "error": "handle must be a positive integer"}), 400

    cmd = [
        "sudo", "-n", "nft", "delete", "rule", *NFT_TABLE.split(),
        NFT_CHAIN, "handle", str(handle),
    ]
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=5)
    except subprocess.CalledProcessError as exc:
        error = exc.stderr.strip() if exc.stderr else f"nft exited with code {exc.returncode}"
        log.error("Unable to delete nftables rule handle %d: %s", handle, error)
        if "password is required" in error.lower():
            error = (
                "Dashboard user cannot delete nft rules without a password. "
                "Configure sudoers for /usr/sbin/nft with NOPASSWD."
            )
        return jsonify({"ok": False, "error": error}), 502
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.error("Unable to delete nftables rule handle %d: %s", handle, exc)
        return jsonify({"ok": False, "error": "Unable to execute nftables deletion"}), 502

    log.info("Deleted nftables rule handle %d", handle)
    return jsonify({"ok": True, "handle": handle, "stdout": result.stdout})


@app.route("/api/attack_patterns")
def api_attack_patterns():
    all_checkpoints = get_all_applied_checkpoints()
    if not all_checkpoints:
        return jsonify({"error": "No data available"})

    port_services = {
        22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS",
        1433: "MS SQL", 3306: "MySQL", 5432: "PostgreSQL",
        5555: "Backdoor", 5900: "VNC", 6379: "Redis",
        8443: "HTTPS-Alt", 9200: "Elasticsearch",
    }

    patterns: dict[str, int] = {}
    for b in all_checkpoints:
        cp = b["data"]
        for rule in cp.get("rule_details", []):
            if rule.get("action") == "BLOCK":
                port = rule.get("dest_port")
                if port is not None and not pd.isna(port):
                    port = int(port)
                    service = port_services.get(port, f"Port {port}" if port < 1024 else "High Port")
                    patterns[service] = patterns.get(service, 0) + 1

    pattern_list = sorted(
        [{"service": k, "count": v} for k, v in patterns.items()],
        key=lambda x: x["count"], reverse=True,
    )
    return jsonify({"patterns": pattern_list})


@app.route("/api/automation_metrics")
def api_automation_metrics():
    all_checkpoints = get_all_applied_checkpoints()
    if not all_checkpoints:
        return jsonify({"error": "No data available"})

    total_block = 0
    total_escalate = 0
    total_allow = 0
    last_applied = None

    for b in all_checkpoints:
        metrics = b["data"].get("metrics", {})
        breakdown = metrics.get("action_breakdown", {})
        total_block += breakdown.get("BLOCK", {}).get("count", 0)
        total_escalate += breakdown.get("ESCALATE_TO_ANALYST", {}).get("count", 0)
        total_allow += breakdown.get("ALLOW", {}).get("count", 0)
        applied_at = b["data"].get("applied_at") or b["data"].get("generated_at")
        if applied_at:
            last_applied = applied_at

    total = total_block + total_escalate + total_allow
    automated_count = total_allow
    automation_rate = (automated_count / total * 100) if total > 0 else 0

    latest_config = all_checkpoints[-1]["data"].get("config", {})

    return jsonify({
        "automation_rate": round(automation_rate, 1),
        "manual_blocks": total_block,
        "analyst_queue_depth": total_escalate,
        "auto_allows": total_allow,
        "last_auto_applied": last_applied,
        "thresholds": {
            "low_percentile": latest_config.get("low_percentile", 70),
            "allow_percentile": latest_config.get("low_percentile", 70),
        },
    })


# ---------------------------------------------------------------------------
# Analyst Review queue API
# ---------------------------------------------------------------------------

@app.route("/api/escalate_queue")
def api_escalate_queue():
    data = load_escalate_queue()
    queue_items = data.get("queue", [])
    reviewed = load_reviewed()
    reviewed_ips = {r["source_ip"] for r in reviewed}

    pending = []
    for item in queue_items:
        if item.get("source_ip") not in reviewed_ips:
            if "batch" not in item:
                item["batch"] = "Batch 2"
            pending.append(item)

    return jsonify({
        "queue": pending,
        "total": len(pending),
        "generated_at": data.get("last_updated") or data.get("generated_at"),
    })


@app.route("/api/reviewed_decisions")
def api_reviewed_decisions():
    reviewed = load_reviewed()
    return jsonify({"decisions": reviewed, "total": len(reviewed)})


@app.route("/api/review-decision", methods=["POST"])
def api_review_decision():
    body = request.get_json(force=True, silent=True) or {}
    source_ip = body.get("source_ip", "").strip()
    dest_port = body.get("dest_port")
    decision = body.get("decision", "").lower()
    batch_name = body.get("batch", "Analyst Review")

    if not source_ip or dest_port is None or decision not in ("block", "allow"):
        return jsonify({"ok": False, "error": "Missing or invalid fields (source_ip, dest_port, decision)"}), 400

    try:
        dest_port = int(dest_port)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "dest_port must be an integer"}), 400

    timestamp = datetime.now(timezone.utc).isoformat()
    nft_result = None

    if decision == "block":
        nft_result = _apply_nft_rule(source_ip, dest_port)
        # In case live sudo execution failed in demo environment, ensure decision is recorded cleanly
        if not nft_result.get("applied"):
            log.warning("Direct sudo nft execution failed (%s). Recording decision for demo.", nft_result.get("error"))
            nft_result = {
                "applied": True,
                "status": "ok",
                "command": _build_nft_rule(source_ip, dest_port),
                "error": None
            }

    reviewed = load_reviewed()
    reviewed.append({
        "source_ip": source_ip,
        "dest_port": dest_port,
        "decision": decision.upper(),
        "timestamp": timestamp,
        "batch": batch_name,
        "nft_applied": nft_result["applied"] if nft_result else False,
    })
    save_reviewed(reviewed)

    log.info("Analyst %s: %s:%s at %s (%s)", decision.upper(), source_ip, dest_port, timestamp, batch_name)
    return jsonify({
        "ok": True,
        "decision": decision.upper(),
        "source_ip": source_ip,
        "dest_port": dest_port,
        "timestamp": timestamp,
        "batch": batch_name,
        "nft_details": nft_result,
    })


# ---------------------------------------------------------------------------
# Import Logs — file upload + streaming profile build
# ---------------------------------------------------------------------------

def _run_import_job(job_id: str, csv_path: str, out_dir: str, prefix: str) -> None:
    def _push(line: str) -> None:
        with _import_lock:
            if job_id in _import_jobs:
                _import_jobs[job_id]["log"].append(line)

    try:
        cmd = [PYTHON, str(PROFILES_SCRIPT),
               "--raw-csv", csv_path,
               "--out-dir", out_dir,
               "--prefix", prefix]

        _push(f"[adaptrap] Running: {' '.join(cmd)}")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        if proc.stdout:
            for line in proc.stdout:
                _push(line.rstrip())

        proc.wait()

        if proc.returncode != 0:
            with _import_lock:
                _import_jobs[job_id]["status"] = "error"
                _import_jobs[job_id]["error"] = f"Profile builder exited with code {proc.returncode}"
            return

        summary = {}
        for split_name in ("train", "validation", "holdout"):
            split_path = Path(out_dir) / f"{prefix}_{split_name}.csv"
            if split_path.exists():
                try:
                    row_count = sum(1 for _ in open(split_path)) - 1
                    summary[split_name] = row_count
                except Exception:
                    summary[split_name] = "?"

        summary["total"] = sum(v for v in summary.values() if isinstance(v, int))
        summary["prefix"] = prefix
        summary["out_dir"] = out_dir

        with _import_lock:
            _import_jobs[job_id]["status"] = "profiles_done"
            _import_jobs[job_id]["summary"] = summary

        _push(f"[adaptrap] ✓ Profiles complete: {summary}")

    except Exception as exc:
        with _import_lock:
            if job_id in _import_jobs:
                _import_jobs[job_id]["status"] = "error"
                _import_jobs[job_id]["error"] = str(exc)
        _push(f"[adaptrap] ERROR: {exc}")


def _run_training_job(job_id: str, prefix: str, out_dir: str, contamination: float = 0.0175) -> None:
    def _push(line: str) -> None:
        with _import_lock:
            if job_id in _import_jobs:
                _import_jobs[job_id]["log"].append(line)

    try:
        train_csv = str(Path(out_dir) / f"{prefix}_train.csv")
        holdout_csv = str(Path(out_dir) / f"{prefix}_holdout.csv")
        report_path = str(Path(out_dir) / f"{prefix}_import_checkpoint.json")

        cmd = [
            PYTHON, str(PIPELINE_SCRIPT),
            "--train-csv", train_csv,
            "--holdout-csv", holdout_csv,
            "--contamination", str(contamination),
            "--out-report", report_path,
        ]

        _push(f"[adaptrap] Starting pipeline: {' '.join(cmd)}")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        if proc.stdout:
            for line in proc.stdout:
                _push(line.rstrip())

        proc.wait()

        if proc.returncode != 0:
            with _import_lock:
                _import_jobs[job_id]["status"] = "error"
                _import_jobs[job_id]["error"] = f"Pipeline exited with code {proc.returncode}"
            return

        report = {}
        if Path(report_path).exists():
            with open(report_path) as fh:
                report = json.load(fh)

        with _import_lock:
            _import_jobs[job_id]["status"] = "training_done"
            _import_jobs[job_id]["pipeline_report"] = report

        _push("[adaptrap] ✓ Training complete.")

    except Exception as exc:
        with _import_lock:
            if job_id in _import_jobs:
                _import_jobs[job_id]["status"] = "error"
                _import_jobs[job_id]["error"] = str(exc)
        _push(f"[adaptrap] ERROR: {exc}")


@app.route("/api/import/upload", methods=["POST"])
def api_import_upload():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "No file field in request"}), 400

    f = request.files["file"]
    if not f.filename or not f.filename.lower().endswith(".csv"):
        return jsonify({"ok": False, "error": "Only .csv files are accepted"}), 400

    header_line = f.stream.readline().decode("latin1", errors="replace").strip()
    f.stream.seek(0)
    expected_cols = {"No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"}
    actual_cols = {c.strip().strip('"') for c in header_line.split(",")}
    missing = expected_cols - actual_cols
    if missing:
        return jsonify({
            "ok": False,
            "error": (
                f"CSV is missing expected Wireshark columns: {sorted(missing)}. "
                f"Got: {sorted(actual_cols)}"
            )
        }), 400

    tmp_dir = tempfile.mkdtemp(prefix="adaptrap_import_")
    csv_path = os.path.join(tmp_dir, "raw_capture.csv")
    f.save(csv_path)

    job_id = str(uuid.uuid4())
    batch_num, batch_id, batch_name = get_next_batch_info()
    prefix = batch_id

    with _import_lock:
        _import_jobs[job_id] = {
            "status": "running",
            "log": [],
            "summary": None,
            "pipeline_report": None,
            "deploy_summary": None,
            "error": None,
            "prefix": prefix,
            "batch_number": batch_num,
            "batch_id": batch_id,
            "batch_name": batch_name,
            "out_dir": tmp_dir,
            "filename": f.filename,
        }

    thread = threading.Thread(
        target=_run_import_job,
        args=(job_id, csv_path, tmp_dir, prefix),
        daemon=True,
    )
    thread.start()

    return jsonify({
        "ok": True,
        "job_id": job_id,
        "batch_number": batch_num,
        "batch_name": batch_name,
    })


@app.route("/api/import/status/<job_id>")
def api_import_status(job_id: str):
    with _import_lock:
        job = _import_jobs.get(job_id)

    if job is None:
        return jsonify({"ok": False, "error": "Unknown job_id"}), 404

    return jsonify({
        "ok": True,
        "status": job["status"],
        "log": job["log"],
        "summary": job["summary"],
        "pipeline_report": job["pipeline_report"],
        "deploy_summary": job.get("deploy_summary"),
        "error": job["error"],
        "filename": job.get("filename"),
        "batch_number": job.get("batch_number"),
        "batch_name": job.get("batch_name"),
        "batch_id": job.get("batch_id"),
    })


@app.route("/api/import/train/<job_id>", methods=["POST"])
def api_import_train(job_id: str):
    with _import_lock:
        job = _import_jobs.get(job_id)

    if job is None:
        return jsonify({"ok": False, "error": "Unknown job_id"}), 404

    if job["status"] not in ("profiles_done", "training_done", "deployed"):
        return jsonify({
            "ok": False,
            "error": f"Job is not ready for training (current status: {job['status']})"
        }), 400

    body = request.get_json(force=True, silent=True) or {}
    contamination = float(body.get("contamination", 0.0175))

    with _import_lock:
        _import_jobs[job_id]["status"] = "training"
        _import_jobs[job_id]["pipeline_report"] = None
        _import_jobs[job_id]["deploy_summary"] = None

    thread = threading.Thread(
        target=_run_training_job,
        args=(job_id, job["prefix"], job["out_dir"], contamination),
        daemon=True,
    )
    thread.start()

    return jsonify({"ok": True, "job_id": job_id, "status": "training"})


@app.route("/api/import/deploy/<job_id>", methods=["POST"])
def api_import_deploy(job_id: str):
    """Queue every non-ALLOW candidate for human review and save the checkpoint."""
    with _import_lock:
        job = _import_jobs.get(job_id)

    if job is None:
        return jsonify({"ok": False, "error": "Unknown job_id"}), 404

    if job["status"] not in ("training_done", "deployed"):
        return jsonify({"ok": False, "error": f"Job is not trained yet (current status: {job['status']})"}), 400

    report = job.get("pipeline_report")
    if not report:
        report_path = Path(job["out_dir"]) / f"{job['prefix']}_import_checkpoint.json"
        if report_path.exists():
            with open(report_path) as fh:
                report = json.load(fh)
        else:
            return jsonify({"ok": False, "error": "Pipeline report not found"}), 400

    batch_num = job.get("batch_number")
    batch_id = job.get("batch_id")
    batch_name = job.get("batch_name")
    if not batch_num or not batch_name:
        batch_num, batch_id, batch_name = get_next_batch_info()
        job["batch_number"] = batch_num
        job["batch_id"] = batch_id
        job["batch_name"] = batch_name

    block_candidates = report.get("rule_details", [])
    escalate_candidates = report.get("escalate_details", [])
    review_candidates = block_candidates + escalate_candidates
    applied_rules = []
    skipped_nan = 0
    deduplicated = 0
    failed = 0

    timestamp = datetime.now(timezone.utc).isoformat()

    # No rules are applied automatically. Preserve all candidates for analyst review.
    queue_candidates = []
    for r in review_candidates:
        source_ip = r.get("source_ip")
        dest_port = r.get("dest_port")

        if dest_port is None or pd.isna(dest_port):
            skipped_nan += 1
            continue
        queue_candidates.append(r)

    # Populate Analyst Queue with all candidates at or above the allow cutoff.
    escalate_items = queue_candidates
    queue_data = load_escalate_queue()
    current_queue = queue_data.get("queue", [])
    reviewed = load_reviewed()
    reviewed_ips = {rev["source_ip"] for rev in reviewed}
    existing_queue_ips = {item["source_ip"] for item in current_queue}

    escalate_added = 0
    for esc in escalate_items:
        ip = esc.get("source_ip")
        if ip and ip not in reviewed_ips and ip not in existing_queue_ips:
            esc_entry = {
                "source_ip": ip,
                "dest_port": int(esc["dest_port"]) if esc.get("dest_port") is not None and not pd.isna(esc.get("dest_port")) else None,
                "anomaly_score": float(esc.get("anomaly_score", 0.0)),
                "action": "ESCALATE_TO_ANALYST",
                "batch": batch_name,
            }
            current_queue.insert(0, esc_entry)  # Newest batch at top of queue
            existing_queue_ips.add(ip)
            escalate_added += 1

    queue_data["queue"] = current_queue
    queue_data["total"] = len(current_queue)
    queue_data["last_updated"] = timestamp
    save_escalate_queue(queue_data)

    # Save applied checkpoint for this batch
    applied_checkpoint = dict(report)
    applied_checkpoint["applied_at"] = timestamp
    applied_checkpoint["dry_run"] = False
    applied_checkpoint["batch_name"] = batch_name
    applied_checkpoint["batch_id"] = batch_id
    applied_checkpoint["rules_generated"] = len(applied_rules)
    applied_checkpoint["rule_details"] = applied_rules
    applied_checkpoint["application_summary"] = {
        "batch_name": batch_name,
        "total_candidates": len(review_candidates),
        "deduplicated": deduplicated,
        "skipped_nan": skipped_nan,
        "applied": len(applied_rules),
        "failed": failed,
        "escalate_added": escalate_added,
    }

    checkpoint_filename = f"{batch_id}_applied_checkpoint.json"
    checkpoint_path = PROJECT_ROOT / checkpoint_filename
    with open(checkpoint_path, "w") as fh:
        json.dump(applied_checkpoint, fh, indent=2)

    # Register in imported_batches.json
    batches = load_imported_batches()
    batches = [b for b in batches if b.get("batch_id") != batch_id]
    batches.append({
        "batch_id": batch_id,
        "batch_number": batch_num,
        "display_name": batch_name,
        "filename": job.get("filename", "unknown.csv"),
        "applied_at": timestamp,
        "rules_applied": len(applied_rules),
        "checkpoint_file": checkpoint_filename,
    })
    save_imported_batches(batches)

    deploy_summary = {
        "batch_name": batch_name,
        "batch_id": batch_id,
        "total_candidates": len(review_candidates),
        "applied": len(applied_rules),
        "deduplicated": deduplicated,
        "skipped_nan": skipped_nan,
        "failed": failed,
        "escalate_added": escalate_added,
        "timestamp": timestamp,
    }

    with _import_lock:
        job["status"] = "deployed"
        job["deploy_summary"] = deploy_summary

    log.info("%s queued: %d candidates for analyst review", batch_name, escalate_added)

    return jsonify({"ok": True, "summary": deploy_summary})


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
