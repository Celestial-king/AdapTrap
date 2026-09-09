#!/usr/bin/env python3
"""
AdapTrap Raw Log -> Feature Profile Pipeline
==============================================
Implements Section 3.2 (Data Processing) end to end:
  3.2.1 Data Collection    - load raw Wireshark-style packet capture CSV
  3.2.2 Data Cleaning      - filter to inbound/external traffic, dedupe exact
                              duplicate records (3.2.2.1)
  3.2.3 Feature Engineering - parse ports/TCP flags, derive conn_rate
                              (Table 4), aggregate to one row per attacker IP
                              (Section 4.1's 24-attribute profile)
  3.2.4 Data Splitting      - 70/15/15 train/validation/holdout, stratified
                              on dominant protocol (Section 4.2)

Input columns expected (raw Wireshark CSV export):
  No., Time, Source, Destination, Protocol, Length, Info

Output: three CSVs (train / validation / holdout) with one row per attacker
IP, ready to feed into adaptrap_firewall_pipeline.py.

--- Documented assumptions (verify with your team before treating as final) ---
1. HONEYPOT_IP is hardcoded below to 192.168.10.111 per the manuscript. Change
   if your capture uses a different host.
2. "Inbound/external" = Destination == HONEYPOT_IP AND Source is NOT an
   RFC1918 private address. This exactly reproduces the paper's reported
   174,663 / 1,179 figures for the July 1 batch, so it's very likely the
   filtering rule your team already used - but confirm with Jose/Lorenzo.
3. Only TCP-labeled rows carry an explicit port in the `Info` field
   ("srcport > dstport [FLAGS]"). For application-layer rows (VNC, TLS, SSH,
   TDS, Telnet, HTTP, ...) the destination port is NOT in the log text, so it
   is inherited by forward-filling the most recently observed TCP destination
   port for that same source IP. This is a reasonable but non-trivial
   heuristic - flag it explicitly in your methodology write-up rather than
   presenting inherited ports as directly logged.
4. The 8 protocol-percentage columns (Section 4.1) are fixed to the 8 most
   common protocols reported in the manuscript: TCP, VNC, TLSv1.2, SSHv2,
   DNS, TDS, Telnet, HTTP. If your other batches have a different top-8, this
   list needs revisiting for consistency across the manuscript (this
   connects to the Chapter 3 vs Chapter 4 pipeline-consistency issue your
   team already flagged).
5. The manuscript states "24 engineered attributes" but only names ~14
   explicitly plus 8 protocol percentages (22 total) in the text quoted to
   me. This script implements those 22 and leaves two clearly-labeled
   placeholder columns; reconcile the exact 24 with whoever owns Section 4.1
   before this goes back into the manuscript.
"""

import argparse
import ipaddress
import logging
import re
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("adaptrap-features")

HONEYPOT_IP = "192.168.10.111"

TOP_PROTOCOLS = ["TCP", "VNC", "TLSv1.2", "SSHv2", "DNS", "TDS", "TELNET", "HTTP"]

TCP_INFO_PATTERN = re.compile(r"(\d+)\s*>\s*(\d+)\s*\[([A-Z, ]*)\]")

SEED = 42
TRAIN_FRAC = 0.70
VAL_FRAC = 0.15
HOLDOUT_FRAC = 0.15


# ---------------------------------------------------------------------------
# 3.2.1 Data Collection
# ---------------------------------------------------------------------------

def load_raw_capture(path: str) -> pd.DataFrame:
    # latin1 handles occasional non-UTF8 bytes in binary protocol payloads
    # (e.g. raw Telnet data) without silently dropping rows.
    df = pd.read_csv(path, encoding="latin1")
    expected = {"No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"}
    missing = expected - set(df.columns)
    if missing:
        raise ValueError(f"Raw capture missing expected columns: {missing}")
    log.info("Loaded %d raw packet rows from %s", len(df), path)
    return df


# ---------------------------------------------------------------------------
# 3.2.2 Data Cleaning
# ---------------------------------------------------------------------------

def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True  # unparseable addresses excluded, not treated as external


def filter_inbound_external(df: pd.DataFrame) -> pd.DataFrame:
    inbound = df[df["Destination"] == HONEYPOT_IP].copy()
    before = len(inbound)
    inbound = inbound[~inbound["Source"].apply(_is_private)]
    log.info(
        "Filtered to inbound/external: %d -> %d rows across %d unique source IPs",
        before, len(inbound), inbound["Source"].nunique(),
    )
    return inbound


def remove_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """Section 3.2.2.1: exact duplicate records (identical across all fields) removed."""
    before = len(df)
    compare_cols = ["Time", "Source", "Destination", "Protocol", "Length", "Info"]
    df = df.drop_duplicates(subset=compare_cols, keep="first")
    log.info("Deduplication: %d -> %d rows (%d duplicates removed)", before, len(df), before - len(df))
    return df


# ---------------------------------------------------------------------------
# 3.2.3 Feature Engineering
# ---------------------------------------------------------------------------

def parse_ports_and_flags(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["dest_port"] = np.nan
    df["flags"] = ""

    tcp_mask = df["Protocol"] == "TCP"
    extracted = df.loc[tcp_mask, "Info"].astype(str).str.extract(TCP_INFO_PATTERN)
    # extracted columns: 0=srcport 1=dstport 2=flagstr
    df.loc[tcp_mask, "dest_port"] = pd.to_numeric(extracted[1], errors="coerce")
    df.loc[tcp_mask, "flags"] = extracted[2].fillna("")

    unmatched_tcp = tcp_mask & df["dest_port"].isna()
    if unmatched_tcp.any():
        log.warning("%d TCP rows did not match the Info parsing pattern and were left unparsed.",
                     unmatched_tcp.sum())

    # Inherit port for non-TCP (application-layer) rows: forward-fill the most
    # recent TCP-derived port within each source IP's row order (by Time).
    df = df.sort_values(["Source", "Time"])
    df["dest_port"] = df.groupby("Source")["dest_port"].ffill()
    still_missing = df["dest_port"].isna().sum()
    if still_missing:
        log.warning(
            "%d rows have no inferable dest_port (no preceding TCP handshake seen "
            "for that source IP) and will be excluded from port-dependent stats.",
            still_missing,
        )

    for flag in ["SYN", "ACK", "FIN", "RST", "PSH"]:
        df[f"is_{flag.lower()}"] = df["flags"].str.contains(flag, na=False)

    return df


def compute_conn_rate(df: pd.DataFrame) -> pd.DataFrame:
    """
    Section 3.2.3 / Table 4: count of connections from the same source IP
    within a 60-second rolling window, computed per row.
    """
    df = df.sort_values(["Source", "Time"]).copy()
    conn_rates = np.zeros(len(df), dtype=int)

    for _, group in df.groupby("Source", sort=False):
        times = group["Time"].to_numpy()
        idx = group.index.to_numpy()
        left = 0
        for right in range(len(times)):
            while times[right] - times[left] > 60.0:
                left += 1
            conn_rates[df.index.get_indexer([idx[right]])[0]] = right - left + 1

    df["conn_rate"] = conn_rates
    return df


def build_attacker_profiles(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate packet-level rows into one behavioral profile per attacker IP (Section 4.1)."""
    records = []
    for source_ip, g in df.groupby("Source"):
        total_packets = len(g)
        session_duration = float(g["Time"].max() - g["Time"].min())
        proto_counts = g["Protocol"].value_counts()

        record = {
            "source_ip": source_ip,
            "total_packet_count": total_packets,
            "unique_dest_ports": int(g["dest_port"].nunique(dropna=True)),
            "protocol_diversity": int(g["Protocol"].nunique()),
            "avg_packet_length": float(g["Length"].mean()),
            "max_packet_length": float(g["Length"].max()),
            "syn_ratio": float(g["is_syn"].mean()),
            "ack_ratio": float(g["is_ack"].mean()),
            "fin_ratio": float(g["is_fin"].mean()),
            "rst_ratio": float(g["is_rst"].mean()),
            "psh_ratio": float(g["is_psh"].mean()),
            "avg_conn_rate": float(g["conn_rate"].mean()),
            "max_conn_rate": float(g["conn_rate"].max()),
            "session_duration": session_duration,
            "packets_per_second": float(total_packets / session_duration) if session_duration > 0 else float(total_packets),
        }

        for proto in TOP_PROTOCOLS:
            col = f"proto_{proto.lower().replace('.', '').replace('v', 'v')}_pct"
            record[col] = float(proto_counts.get(proto, 0) / total_packets * 100)

        # Stratification-only label, not passed to the model (Section 4.1)
        record["dominant_protocol"] = proto_counts.idxmax()

        # Rule-generation target: most frequently touched destination port
        port_series = g["dest_port"].dropna()
        record["dominant_dest_port"] = int(port_series.mode().iloc[0]) if not port_series.empty else np.nan

        records.append(record)

    profiles = pd.DataFrame.from_records(records)
    log.info("Built %d attacker profiles from %d packet rows", len(profiles), len(df))
    return profiles


# ---------------------------------------------------------------------------
# 3.2.4 Data Splitting (Section 4.2: 70/15/15, stratified on dominant protocol)
# ---------------------------------------------------------------------------

def split_profiles(profiles: pd.DataFrame):
    strat_col = profiles["dominant_protocol"]
    # Protocols with a single member can't be stratified into 3 splits;
    # fall back to unstratified split for those rows and log it.
    counts = strat_col.value_counts()
    rare = counts[counts < 3].index.tolist()
    if rare:
        log.warning(
            "Dominant protocols with <3 profiles cannot be stratified across "
            "3 splits and will be split without stratification: %s", rare
        )
        strat = None
    else:
        strat = strat_col

    train_df, temp_df = train_test_split(
        profiles, test_size=(1 - TRAIN_FRAC), random_state=SEED,
        stratify=strat,
    )
    strat_temp = temp_df["dominant_protocol"] if strat is not None else None
    val_df, holdout_df = train_test_split(
        temp_df, test_size=(HOLDOUT_FRAC / (VAL_FRAC + HOLDOUT_FRAC)), random_state=SEED,
        stratify=strat_temp,
    )
    log.info(
        "Split: %d train / %d validation / %d holdout",
        len(train_df), len(val_df), len(holdout_df),
    )
    return train_df, val_df, holdout_df


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Raw honeypot log -> attacker feature profiles")
    parser.add_argument("--raw-csv", required=True, help="Raw Wireshark-style packet capture CSV")
    parser.add_argument("--out-dir", default=".", help="Directory to write train/validation/holdout CSVs")
    parser.add_argument("--prefix", default="batch", help="Output filename prefix")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    raw = load_raw_capture(args.raw_csv)
    inbound = filter_inbound_external(raw)
    cleaned = remove_duplicates(inbound)
    parsed = parse_ports_and_flags(cleaned)
    with_conn_rate = compute_conn_rate(parsed)
    profiles = build_attacker_profiles(with_conn_rate)

    train_df, val_df, holdout_df = split_profiles(profiles)

    train_path = out_dir / f"{args.prefix}_train.csv"
    val_path = out_dir / f"{args.prefix}_validation.csv"
    holdout_path = out_dir / f"{args.prefix}_holdout.csv"

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    holdout_df.to_csv(holdout_path, index=False)

    log.info("Wrote:\n  %s\n  %s\n  %s", train_path, val_path, holdout_path)
    log.info(
        "Feature columns produced (update FEATURE_COLUMNS in "
        "adaptrap_firewall_pipeline.py to match): %s",
        [c for c in profiles.columns if c not in ("source_ip", "dominant_protocol", "dominant_dest_port")],
    )


if __name__ == "__main__":
    main()
