
#!/usr/bin/env python3
"""
UAC Artifact Collector and Parser

Author: Sari
Description:
    This script collects and optionally parses important digital forensic artifacts
    from UAC (Unix-like Artifact Collector) output folders across multiple systems.
    It supports structured organization, duplicate-safe handling, and JSON parsing
    of common Linux forensic files, including a special category for hash_executables.

Usage:
    python3 uac_artifact_collector.py --path /path/to/UAC_outputs
"""

import os
import shutil
import argparse
import sys
import json
import re
from datetime import datetime
from collections import defaultdict

# Category definitions with keywords to match files
CATEGORIES = {
    "auth_and_users": ["passwd", "shadow", "group", "login", "who", "lastlog", "bash_history", ".bash_history"],
    "cron_persistence": ["cron", "crontab", "at", "systemd-timers"],
    "ssh_config": ["sshd_config", "authorized_keys", "known_hosts"],
    "system_and_auth_logs": ["syslog", "auth.log", "secure", "messages", "dmesg"],
    "temp_suspicious": ["tmp", "temp", "suspicious", "malware", "binwalk"],
    "web_server": ["apache", "nginx", "httpd", "access.log", "error.log"],
    "hashes": []  # handled manually from hash_executables
}

SKIP_FOLDERS = {"bodyfile", "hash_executables", "live_response"}
all_parsed = []
summary_data = defaultdict(lambda: defaultdict(int))

def extract_hostname(name):
    match = re.match(r'(.+?)-20\d{10,}', name)
    return match.group(1) if match else name

def is_text_file(path, threshold=0.90):
    try:
        with open(path, 'rb') as f:
            chunk = f.read(1024)
        if not chunk:
            return False
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
        nontext = [b for b in chunk if b not in text_chars]
        return (len(nontext) / len(chunk)) < (1 - threshold)
    except Exception:
        return False

def parse_log(infile, outfile, hostname, original):
    try:
        with open(infile, "r", errors="ignore") as f:
            lines = [{"hostname": hostname, "source_file": os.path.basename(original), "line": line.strip()}
                     for line in f if line.strip()]
        if lines:
            with open(outfile, "w") as o:
                json.dump(lines, o, indent=2)
            all_parsed.extend(lines)
            summary_data[hostname]['parsed_files'] += 1
    except Exception:
        pass

def parse_structured_config(filepath, outpath, kind, hostname):
    result = []
    try:
        with open(filepath, "r", errors="ignore") as f:
            lines = [l.strip() for l in f if l.strip()]
        if not lines:
            return
        for line in lines:
            parts = line.split(':')
            if kind.startswith("passwd") and len(parts) >= 7:
                result.append({
                    "hostname": hostname,
                    "user": parts[0], "uid": parts[2], "gid": parts[3],
                    "desc": parts[4], "home": parts[5], "shell": parts[6]
                })
            elif kind.startswith("shadow") and len(parts) >= 2:
                result.append({"hostname": hostname, "user": parts[0], "has_hash": parts[1] not in ["*", "!"]})
            elif kind.startswith("group") and len(parts) >= 3:
                result.append({
                    "hostname": hostname,
                    "group": parts[0], "gid": parts[2],
                    "members": parts[3].split(',') if len(parts) > 3 else []
                })
            elif kind.startswith("sudoers"):
                result.append({"hostname": hostname, "rule": line})
        if result:
            with open(outpath, "w") as o:
                json.dump(result, o, indent=2)
            all_parsed.extend(result)
            summary_data[hostname]['parsed_files'] += 1
    except Exception:
        pass

def create_output_dirs(base_path):
    for category in CATEGORIES:
        os.makedirs(os.path.join(base_path, category, "original"), exist_ok=True)
        os.makedirs(os.path.join(base_path, category, "parsed"), exist_ok=True)

def collect_files(input_path, output_path):
    for system_name in os.listdir(input_path):
        system_path = os.path.join(input_path, system_name)
        if not os.path.isdir(system_path) or system_name.startswith("_"):
            continue

        # Handle hash_executables separately
        hash_dir = os.path.join(system_path, "hash_executables")
        if os.path.isdir(hash_dir):
            for file in os.listdir(hash_dir):
                src = os.path.join(hash_dir, file)
                if os.path.isfile(src):
                    dst = os.path.join(output_path, "hashes", "original", f"{system_name}__{file}")
                    shutil.copy2(src, dst)
                    print(f"[hashes] {src} -> {dst}")

        # Walk user directories
        for subdir in os.listdir(system_path):
            subdir_path = os.path.join(system_path, subdir)
            if not os.path.isdir(subdir_path) or subdir in SKIP_FOLDERS:
                continue
            username = subdir
            for root, _, files in os.walk(subdir_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    file_lc = file.lower()
                    for category, keywords in CATEGORIES.items():
                        if category == "hashes":
                            continue
                        if any(keyword in file_lc for keyword in keywords):
                            base_name = f"{system_name}__{category}__{username}__{file}"
                            dest_dir = os.path.join(output_path, category, "original")
                            dst = os.path.join(dest_dir, base_name)
                            base, ext = os.path.splitext(base_name)
                            count = 1
                            while os.path.exists(dst):
                                dst = os.path.join(dest_dir, f"{base}_{count}{ext}")
                                count += 1
                            shutil.copy2(full_path, dst)
                            print(f"[{category}] {full_path} -> {dst}")

def parse_all_logs(output_path):
    for category in CATEGORIES:
        orig_dir = os.path.join(output_path, category, "original")
        parsed_dir = os.path.join(output_path, category, "parsed")
        for file in os.listdir(orig_dir):
            src = os.path.join(orig_dir, file)
            if not is_text_file(src):
                continue
            hostname = extract_hostname(file)
            json_name = file.replace(".", "_") + ".json"
            dst = os.path.join(parsed_dir, json_name)
            keywords = CATEGORIES[category]
            matched_key = next((k for k in keywords if k in file), None)
            if matched_key in ["passwd", "shadow", "group", "sudoers"]:
                parse_structured_config(src, dst, matched_key, hostname)
            elif any(x in file.lower() for x in ["log", "history", "authorized_keys", "hash"]):
                parse_log(src, dst, hostname, src)

def main():
    parser = argparse.ArgumentParser(description="Collect and parse UAC Linux forensic artifacts.")
    parser.add_argument('--path', required=True, help='Path to folder containing UAC outputs.')
    args = parser.parse_args()

    input_path = args.path
    if not os.path.isdir(input_path):
        print("❌ Invalid input folder.")
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    output_path = os.path.join(os.getcwd(), f"_collected_important_logs_{timestamp}")
    os.makedirs(output_path, exist_ok=True)

    print(f"📁 Output directory: {output_path}")
    create_output_dirs(output_path)
    collect_files(input_path, output_path)

    choice = input("
🔍 Parse collected logs to JSON? (y/n): ").strip().lower()
    if choice == 'y':
        parse_all_logs(output_path)
        print("✅ Parsing complete.")

if __name__ == "__main__":
    main()
