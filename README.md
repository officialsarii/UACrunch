# UACrunch
🔍 UACrunch — A zero-dependency Linux triage tool to organize and parse UAC forensic artifacts.
# 🛡️ UAC Artifact Collector & Parser

**Author:** Sari  
**Version:** 1.0  
**Last Updated:** Automatically timestamped per output run.

---

## 🔍 Description

This tool is designed to assist digital forensic responders by collecting and optionally parsing key Linux system artifacts gathered by [UAC (Unix-like Artifact Collector)](https://github.com/tclahr/uac).

It automates triage organization by:
- Categorizing artifacts from multiple systems
- Copying and labeling files by system, user, and type
- Optionally converting logs into structured JSON
- Organizing outputs into `original/` and `parsed/` subfolders
- Naming output folders with timestamps to maintain audit history

---

## 📂 Artifact Categories

| Category              | Includes (Keywords matched)                              |
|-----------------------|----------------------------------------------------------|
| `auth_and_users`      | passwd, shadow, group, login, .bash_history              |
| `cron_persistence`    | crontab, systemd-timers, at                              |
| `ssh_config`          | sshd_config, authorized_keys, known_hosts                |
| `system_and_auth_logs`| syslog, auth.log, secure, messages, dmesg                |
| `temp_suspicious`     | files in /tmp, /var/tmp, /dev/shm, binwalk hits          |
| `web_server`          | nginx, apache, access.log, error.log, config files       |
| `hashes`              | Collected from `hash_executables/` in each UAC output    |
------------------------------------------------------------------------------------
---

## 🚀 Usage

```bash
python3 uac_artifact_collector.py --path /path/to/UAC_outputs
