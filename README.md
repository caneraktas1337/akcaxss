# 🦊 AkcaXSS

Automated XSS vulnerability scanner built for **Bug Bounty hunters**. Single Bash script — no frameworks, no dependencies hell.

[![GitHub](https://img.shields.io/badge/GitHub-caneraktas1337%2Fakcaxss-181717?logo=github)](https://github.com/caneraktas1337/akcaxss)
![Bash](https://img.shields.io/badge/Language-Bash-green?logo=gnubash&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey?logo=linux)

## What It Does

Collects URLs → cleans & deduplicates → extracts parameters → scans for XSS with Dalfox → scores findings → generates HTML report.

```
Phase 1  URL Discovery     (gospider, katana, waybackurls, gau, hakrawler, urlfinder)
Phase 2  Merge & Dedup     (sort -u)
Phase 3  URL Cleaning       (urless → uro)
Phase 4  Param Extraction   (grep + ParamSpider)
Phase 5  WAF Detection      (adaptive throttling)
Phase 6  XSS Scanning       (dalfox with live progress bar)
Phase 7  Scoring & Report   (0-100 risk score + HTML report)
Phase 8  Self Audit         (automated code audit)
```

## Quick Start

```bash
# Clone the repo
git clone https://github.com/caneraktas1337/akcaxss.git
cd akcaxss

# 1. Install all required tools
./akcaxss.sh --tool-install

# 2. Scan a target
./akcaxss.sh example.com
```

## Output

```
akcaxss/
  └── output/
      ├── urls_raw.txt      # All discovered URLs
      ├── urls_clean.txt    # Cleaned parameterized URLs
      ├── dalfox.json       # Raw dalfox results
      ├── score.json        # Risk-scored findings
      ├── report.html       # Visual HTML report
      └── audit.txt         # Automated self-audit
```

## Features

- **8 discovery tools** running in sequence for maximum coverage
- **WAF/rate-limit detection** with automatic concurrency & delay tuning
- **User-Agent rotation** across requests
- **XSS risk scoring** (0–100) based on context, payload, param type, WAF & CSP
- **Live progress bar** during Dalfox scan
- **Dark-themed HTML report** with severity color coding
- **Proxy support** via `AKCAXSS_PROXY` environment variable

## Required Tools

| Tool | Type | Install |
|------|------|---------|
| gospider | Go | `go install` |
| katana | Go | `go install` |
| waybackurls | Go | `go install` |
| gau | Go | `go install` |
| hakrawler | Go | `go install` |
| urlfinder | Go | `go install` |
| dalfox | Go | `go install` |
| urless | Python | `pip install` |
| uro | Python | `pip install` |
| ParamSpider | Python | `git clone` |

> All tools are installed automatically with `--tool-install`.

## Proxy Usage

```bash
export AKCAXSS_PROXY="http://127.0.0.1:8080"
./akcaxss.sh target.com
```

## Disclaimer

This tool is intended for **authorized security testing only**. The author is not responsible for any misuse. Always obtain proper authorization before scanning any target.

## Author

**Caner Aktaş**

## License

MIT

