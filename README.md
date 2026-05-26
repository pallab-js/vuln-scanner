# LANScanner

Offline-first network vulnerability scanner for macOS 14+. Discovers devices on your LAN, fingerprints their OS and services, maps vulnerabilities against built-in rule signatures, and produces structured reports.

## Features

- **Network discovery** — ARP-based host detection, CIDR subnet support, automatic subnet detection
- **Port scanning** — TCP connect + UDP probe scanning (swift-nio), banner grabbing, service version extraction
- **OS fingerprinting** — SSH/HTTP banner analysis + port signature–based OS inference
- **Vulnerability mapping** — 20+ offline rules (weak protocols, outdated versions, weak ciphers, EOL systems, dangerous ports) with regex pattern matching
- **Compliance filtering** — PCI-DSS, HIPAA, GDPR, SOC2, NIST framework tags on rules and findings
- **Custom rules** — In-app editor with regex tester, persisted alongside built-in rules
- **Network topology** — Force-directed graph visualization (SpriteKit), risk-colored nodes, interactive selection
- **Asset tagging** — Color-coded tags per device, sidebar filter
- **Scheduled scans** — In-app timer + launchd agent for background execution
- **REST API** — NIOHTTP1 server on configurable port (endpoints: `/api/v1/devices`, `/api/v1/scans`, `/api/v1/vulnerabilities`, `/api/v1/export`, `/api/v1/health`, `POST /api/v1/scans`)
- **Rules auto-update** — Fetch latest rules from a signed URL on scan start, stale-rules indicator
- **Webhook alerts** — Slack/Discord webhook dispatch on scan complete
- **Reports** — HTML (styled with executive summary, severity chart, compliance mapping), CSV, JSON export
- **CLI headless mode** — `--scan --subnet 10.0.0.0/24 --output report.html`
- **Scan history** — JSON persistence, trends over time (vuln count, risk score, top CVEs)

## Usage

```bash
# Launch GUI
swift run LANScanner

# Headless scan
swift run LANScanner --scan --subnet 192.168.1.0/24 --output report.html

# Scheduled scan (requires launchd agent)
swift run LANScanner --scheduled-scan
```

## Requirements

- macOS 14+ (Sonoma or later)
- Swift 6.0+ (Xcode 16+ or Command Line Tools)
- Network client + server entitlements (for raw socket access)

## Build

```bash
swift build --target App
swift test
```

## License

MIT
