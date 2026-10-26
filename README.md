# Wallet Security Monitoring

Phishing detection, address-risk continuous scanning, alert pipeline (extends walletrisk concept).

## Service Description

WalletGuard provides continuous wallet security monitoring across EVM chains. It detects:

- **Phishing interactions** — known malicious contracts and domains
- **Risky approvals** — unlimited ERC-20/NFT approvals to unknown spenders
- **High-risk transactions** — interactions with honeypots, rug pulls, mixer contracts
- **Anomalous activity** — unusual transaction volumes, new contract interactions
- **Address risk scoring** — 0-100 risk score with severity classification

Pricing: **$29–99/mo** entry; trading desks validated $400+/mo with SLA (Specialty tier)

## Installation

```bash
# Clone and install
git clone https://github.com/jonathanngiroux-star/walletguard
cd walletguard
pip install -r requirements.txt

# Or install directly
pip install git+https://github.com/jonathanngiroux-star/walletguard
```

## Configuration

Create `config.json`:

```json
{
  "rpc_endpoints": {
    "ethereum": "https://eth.llamarpc.com",
    "polygon": "https://polygon-rpc.com",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "optimism": "https://mainnet.optimism.io",
    "base": "https://mainnet.base.org",
    "gnosis": "https://rpc.gnosischain.com"
  },
  "scan_interval_minutes": 60,
  "alert_webhook": "https://your-webhook.example.com/alerts",
  "risk_thresholds": {
    "low": 30,
    "medium": 60,
    "high": 80
  }
}
```

## CLI Interface

```bash
# Add wallet to monitor
walletguard add 0x1234... ethereum --label "Main Wallet"

# List monitored wallets
walletguard list

# Scan a wallet now
walletguard scan 0x1234...

# Scan all wallets
walletguard scan-all

# Show wallet status
walletguard status [address]

# Show alerts
walletguard alerts [address] --limit 50

# Show scan history
walletguard history 0x1234... --limit 10

# Run as daemon (continuous scanning)
walletguard daemon --interval 60
```

## Risk Scoring

| Score Range | Level | Description |
|-------------|-------|-------------|
| 0-29 | LOW | No significant findings |
| 30-59 | LOW-MEDIUM | Minor findings, monitor |
| 60-79 | MEDIUM | Notable risks, review approvals |
| 80-100 | HIGH | Critical findings, immediate action needed |

## Detection Rules

- Known phishing domains (10+ built-in)
- Known malicious contracts (honeypots, rug pulls)
- Unlimited ERC-20 approvals to unverified contracts
- High-frequency trading patterns (potential bot compromise)
- Interactions with mixer/tornado contracts
- New contract deployments from wallet

## API Interface (Daemon Mode)

```
GET  /api/wallets           - List all wallets
GET  /api/wallets/:address  - Get wallet details
POST /api/wallets           - Add wallet
DELETE /api/wallets/:address - Remove wallet
POST /api/wallets/:address/scan - Trigger scan
GET  /api/wallets/:address/alerts - Get alerts
GET  /api/wallets/:address/history - Get scan history
GET  /api/metrics           - Prometheus metrics
```

## Pricing

| Tier | Price | Includes |
|------|-------|----------|
| Personal | $29/mo | Up to 10 addresses, hourly scans, email alerts |
| Team | $99/mo | Up to 100 addresses, 15-min scans, Slack/Discord alerts |
| Trading Desk | $400+/mo | Unlimited addresses, real-time, SLA with credits, on-call |

## Hosted Version

Managed monitoring at **katsironni.com/walletguard** — includes SLA, managed infrastructure, 24/7 security team.

## License

MIT — see [LICENSE](LICENSE)