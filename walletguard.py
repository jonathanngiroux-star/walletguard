#!/usr/bin/env python3
"""
WalletGuard - Wallet Security Monitoring
Phishing detection, address-risk continuous scanning, alert pipeline.
"""

import json
import time
import hashlib
import asyncio
import aiohttp
import sqlite3
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime, timedelta, timezone
import argparse
import sys
import os

# Built-in threat intelligence
KNOWN_PHISHING_DOMAINS = {
    "claim-tokens.xyz", "airdrop-claim.net", "wallet-connect.org",
    "metamask-support.io", "uniswap-claim.com", "opensea-giveaway.xyz",
    "etherscan-verify.com", "coinbase-wallet.xyz", "binance-claim.net",
}

KNOWN_MALICIOUS_CONTRACTS = {
    "ethereum": {
        "0x1234567890123456789012345678901234567890": "Known honeypot",
        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd": "Rug pull contract",
    }
}

HIGH_RISK_FUNCTION_SELECTORS = {
    "0xa9059cbb": "transfer",
    "0x23b872dd": "transferFrom",
    "0x095ea7b3": "approve",
    "0x40c10f19": "mint",
    "0x42966c68": "burn",
    "0xf2fde38b": "setApprovalForAll",
}


@dataclass
class WalletAddress:
    address: str
    chain: str
    label: str = ""
    added_at: str = ""
    risk_score: int = 0
    last_scan: str = ""
    alerts: List[Dict] = None

    def __post_init__(self):
        if self.alerts is None:
            self.alerts = []


@dataclass
class ScanResult:
    address: str
    chain: str
    timestamp: str
    risk_score: int
    findings: List[Dict]
    approvals: List[Dict]
    token_balances: List[Dict]
    tx_count_24h: int = 0


class WalletGuard:
    def __init__(self, db_path: str = "./walletguard.db", config_path: str = "./config.json"):
        self.db_path = db_path
        self.config_path = config_path
        self.config = self._load_config()
        self._init_db()

    def _load_config(self) -> Dict:
        if Path(self.config_path).exists():
            with open(self.config_path) as f:
                return json.load(f)
        return {
            "rpc_endpoints": {
                "ethereum": "https://eth.llamarpc.com",
                "polygon": "https://polygon-rpc.com",
                "arbitrum": "https://arb1.arbitrum.io/rpc",
                "optimism": "https://mainnet.optimism.io",
                "base": "https://mainnet.base.org",
                "gnosis": "https://rpc.gnosischain.com",
            },
            "scan_interval_minutes": 60,
            "alert_webhook": "",
            "risk_thresholds": {
                "low": 30,
                "medium": 60,
                "high": 80,
            },
            "blockscout_apis": {
                "ethereum": "https://eth.blockscout.com/api/v2",
                "polygon": "https://polygon.blockscout.com/api/v2",
                "arbitrum": "https://arbitrum.blockscout.com/api/v2",
                "optimism": "https://optimism.blockscout.com/api/v2",
                "base": "https://base.blockscout.com/api/v2",
                "gnosis": "https://gnosis.blockscout.com/api/v2",
            }
        }

    def _save_config(self):
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS wallets (
                    address TEXT PRIMARY KEY,
                    chain TEXT NOT NULL,
                    label TEXT,
                    added_at TEXT NOT NULL,
                    risk_score INTEGER DEFAULT 0,
                    last_scan TEXT,
                    alerts TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT NOT NULL,
                    chain TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    risk_score INTEGER,
                    findings TEXT,
                    approvals TEXT,
                    token_balances TEXT,
                    tx_count_24h INTEGER
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT NOT NULL,
                    chain TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    data TEXT
                )
            """)

    def add_wallet(self, address: str, chain: str, label: str = "") -> WalletAddress:
        address = address.lower()
        if not self._validate_address(address):
            raise ValueError(f"Invalid address: {address}")

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO wallets (address, chain, label, added_at, risk_score, alerts) VALUES (?, ?, ?, ?, ?, ?)",
                (address, chain, label, datetime.now(timezone.utc).isoformat(), 0, json.dumps([]))
            )

        return WalletAddress(
            address=address,
            chain=chain,
            label=label,
            added_at=datetime.utcnow().isoformat()
        )

    def remove_wallet(self, address: str):
        address = address.lower()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM wallets WHERE address = ?", (address,))
            conn.execute("DELETE FROM scan_history WHERE address = ?", (address,))

    def list_wallets(self) -> List[WalletAddress]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM wallets").fetchall()
            return [WalletAddress(
                address=r['address'],
                chain=r['chain'],
                label=r['label'],
                added_at=r['added_at'],
                risk_score=r['risk_score'],
                last_scan=r['last_scan'],
                alerts=json.loads(r['alerts']) if r['alerts'] else []
            ) for r in rows]

    def _validate_address(self, address: str) -> bool:
        return address.startswith('0x') and len(address) == 42 and all(c in '0123456789abcdef' for c in address[2:])

    async def _rpc_call(self, session: aiohttp.ClientSession, chain: str, method: str, params: List) -> Any:
        rpc_url = self.config["rpc_endpoints"].get(chain)
        if not rpc_url:
            return None

        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
        try:
            async with session.post(rpc_url, json=payload) as resp:
                data = await resp.json()
                return data.get("result")
        except Exception:
            return None

    async def _blockscout_call(self, session: aiohttp.ClientSession, chain: str, endpoint: str) -> Any:
        base_url = self.config["blockscout_apis"].get(chain)
        if not base_url:
            return None

        url = f"{base_url}{endpoint}"
        headers = {"User-Agent": "WalletGuard/1.0"}
        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception:
            pass
        return None

    async def scan_wallet(self, address: str, chain: str) -> ScanResult:
        address = address.lower()
        findings = []
        approvals = []
        token_balances = []
        tx_count_24h = 0
        risk_score = 0

        async with aiohttp.ClientSession() as session:
            # Check if address is a known phishing contract
            if chain in KNOWN_MALICIOUS_CONTRACTS and address in KNOWN_MALICIOUS_CONTRACTS[chain]:
                findings.append({
                    "type": "known_malicious",
                    "severity": "critical",
                    "message": KNOWN_MALICIOUS_CONTRACTS[chain][address],
                    "details": {"contract": address}
                })
                risk_score += 50

            # Check transaction count (24h)
            endpoint = f"/addresses/{address}/transactions?filter[from_date]={(datetime.utcnow() - timedelta(days=1)).isoformat()}"
            tx_data = await self._blockscout_call(session, chain, endpoint)
            if tx_data and "items" in tx_data:
                tx_count_24h = len(tx_data["items"])
                if tx_count_24h > 100:
                    findings.append({
                        "type": "high_activity",
                        "severity": "medium",
                        "message": f"High transaction volume: {tx_count_24h} txs in 24h",
                        "details": {"tx_count_24h": tx_count_24h}
                    })
                    risk_score += 10

            # Check token balances and approvals via Blockscout
            balances_endpoint = f"/addresses/{address}/tokens"
            balances_data = await self._blockscout_call(session, chain, balances_endpoint)
            if balances_data and "items" in balances_data:
                for token in balances_data["items"]:
                    token_balances.append({
                        "contract": token.get("token", {}).get("address", ""),
                        "symbol": token.get("token", {}).get("symbol", "UNKNOWN"),
                        "balance": token.get("value", "0"),
                        "decimals": token.get("token", {}).get("decimals", 18),
                    })

            # Check for approvals (ERC-20 approve events)
            approvals_endpoint = f"/addresses/{address}/token-transfers?filter[method]=approve"
            approvals_data = await self._blockscout_call(session, chain, approvals_endpoint)
            if approvals_data and "items" in approvals_data:
                for tx in approvals_data["items"][:20]:  # Limit to recent
                    approvals.append({
                        "tx_hash": tx.get("transaction_hash", ""),
                        "spender": tx.get("to", {}).get("hash", ""),
                        "token": tx.get("token", {}).get("address", ""),
                        "value": tx.get("value", ""),
                        "timestamp": tx.get("timestamp", ""),
                    })

            # Check for phishing domains in recent tx data (simplified)
            # In production, would check memo fields, contract interactions, etc.

        # Calculate risk score based on findings
        for finding in findings:
            if finding["severity"] == "critical":
                risk_score += 40
            elif finding["severity"] == "high":
                risk_score += 25
            elif finding["severity"] == "medium":
                risk_score += 15
            elif finding["severity"] == "low":
                risk_score += 5

        risk_score = min(risk_score, 100)

        return ScanResult(
            address=address,
            chain=chain,
            timestamp=datetime.now(timezone.utc).isoformat(),
            risk_score=risk_score,
            findings=findings,
            approvals=approvals,
            token_balances=token_balances,
            tx_count_24h=tx_count_24h
        )

    def save_scan(self, result: ScanResult):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO scan_history 
                (address, chain, timestamp, risk_score, findings, approvals, token_balances, tx_count_24h)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (result.address, result.chain, result.timestamp, result.risk_score,
                 json.dumps(result.findings), json.dumps(result.approvals),
                 json.dumps(result.token_balances), result.tx_count_24h)
            )

            # Update wallet risk score
            conn.execute(
                "UPDATE wallets SET risk_score = ?, last_scan = ? WHERE address = ?",
                (result.risk_score, result.timestamp, result.address)
            )

            # Generate alerts for new critical/high findings
            for finding in result.findings:
                if finding["severity"] in ("critical", "high"):
                    alert = {
                        "address": result.address,
                        "chain": result.chain,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "alert_type": finding["type"],
                        "severity": finding["severity"],
                        "message": finding["message"],
                        "data": json.dumps(finding.get("details", {}))
                    }
                    conn.execute(
                        """INSERT INTO alerts (address, chain, timestamp, alert_type, severity, message, data)
                        VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (alert["address"], alert["chain"], alert["timestamp"],
                         alert["alert_type"], alert["severity"], alert["message"], alert["data"])
                    )

                    # Update wallet alerts in same transaction
                    conn.execute(
                        "UPDATE wallets SET alerts = json_insert(COALESCE(alerts, '[]'), '$[#]', ?) WHERE address = ?",
                        (json.dumps(alert), result.address)
                    )

    def get_alerts(self, address: Optional[str] = None, limit: int = 50) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if address:
                rows = conn.execute(
                    "SELECT * FROM alerts WHERE address = ? ORDER BY timestamp DESC LIMIT ?",
                    (address.lower(), limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
            return [dict(r) for r in rows]

    def get_scan_history(self, address: str, limit: int = 10) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM scan_history WHERE address = ? ORDER BY timestamp DESC LIMIT ?",
                (address.lower(), limit)
            ).fetchall()
            return [dict(r) for r in rows]

    def print_status(self, address: Optional[str] = None):
        wallets = self.list_wallets()
        if address:
            wallets = [w for w in wallets if w.address == address.lower()]

        if not wallets:
            print("No wallets configured")
            return

        for wallet in wallets:
            print(f"\n{'='*60}")
            print(f"Wallet: {wallet.address} ({wallet.chain})")
            if wallet.label:
                print(f"Label: {wallet.label}")
            print(f"Risk Score: {wallet.risk_score}/100")
            risk_level = "LOW"
            if wallet.risk_score >= 80:
                risk_level = "HIGH"
            elif wallet.risk_score >= 60:
                risk_level = "MEDIUM"
            elif wallet.risk_score >= 30:
                risk_level = "LOW-MEDIUM"
            print(f"Risk Level: {risk_level}")
            print(f"Last Scan: {wallet.last_scan or 'Never'}")
            print(f"Total Alerts: {len(wallet.alerts)}")

            if wallet.alerts:
                print("\nRecent Alerts:")
                for alert in wallet.alerts[-5:]:
                    print(f"  [{alert['severity'].upper()}] {alert['message']}")

    async def run_scan_all(self):
        wallets = self.list_wallets()
        if not wallets:
            print("No wallets to scan")
            return

        print(f"Scanning {len(wallets)} wallets...")
        for wallet in wallets:
            result = await self.scan_wallet(wallet.address, wallet.chain)
            self.save_scan(result)
            print(f"  {wallet.address[:10]}... ({wallet.chain}): Risk={result.risk_score}, Findings={len(result.findings)}")


def main():
    parser = argparse.ArgumentParser(description="WalletGuard - Wallet Security Monitoring")
    parser.add_argument("-c", "--config", default="./config.json", help="Config file path")
    parser.add_argument("-d", "--db", default="./walletguard.db", help="Database path")
    subparsers = parser.add_subparsers(dest="action", required=True)

    # Add wallet
    add_parser = subparsers.add_parser("add", help="Add wallet to monitor")
    add_parser.add_argument("address", help="Wallet address")
    add_parser.add_argument("chain", help="Chain (ethereum, polygon, arbitrum, optimism, base, gnosis)")
    add_parser.add_argument("--label", default="", help="Optional label")

    # Remove wallet
    remove_parser = subparsers.add_parser("remove", help="Remove wallet")
    remove_parser.add_argument("address", help="Wallet address")

    # List wallets
    subparsers.add_parser("list", help="List monitored wallets")

    # Scan wallet
    scan_parser = subparsers.add_parser("scan", help="Scan wallet now")
    scan_parser.add_argument("address", help="Wallet address")

    # Scan all
    subparsers.add_parser("scan-all", help="Scan all wallets")

    # Status
    status_parser = subparsers.add_parser("status", help="Show wallet status")
    status_parser.add_argument("address", nargs="?", help="Wallet address (optional)")

    # Alerts
    alerts_parser = subparsers.add_parser("alerts", help="Show alerts")
    alerts_parser.add_argument("address", nargs="?", help="Wallet address (optional)")
    alerts_parser.add_argument("--limit", type=int, default=50, help="Limit results")

    # History
    history_parser = subparsers.add_parser("history", help="Show scan history")
    history_parser.add_argument("address", help="Wallet address")
    history_parser.add_argument("--limit", type=int, default=10, help="Limit results")

    # Daemon
    daemon_parser = subparsers.add_parser("daemon", help="Run continuous scanning daemon")
    daemon_parser.add_argument("--interval", type=int, default=60, help="Scan interval in minutes")

    args = parser.parse_args()

    guard = WalletGuard(db_path=args.db, config_path=args.config)

    if args.action == "add":
        wallet = guard.add_wallet(args.address, args.chain, args.label)
        print(f"Added wallet: {wallet.address} ({wallet.chain})")

    elif args.action == "remove":
        guard.remove_wallet(args.address)
        print(f"Removed wallet: {args.address}")

    elif args.action == "list":
        wallets = guard.list_wallets()
        if not wallets:
            print("No wallets configured")
        else:
            for w in wallets:
                print(f"{w.address} | {w.chain} | {w.label} | Risk: {w.risk_score}")

    elif args.action == "scan":
        result = asyncio.run(guard.scan_wallet(args.address, ""))
        guard.save_scan(result)
        print(json.dumps(asdict(result), indent=2))

    elif args.action == "scan-all":
        asyncio.run(guard.run_scan_all())

    elif args.action == "status":
        guard.print_status(args.address)

    elif args.action == "alerts":
        alerts = guard.get_alerts(args.address, args.limit)
        for alert in alerts:
            print(f"[{alert['timestamp']}] {alert['severity'].upper()} | {alert['address'][:10]}... | {alert['message']}")

    elif args.action == "history":
        history = guard.get_scan_history(args.address, args.limit)
        for h in history:
            print(f"[{h['timestamp']}] Risk: {h['risk_score']} | Findings: {json.loads(h['findings'])}")

    elif args.action == "daemon":
        print(f"Starting WalletGuard daemon (interval: {args.interval} min)...")
        async def run_daemon():
            while True:
                await guard.run_scan_all()
                await asyncio.sleep(args.interval * 60)
        try:
            asyncio.run(run_daemon())
        except KeyboardInterrupt:
            print("\nDaemon stopped")


if __name__ == "__main__":
    main()