import pytest
import asyncio
import tempfile
import os
import json
from walletguard import WalletGuard, WalletAddress, ScanResult

@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    yield db_path
    if os.path.exists(db_path):
        os.unlink(db_path)

@pytest.fixture
def temp_config():
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as f:
        json.dump({
            "rpc_endpoints": {"ethereum": "https://eth.llamarpc.com"},
            "scan_interval_minutes": 60,
            "alert_webhook": "",
            "risk_thresholds": {"low": 30, "medium": 60, "high": 80},
            "blockscout_apis": {"ethereum": "https://eth.blockscout.com/api/v2"}
        }, f)
        config_path = f.name
    yield config_path
    if os.path.exists(config_path):
        os.unlink(config_path)

@pytest.fixture
def guard(temp_db, temp_config):
    return WalletGuard(db_path=temp_db, config_path=temp_config)

def test_add_wallet(guard):
    wallet = guard.add_wallet("0x1234567890123456789012345678901234567890", "ethereum", "Test Wallet")
    assert wallet.address == "0x1234567890123456789012345678901234567890"
    assert wallet.chain == "ethereum"
    assert wallet.label == "Test Wallet"
    assert wallet.risk_score == 0

def test_add_wallet_invalid_address(guard):
    with pytest.raises(ValueError):
        guard.add_wallet("invalid", "ethereum")

def test_remove_wallet(guard):
    guard.add_wallet("0x1234567890123456789012345678901234567890", "ethereum")
    guard.remove_wallet("0x1234567890123456789012345678901234567890")
    wallets = guard.list_wallets()
    assert len(wallets) == 0

def test_list_wallets(guard):
    guard.add_wallet("0x1111111111111111111111111111111111111111", "ethereum", "Wallet 1")
    guard.add_wallet("0x2222222222222222222222222222222222222222", "polygon", "Wallet 2")
    wallets = guard.list_wallets()
    assert len(wallets) == 2

def test_validate_address(guard):
    assert guard._validate_address("0x1234567890123456789012345678901234567890") == True
    assert guard._validate_address("0x123") == False
    assert guard._validate_address("1234567890123456789012345678901234567890") == False
    assert guard._validate_address("") == False

@pytest.mark.asyncio
async def test_scan_result_dataclass():
    result = ScanResult(
        address="0x1234567890123456789012345678901234567890",
        chain="ethereum",
        timestamp="2024-01-01T00:00:00",
        risk_score=50,
        findings=[{"type": "test", "severity": "medium", "message": "Test finding"}],
        approvals=[],
        token_balances=[],
        tx_count_24h=10
    )
    assert result.risk_score == 50
    assert len(result.findings) == 1

def test_wallet_address_dataclass():
    wallet = WalletAddress(
        address="0x1234567890123456789012345678901234567890",
        chain="ethereum",
        label="Test",
        added_at="2024-01-01T00:00:00"
    )
    assert wallet.address == "0x1234567890123456789012345678901234567890"
    assert wallet.risk_score == 0
    assert wallet.alerts == []

def test_config_loading(temp_config):
    guard = WalletGuard(db_path=":memory:", config_path=temp_config)
    assert "ethereum" in guard.config["rpc_endpoints"]
    assert guard.config["scan_interval_minutes"] == 60

def test_known_phishing_domains():
    from walletguard import KNOWN_PHISHING_DOMAINS
    assert "claim-tokens.xyz" in KNOWN_PHISHING_DOMAINS
    assert "metamask-support.io" in KNOWN_PHISHING_DOMAINS
    assert len(KNOWN_PHISHING_DOMAINS) > 5

def test_high_risk_selectors():
    from walletguard import HIGH_RISK_FUNCTION_SELECTORS
    assert "0xa9059cbb" in HIGH_RISK_FUNCTION_SELECTORS  # transfer
    assert "0x095ea7b3" in HIGH_RISK_FUNCTION_SELECTORS  # approve
    assert HIGH_RISK_FUNCTION_SELECTORS["0xa9059cbb"] == "transfer"

def test_scan_history_storage(guard):
    guard.add_wallet("0x1234567890123456789012345678901234567890", "ethereum")
    result = ScanResult(
        address="0x1234567890123456789012345678901234567890",
        chain="ethereum",
        timestamp="2024-01-01T00:00:00",
        risk_score=25,
        findings=[],
        approvals=[],
        token_balances=[],
        tx_count_24h=5
    )
    guard.save_scan(result)
    history = guard.get_scan_history("0x1234567890123456789012345678901234567890")
    assert len(history) == 1
    assert history[0]['risk_score'] == 25

def test_alert_creation(guard):
    guard.add_wallet("0x1234567890123456789012345678901234567890", "ethereum")
    result = ScanResult(
        address="0x1234567890123456789012345678901234567890",
        chain="ethereum",
        timestamp="2024-01-01T00:00:00",
        risk_score=85,
        findings=[{"type": "known_malicious", "severity": "critical", "message": "Known honeypot"}],
        approvals=[],
        token_balances=[],
        tx_count_24h=0
    )
    guard.save_scan(result)
    # Create a new guard instance to avoid db lock
    guard2 = WalletGuard(db_path=guard.db_path, config_path=guard.config_path)
    alerts = guard2.get_alerts("0x1234567890123456789012345678901234567890")
    assert len(alerts) == 1
    assert alerts[0]['severity'] == 'critical'