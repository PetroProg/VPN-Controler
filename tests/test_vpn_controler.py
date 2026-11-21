"""Unit and API tests for VPN Controler."""

from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.services.adguard import AdGuardClient
from app.services.tailscale import TailscaleClient


client = TestClient(app)


def test_html_and_pwa_routes():
    for path in ("/", "/vpn", "/settings"):
        r = client.get(path)
        assert r.status_code == 200
        assert "VPN Controler" in r.text

    r_man = client.get("/manifest.webmanifest")
    assert r_man.status_code == 200
    assert r_man.json()["short_name"] == "VPN Controler"

    r_sw = client.get("/sw.js")
    assert r_sw.status_code == 200
    assert r_sw.headers.get("service-worker-allowed") == "/"

    r_ico = client.get("/favicon.ico")
    assert r_ico.status_code == 200

    r_apple = client.get("/apple-touch-icon.png")
    assert r_apple.status_code == 200


def test_api_health_route():
    with patch("app.main.adguard_client.check_health", new=AsyncMock(return_value=True)), \
         patch("app.main.tailscale_client.check_health", new=AsyncMock(return_value=True)):
        r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {
        "status": "ok",
        "version": "1.0.0",
        "adguard_online": True,
        "tailscale_online": True,
    }


def test_ping_rejects_non_tailscale_ips():
    for bad_ip in ("192.168.178.1", "127.0.0.1", "8.8.8.8", "not-an-ip"):
        r = client.post("/api/vpn/ping", json={"ip": bad_ip})
        assert r.status_code == 422


def test_domain_and_rule_validation_rejects_injection():
    bad_inputs = [
        "<script>alert(1)</script>",
        "evil.com^$important",
        "bad domain.com",
        "localhost",
        "foo.com|bar",
    ]
    for bad in bad_inputs:
        assert client.post("/api/dns/block", json={"domain": bad}).status_code == 422
        assert client.post("/api/dns/rules", json={"domain": bad, "mode": "block"}).status_code == 422

    assert client.post("/api/dns/pause", json={"minutes": 0}).status_code == 422
    assert client.post("/api/dns/pause", json={"minutes": 9999}).status_code == 422


@pytest.mark.asyncio
async def test_tailscale_status_and_traffic_deltas():
    ts = TailscaleClient(sock_path="/tmp/nonexistent-ts.sock")
    sample_status = {
        "BackendState": "Running",
        "Version": "1.78.0-t123",
        "Health": [],
        "Self": {
            "HostName": "petroprog",
            "TailscaleIPs": ["100.107.4.120"],
            "DNSName": "petroprog.tail703e6c.ts.net.",
            "OS": "linux",
            "Relay": "fra",
            "Online": True,
        },
        "Peer": {
            "node1": {
                "ID": "n1",
                "HostName": "Samsung A54",
                "TailscaleIPs": ["100.76.188.111"],
                "DNSName": "samsung-a54.tail703e6c.ts.net.",
                "OS": "android",
                "Online": True,
                "Active": True,
                "CurAddr": "",
                "Relay": "fra",
                "RxBytes": 100_000,
                "TxBytes": 50_000,
                "LastSeen": "2026-11-21T18:00:00Z",
            },
            "node2": {
                "ID": "n2",
                "HostName": "DESKTOP-BE94GUV",
                "TailscaleIPs": ["100.82.14.22"],
                "DNSName": "desktop-be94guv.tail703e6c.ts.net.",
                "OS": "windows",
                "Online": True,
                "Active": False,
                "CurAddr": "192.168.178.39:41641",
                "Relay": "fra",
                "RxBytes": 20_000,
                "TxBytes": 10_000,
                "LastSeen": "2026-11-21T18:00:00Z",
            },
        },
    }

    with patch.object(ts, "_fetch_raw_status", new=AsyncMock(return_value=sample_status)):
        st = await ts.get_status()

    assert st["online"] is True
    assert st["peers_online"] == 2
    assert st["peers_count"] == 2
    by_name = {p["display_name"]: p for p in st["peers"]}
    assert by_name["Samsung A54"]["mode"] == "DERP fra"
    assert by_name["Samsung A54"]["direct"] is False
    assert by_name["DESKTOP-BE94GUV"]["mode"] == "Direct P2P"
    assert by_name["DESKTOP-BE94GUV"]["direct"] is True

    # Traffic baseline then delta
    with patch.object(ts, "_fetch_raw_status", new=AsyncMock(return_value=sample_status)):
        t1 = await ts.get_traffic()
    assert t1["rx_kbps"] == 0.0
    assert len(t1["history_rx"]) == 24

    sample_status["Peer"]["node1"]["RxBytes"] += 125_000  # +1 Mbit
    with patch.object(ts, "_fetch_raw_status", new=AsyncMock(return_value=sample_status)):
        t2 = await ts.get_traffic()
    assert t2["rx_kbps"] > 0.0


@pytest.mark.asyncio
async def test_adguard_smart_unblock_and_safesearch_toggle():
    ag = AdGuardClient()
    posted_rules = []

    def make_resp(status_code, json_data):
        m = MagicMock()
        m.status_code = status_code
        m.json.return_value = json_data
        m.content = b"{}"
        return m

    mock_http = AsyncMock()

    async def fake_get(url, **kwargs):
        if url == "/control/filtering/status":
            return make_resp(200, {"user_rules": list(current_rules), "interval": 24})
        if url == "/control/safesearch/status":
            return make_resp(200, {"enabled": False, "google": True, "youtube": True})
        return make_resp(200, {})

    async def fake_post(url, **kwargs):
        if url == "/control/filtering/set_rules":
            posted_rules.append(kwargs["json"]["rules"])
        return make_resp(200, {})

    async def fake_put(url, **kwargs):
        return make_resp(200, {})

    mock_http.get.side_effect = fake_get
    mock_http.post.side_effect = fake_post
    mock_http.put.side_effect = fake_put
    mock_http.__aenter__.return_value = mock_http
    mock_http.__aexit__.return_value = None

    # Case 1: domain in user_rules -> removes ||domain^
    current_rules = ["||tracker.test^", "@@||spotify.com^"]
    with patch.object(ag, "_make_client", return_value=mock_http):
        res1 = await ag.unblock_domain("tracker.test")
    assert res1["action"] == "removed_block_rule"
    assert posted_rules[-1] == ["@@||spotify.com^"]

    # Case 2: domain blocked by subscription list (not in user_rules) -> adds @@||domain^
    current_rules = ["@@||spotify.com^"]
    with patch.object(ag, "_make_client", return_value=mock_http):
        res2 = await ag.unblock_domain("ads.tiktok.com")
    assert res2["action"] == "added_exception_rule"
    assert "@@||ads.tiktok.com^" in posted_rules[-1]

    # Case 3: SafeSearch toggle uses /control/safesearch/settings cleanly
    with patch.object(ag, "_make_client", return_value=mock_http):
        res3 = await ag.toggle_feature("safesearch", True)
    assert res3 == {"success": True, "feature": "safesearch", "enabled": True}


def test_api_services_and_rewrites_endpoints():
    with patch("app.main.adguard_client.set_blocked_services", new=AsyncMock(return_value={"success": True, "ids": ["tiktok", "roblox"]})):
        r = client.put("/api/dns/services", json={"ids": ["TikTok", "roblox", "tiktok"]})
    assert r.status_code == 200
    assert r.json()["ids"] == ["tiktok", "roblox"]

    with patch("app.main.adguard_client.add_rewrite", new=AsyncMock(return_value={"success": True, "domain": "vpn.home", "answer": "192.168.178.65"})):
        r2 = client.post("/api/dns/rewrites", json={"domain": "vpn.home", "answer": "192.168.178.65"})
    assert r2.status_code == 200
    assert r2.json()["domain"] == "vpn.home"

    r_bad = client.post("/api/dns/rewrites", json={"domain": "bad host", "answer": "192.168.178.65"})
    assert r_bad.status_code == 422
