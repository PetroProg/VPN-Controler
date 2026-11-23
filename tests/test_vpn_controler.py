"""Unit and API tests for VPN Controler."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
import httpx
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
    assert "vc-v1.2.1" in r_sw.text
    assert "API_CACHE" not in r_sw.text
    assert "k.startsWith('vc-')" in r_sw.text

    r_cache_js = client.get("/js/core/cache.js")
    assert r_cache_js.status_code == 200
    assert "localStorage.setItem" not in r_cache_js.text
    assert "inspectAndGuardStorage" in r_cache_js.text

    r_ico = client.get("/favicon.ico")
    assert r_ico.status_code == 200

    r_apple = client.get("/apple-touch-icon.png")
    assert r_apple.status_code == 200


def test_api_health_route():
    with patch("app.main.adguard_client.check_health", new=AsyncMock(return_value=True)), \
         patch("app.main.tailscale_client.check_health", new=AsyncMock(return_value=True)):
        r = client.get("/api/health")
    assert r.status_code == 200
    assert r.headers.get("cache-control") == "no-store"
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


@pytest.mark.asyncio
async def test_adguard_session_login_singleflight_and_cookie_client():
    ag = AdGuardClient()
    login_calls = 0
    seen_auth_headers = []
    seen_cookies = []

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal login_calls
        if request.url.path == "/control/login":
            login_calls += 1
            await asyncio.sleep(0.02)
            return httpx.Response(
                200,
                headers={"Set-Cookie": "agh_session=tok123; Path=/; HttpOnly"},
                json={},
            )
        seen_auth_headers.append(request.headers.get("authorization"))
        seen_cookies.append(request.headers.get("cookie", ""))
        return httpx.Response(200, json={"running": True, "protection_enabled": True})

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def client_with_transport(*args, **kwargs):
        kwargs["transport"] = transport
        return real_async_client(*args, **kwargs)

    with patch("app.services.adguard.settings.ADGUARD_PASSWORD", "test-secret"), \
         patch("app.services.adguard.httpx.AsyncClient", side_effect=client_with_transport):
        results = await asyncio.gather(
            ag._ensure_session(),
            ag._ensure_session(),
            ag._ensure_session(),
        )
        assert results == [True, True, True]
        assert login_calls == 1
        assert ag._session_cookie == "tok123"

        async_client = ag._make_client()
        try:
            assert async_client.auth is None
            assert async_client.cookies.get("agh_session") == "tok123"
        finally:
            await async_client.aclose()

        assert await ag.check_health() is True

    assert login_calls == 1
    assert seen_auth_headers == [None]
    assert seen_cookies == ["agh_session=tok123"]


@pytest.mark.asyncio
async def test_adguard_401_triggers_relogin_and_retry():
    ag = AdGuardClient()
    ag._session_cookie = "expired_tok"
    login_calls = 0
    status_attempts = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal login_calls, status_attempts
        if request.url.path == "/control/login":
            login_calls += 1
            await asyncio.sleep(0.01)
            return httpx.Response(
                200,
                headers={"Set-Cookie": "agh_session=fresh_tok; Path=/; HttpOnly"},
                json={},
            )
        assert request.headers.get("authorization") is None
        cookie = request.headers.get("cookie", "")
        if request.url.path == "/control/status":
            status_attempts += 1
            if "agh_session=expired_tok" in cookie:
                return httpx.Response(401)
            if "agh_session=fresh_tok" in cookie:
                return httpx.Response(200, json={"running": True, "protection_enabled": True})
        return httpx.Response(404)

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def client_with_transport(*args, **kwargs):
        kwargs["transport"] = transport
        return real_async_client(*args, **kwargs)

    with patch("app.services.adguard.settings.ADGUARD_PASSWORD", "test-secret"), \
         patch("app.services.adguard.httpx.AsyncClient", side_effect=client_with_transport):
        async with ag._make_client() as http_client:
            r1, r2 = await asyncio.gather(
                ag._request(http_client, "get", "/control/status"),
                ag._request(http_client, "get", "/control/status"),
            )

    assert r1.status_code == 200
    assert r2.status_code == 200
    assert login_calls == 1
    assert status_attempts == 4
    assert ag._session_cookie == "fresh_tok"


@pytest.mark.asyncio
async def test_adguard_overview_and_tailscale_short_ttl_caches():
    ag = AdGuardClient()
    ag._session_cookie = "tok123"
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"running": True, "protection_enabled": True})

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def client_with_transport(*args, **kwargs):
        kwargs["transport"] = transport
        return real_async_client(*args, **kwargs)

    with patch("app.services.adguard.settings.ADGUARD_PASSWORD", "test-secret"), \
         patch("app.services.adguard.httpx.AsyncClient", side_effect=client_with_transport):
        ov1 = await ag.get_overview()
        first_batch_calls = calls
        assert ov1["online"] is True
        assert first_batch_calls == 8

        # Second call within 2.5s should hit the in-memory cache (0 new HTTP calls)
        ov2 = await ag.get_overview()
        assert ov2["online"] is True
        assert calls == first_batch_calls

        # Invalidation clears the cache so the next call fetches fresh data
        ag.invalidate_cache()
        ov3 = await ag.get_overview()
        assert ov3["online"] is True
        assert calls == first_batch_calls * 2


@pytest.mark.asyncio
async def test_blocked_services_syncs_enforced_important_rules_and_clears_cache():
    ag = AdGuardClient()
    ag._session_cookie = "tok123"
    stored_rules = ["||custom-manual.test^", "@@||spotify.com^", "@@||jut.su^$important"]
    stored_blocked_ids = []
    cache_clear_calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal stored_rules, stored_blocked_ids, cache_clear_calls
        path = request.url.path
        if path == "/control/blocked_services/get":
            return httpx.Response(200, json={"ids": stored_blocked_ids, "schedule": {"time_zone": "UTC"}})
        if path == "/control/blocked_services/update":
            import json
            body = json.loads(request.content.decode())
            stored_blocked_ids = list(body.get("ids") or [])
            return httpx.Response(200, json={})
        if path == "/control/filtering/status":
            return httpx.Response(200, json={"enabled": True, "user_rules": list(stored_rules), "filters": []})
        if path == "/control/filtering/set_rules":
            import json
            body = json.loads(request.content.decode())
            stored_rules = list(body.get("rules") or [])
            return httpx.Response(200, json={})
        if path == "/control/cache_clear":
            cache_clear_calls += 1
            return httpx.Response(200, json={})
        if path == "/control/querylog":
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "time": "2026-11-23T20:00:00Z",
                            "question": {"name": "aggr32-normal.tiktokv.eu", "type": "A"},
                            "client": "100.76.188.111",
                            "reason": "FilteredBlackList",
                            "rule": "||tiktokv.eu^$important",
                            "elapsedMs": 1.2,
                        }
                    ]
                },
            )
        return httpx.Response(200, json={"running": True, "protection_enabled": True})

    real_async_client = httpx.AsyncClient
    transport = httpx.MockTransport(handler)

    def client_with_transport(*args, **kwargs):
        kwargs["transport"] = transport
        return real_async_client(*args, **kwargs)

    with patch("app.services.adguard.settings.ADGUARD_PASSWORD", "test-secret"), \
         patch("app.services.adguard.httpx.AsyncClient", side_effect=client_with_transport):
        res = await ag.set_blocked_services(["tiktok", "spotify"])
        assert res == {"success": True, "ids": ["tiktok", "spotify"]}
        assert cache_clear_calls == 1
        assert "||tiktokv.eu^$important" in stored_rules
        assert "||byteeffecttos-g.com^$important" in stored_rules
        assert "||tiktokcdn-eu.com^$important" in stored_rules
        assert "||spotify.com^$important" in stored_rules
        # Manual rules stay preserved in AdGuard
        assert "||custom-manual.test^" in stored_rules
        assert "@@||spotify.com^" in stored_rules
        assert "@@||jut.su^$important" in stored_rules

        # Visible user_rules in UI exclude managed service $important rules
        visible = await ag.get_rules()
        assert visible == ["||custom-manual.test^", "@@||spotify.com^", "@@||jut.su^$important"]

        # Querylog classifies enforced service rule as blocked_service
        qlog = await ag.get_querylog()
        assert qlog["logs"][0]["source"] == "blocked_service"
        assert qlog["logs"][0]["reason"] == "Блокировка сервиса"

        # Unblocking services removes managed $important rules and preserves manual rules
        await ag.set_blocked_services([])
        assert cache_clear_calls == 2
        assert stored_rules == ["||custom-manual.test^", "@@||spotify.com^", "@@||jut.su^$important"]


