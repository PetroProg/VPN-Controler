"""Async client for AdGuard Home REST API."""

import asyncio
from datetime import datetime
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import httpx

from app.config import settings

logger = logging.getLogger("vpn_controler.adguard")

UPSTREAM_PRESETS: Dict[str, Dict[str, str]] = {
    "quad9": {
        "name": "Quad9",
        "doh": "https://dns.quad9.net/dns-query",
        "plain": "9.9.9.9",
    },
    "cloudflare": {
        "name": "Cloudflare",
        "doh": "https://cloudflare-dns.com/dns-query",
        "plain": "1.1.1.1",
    },
    "adguard": {
        "name": "AdGuard",
        "doh": "https://dns.adguard-dns.com/dns-query",
        "plain": "94.140.14.14",
    },
    "google": {
        "name": "Google",
        "doh": "https://dns.google/dns-query",
        "plain": "8.8.8.8",
    },
}

# RFC 8484 minimal DNS wire query for example.com A record
_DOH_SAMPLE_QUERY = "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"

CURATED_SERVICES: List[str] = [
    "youtube",
    "tiktok",
    "instagram",
    "facebook",
    "steam",
    "discord",
    "twitch",
    "roblox",
    "telegram",
    "netflix",
    "spotify",
    "twitter",
]

# Enforced $important domains per service to cover regional/EU failovers (e.g. tiktokv.eu,
# byteeffecttos-g.com, tiktokcdn-eu.com) missing from AdGuard Home's built-in catalog
# and to take precedence over non-important @@|| user exceptions while a service is blocked.
SERVICE_ENFORCED_DOMAINS: Dict[str, List[str]] = {
    "tiktok": [
        "tiktok.com",
        "tiktokv.com",
        "tiktokv.eu",
        "tiktokv.us",
        "tiktokcdn.com",
        "tiktokcdn-eu.com",
        "tiktokcdn-us.com",
        "tiktokrow-cdn.com",
        "tiktokw.eu",
        "tiktokw.us",
        "ttwstatic.com",
        "ttlivecdn.com",
        "ibyteimg.com",
        "ibytedtos.com",
        "byteimg.com",
        "byteoversea.com",
        "byteoversea.net",
        "byteeffecttos-g.com",
        "byteeffecttos.com",
        "bytefcdn-oversea.com",
        "bytefcdn-ttpeu.com",
        "bytedapm.com",
        "bytegoofy.com",
        "bytescm.com",
        "bytednsdoc.com",
        "pstatp.com",
        "sgpstatp.com",
        "snssdk.com",
        "amemv.com",
        "muscdn.com",
        "musical.ly",
        "tiktok.tps.dv.tech",
    ],
    "youtube": [
        "youtube.com",
        "youtu.be",
        "googlevideo.com",
        "ytimg.com",
        "ggpht.com",
        "youtubei.googleapis.com",
        "youtube-nocookie.com",
        "youtubekids.com",
        "withyoutube.com",
        "yt.be",
    ],
    "instagram": [
        "instagram.com",
        "cdninstagram.com",
        "ig.me",
        "igcdn.com",
        "igsonar.com",
        "igtv.com",
    ],
    "facebook": [
        "facebook.com",
        "facebook.net",
        "fbcdn.net",
        "fbsbx.com",
        "fb.com",
        "fb.me",
        "messenger.com",
        "m.me",
        "tfbnw.net",
    ],
    "steam": [
        "steampowered.com",
        "steamcommunity.com",
        "steamstatic.com",
        "steamcontent.com",
        "steamgames.com",
        "steamusercontent.com",
        "steamserver.net",
        "steam-api.com",
        "steam-chat.com",
        "s.team",
    ],
    "discord": [
        "discord.com",
        "discordapp.com",
        "discordapp.net",
        "discord.gg",
        "discord.media",
        "discordcdn.com",
        "discord.co",
        "dis.gd",
    ],
    "twitch": [
        "twitch.tv",
        "ttvnw.net",
        "jtvnw.net",
        "twitchcdn.net",
        "twitchsvc.net",
        "ext-twitch.tv",
    ],
    "roblox": [
        "roblox.com",
        "rbxcdn.com",
        "robloxcdn.com",
        "rbx.com",
        "rbxinfra.com",
        "rbxinfra.net",
    ],
    "telegram": [
        "telegram.org",
        "t.me",
        "telegram.me",
        "telegram.dog",
        "telegra.ph",
        "telesco.pe",
        "telegram-cdn.org",
        "cdn-telegram.org",
        "tdesktop.com",
        "web.telegram.org",
    ],
    "netflix": [
        "netflix.com",
        "netflix.net",
        "nflxso.net",
        "nflxvideo.net",
        "nflximg.net",
        "nflximg.com",
        "nflxext.com",
        "fast.com",
    ],
    "spotify": [
        "spotify.com",
        "scdn.co",
        "spotifycdn.com",
        "spotifycdn.net",
        "byspotify.com",
        "pscdn.co",
        "spoti.fi",
        "audio-ak-spotify-com.akamaized.net",
        "audio4-ak-spotify-com.akamaized.net",
        "heads-ak-spotify-com.akamaized.net",
        "heads4-ak-spotify-com.akamaized.net",
    ],
    "twitter": [
        "twitter.com",
        "x.com",
        "twimg.com",
        "t.co",
        "twtrdns.net",
        "twttr.com",
        "twttr.net",
        "pscp.tv",
        "periscope.tv",
        "cms-twdigitalassets.com",
    ],
}

_ALL_SERVICE_ENFORCED_RULES: Set[str] = {
    f"||{dom}^$important"
    for doms in SERVICE_ENFORCED_DOMAINS.values()
    for dom in doms
}

_DEFAULT_MAX_CACHE_TTL_SECONDS = 60
_DEFAULT_BLOCKED_RESPONSE_TTL_SECONDS = 10


def _build_service_enforced_rules(service_ids: List[str]) -> List[str]:
    rules: List[str] = []
    seen: Set[str] = set()
    for raw_sid in service_ids:
        sid = str(raw_sid).strip().lower()
        for dom in SERVICE_ENFORCED_DOMAINS.get(sid, []):
            rule = f"||{dom}^$important"
            if rule not in seen:
                seen.add(rule)
                rules.append(rule)
    return rules


def _filter_visible_user_rules(raw_rules: List[Any]) -> List[str]:
    return [
        str(r)
        for r in raw_rules
        if str(r).strip().lower() not in _ALL_SERVICE_ENFORCED_RULES
    ]


def _detect_provider(upstreams: List[str]) -> str:
    joined = " ".join(upstreams).lower()
    primary = (upstreams[0] if upstreams else "").lower()
    if "quad9" in primary or "9.9.9.9" in primary or "quad9" in joined:
        return "quad9"
    if "cloudflare" in primary or "1.1.1.1" in primary or "cloudflare" in joined:
        return "cloudflare"
    if "adguard" in primary or "94.140" in primary or "adguard" in joined:
        return "adguard"
    if "dns.google" in primary or "8.8.8.8" in primary or "dns.google" in joined:
        return "google"
    return "quad9"


def _build_upstreams(provider: str, doh_enabled: bool) -> List[str]:
    preset = UPSTREAM_PRESETS.get(provider, UPSTREAM_PRESETS["quad9"])
    if doh_enabled:
        return [preset["doh"], preset["plain"], "192.168.178.1"]
    return [preset["plain"], "192.168.178.1"]


class AdGuardError(RuntimeError):
    """Raised when AdGuard Home API returns an unexpected error."""


class AdGuardClient:
    """Async REST client for AdGuard Home control API."""

    def __init__(self) -> None:
        self._doh_cache: Tuple[float, Dict[str, Optional[float]]] = (0.0, {})
        self._overview_cache: Tuple[float, Optional[Dict[str, Any]]] = (0.0, None)
        self._services_cache: Tuple[float, Optional[Dict[str, Any]]] = (0.0, None)
        self._session_cookie: Optional[str] = None
        self._auth_lock = asyncio.Lock()
        self._desired_service_ids: Optional[List[str]] = None
        self._services_worker_task: Optional[asyncio.Task[None]] = None
        self._blocked_services_schedule: Optional[Dict[str, Any]] = None

    def invalidate_cache(self) -> None:
        """Invalidate short-lived in-memory overview and services caches after a mutation."""
        self._overview_cache = (0.0, None)
        self._services_cache = (0.0, None)

    def _make_client(
        self,
        timeout: Optional[float] = None,
        *,
        with_auth: bool = True,
    ) -> httpx.AsyncClient:
        effective_timeout = timeout or settings.ADGUARD_TIMEOUT_SECONDS
        if with_auth and self._session_cookie:
            return httpx.AsyncClient(
                base_url=settings.ADGUARD_URL,
                cookies={"agh_session": self._session_cookie},
                timeout=effective_timeout,
            )
        if with_auth and settings.ADGUARD_PASSWORD:
            return httpx.AsyncClient(
                base_url=settings.ADGUARD_URL,
                auth=(settings.ADGUARD_USER, settings.ADGUARD_PASSWORD),
                timeout=effective_timeout,
            )
        return httpx.AsyncClient(
            base_url=settings.ADGUARD_URL,
            timeout=effective_timeout,
        )

    async def _ensure_session(
        self,
        force: bool = False,
        failed_cookie: Optional[str] = None,
    ) -> bool:
        """Obtain and cache AdGuard Home session cookie so requests skip per-call bcrypt."""
        if not settings.ADGUARD_PASSWORD:
            return True
        if not force and self._session_cookie:
            return True

        async with self._auth_lock:
            if not force and self._session_cookie:
                return True
            if (
                force
                and failed_cookie is not None
                and self._session_cookie
                and self._session_cookie != failed_cookie
            ):
                return True

            login_timeout = max(settings.ADGUARD_TIMEOUT_SECONDS, 10.0)
            try:
                async with self._make_client(timeout=login_timeout, with_auth=False) as client:
                    resp = await client.post(
                        "/control/login",
                        json={"name": settings.ADGUARD_USER, "password": settings.ADGUARD_PASSWORD},
                    )
                if resp.status_code == 200:
                    cookies = getattr(resp, "cookies", None)
                    cookie_val = cookies.get("agh_session") if hasattr(cookies, "get") else None
                    if isinstance(cookie_val, str) and cookie_val:
                        self._session_cookie = cookie_val
                    else:
                        self._session_cookie = None
                    return True
                self._session_cookie = None
                logger.warning("AdGuard /control/login returned HTTP %s", resp.status_code)
                return False
            except Exception as exc:
                self._session_cookie = None
                logger.warning("AdGuard /control/login failed: %s", exc)
                return False

    async def _require_session(self) -> None:
        if not await self._ensure_session():
            raise AdGuardError("AdGuard Home authentication failed")

    async def _request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Execute an AdGuard API request and refresh expired session cookies on 401."""
        client_cookies = getattr(client, "cookies", None)
        raw_cookie = client_cookies.get("agh_session") if hasattr(client_cookies, "get") else None
        used_cookie = raw_cookie if isinstance(raw_cookie, str) and raw_cookie else self._session_cookie
        resp = await getattr(client, method)(url, **kwargs)
        if resp.status_code == 401 and settings.ADGUARD_PASSWORD:
            if await self._ensure_session(force=True, failed_cookie=used_cookie):
                cookies = getattr(client, "cookies", None)
                if self._session_cookie and hasattr(cookies, "set"):
                    cookies.set("agh_session", self._session_cookie)
                resp = await getattr(client, method)(url, **kwargs)
        return resp

    async def check_health(self) -> bool:
        if not await self._ensure_session():
            return False
        try:
            async with self._make_client(timeout=3.0) as client:
                resp = await self._request(client, "get", "/control/status")
                return resp.status_code == 200
        except Exception:
            return False

    async def get_overview(
        self,
        ip_name_map: Optional[Dict[str, str]] = None,
        *,
        force: bool = False,
    ) -> Dict[str, Any]:
        """Fetch full dashboard overview (status, 24h stats, toggles, rules, filters)."""
        now = time.monotonic()
        cached_ts, cached_data = self._overview_cache
        if not force and cached_data is not None and (now - cached_ts) < 2.5:
            return dict(cached_data)

        ip_map = ip_name_map or {}
        result: Dict[str, Any] = {
            "online": False,
            "running": False,
            "version": "",
            "protection": True,
            "protection_disabled_duration_ms": 0,
            "toggles": {
                "adblock": True,
                "malware": True,
                "doh": True,
                "safesearch": False,
                "parental": False,
            },
            "provider": "quad9",
            "upstream_dns": [],
            "stats": {
                "total_queries": 0,
                "blocked_queries": 0,
                "blocked_percent": 0.0,
                "threats_count": 0,
                "avg_latency_ms": 0.0,
                "dns_queries_history": [],
                "blocked_history": [],
                "top_blocked": [],
                "top_clients": [],
            },
            "filters": [],
            "user_rules": [],
            "blocked_service_ids": [],
            "dns_ip": settings.HOST_LAN_IP,
            "tailscale_ip": settings.HOST_TAILSCALE_IP,
        }

        if not await self._ensure_session():
            return result

        try:
            async with self._make_client() as client:
                resps = await asyncio.gather(
                    self._request(client, "get", "/control/status"),
                    self._request(client, "get", "/control/stats"),
                    self._request(client, "get", "/control/filtering/status"),
                    self._request(client, "get", "/control/safebrowsing/status"),
                    self._request(client, "get", "/control/safesearch/status"),
                    self._request(client, "get", "/control/parental/status"),
                    self._request(client, "get", "/control/dns_info"),
                    self._request(client, "get", "/control/blocked_services/get"),
                    return_exceptions=True,
                )
        except Exception as exc:
            logger.warning("AdGuard overview error: %s", exc)
            return result

        r_stat, r_stats, r_filt, r_safe, r_ss, r_par, r_dns, r_svcs = resps

        if isinstance(r_stat, Exception):
            logger.warning("AdGuard /control/status error: %s", r_stat)
        elif r_stat.status_code != 200:
            logger.warning("AdGuard /control/status returned HTTP %s", r_stat.status_code)
        else:
            sj = r_stat.json()
            result["online"] = True
            result["running"] = bool(sj.get("running", True))
            result["version"] = str(sj.get("version", ""))
            result["protection"] = bool(sj.get("protection_enabled", True))
            result["protection_disabled_duration_ms"] = int(sj.get("protection_disabled_duration") or 0)

        if isinstance(r_stats, Exception):
            logger.warning("AdGuard /control/stats error: %s", r_stats)
        elif r_stats.status_code != 200:
            logger.warning("AdGuard /control/stats returned HTTP %s", r_stats.status_code)
        else:
            st = r_stats.json()
            total = int(st.get("num_dns_queries") or 0)
            blocked = int(st.get("num_blocked_filtering") or 0)
            safebrowsing = int(st.get("num_replaced_safebrowsing") or 0)
            parental = int(st.get("num_replaced_parental") or 0)
            pct = round((blocked / total * 100.0), 1) if total > 0 else 0.0
            avg_lat = round(float(st.get("avg_processing_time") or 0.0) * 1000.0, 1)

            top_blocked: List[Dict[str, Any]] = []
            for entry in (st.get("top_blocked_domains") or [])[:5]:
                for dom, cnt in entry.items():
                    top_blocked.append({"domain": dom, "count": int(cnt)})

            top_clients: List[Dict[str, Any]] = []
            for entry in (st.get("top_clients") or [])[:5]:
                for ip, cnt in entry.items():
                    top_clients.append(
                        {"ip": ip, "name": ip_map.get(ip, ip), "count": int(cnt)}
                    )

            result["stats"] = {
                "total_queries": total,
                "blocked_queries": blocked,
                "blocked_percent": pct,
                "threats_count": safebrowsing + parental,
                "avg_latency_ms": avg_lat,
                "dns_queries_history": list(st.get("dns_queries") or []),
                "blocked_history": list(st.get("blocked_filtering") or []),
                "top_blocked": top_blocked,
                "top_clients": top_clients,
            }

        if not isinstance(r_filt, Exception) and r_filt.status_code == 200:
            fj = r_filt.json()
            result["toggles"]["adblock"] = bool(fj.get("enabled", True))
            result["user_rules"] = _filter_visible_user_rules(fj.get("user_rules") or [])
            result["filters"] = [
                {
                    "id": item.get("id"),
                    "name": item.get("name") or "",
                    "url": item.get("url") or "",
                    "enabled": bool(item.get("enabled", False)),
                    "rules_count": int(item.get("rules_count") or 0),
                    "last_updated": item.get("last_updated") or "",
                }
                for item in (fj.get("filters") or [])
            ]

        if not isinstance(r_safe, Exception) and r_safe.status_code == 200:
            result["toggles"]["malware"] = bool(r_safe.json().get("enabled", True))

        if not isinstance(r_ss, Exception) and r_ss.status_code == 200:
            result["toggles"]["safesearch"] = bool(r_ss.json().get("enabled", False))

        if not isinstance(r_par, Exception) and r_par.status_code == 200:
            result["toggles"]["parental"] = bool(r_par.json().get("enabled", False))

        if not isinstance(r_dns, Exception) and r_dns.status_code == 200:
            dj = r_dns.json()
            upstreams = [str(u) for u in (dj.get("upstream_dns") or [])]
            result["upstream_dns"] = upstreams
            result["provider"] = _detect_provider(upstreams)
            result["toggles"]["doh"] = any(u.startswith("https://") for u in upstreams)

        if not isinstance(r_svcs, Exception) and r_svcs.status_code == 200:
            sv = r_svcs.json()
            if isinstance(sv, dict):
                result["blocked_service_ids"] = list(sv.get("ids") or [])
                if sv.get("schedule"):
                    self._blocked_services_schedule = sv.get("schedule")
            elif isinstance(sv, list):
                result["blocked_service_ids"] = list(sv)

        if self._desired_service_ids is not None:
            result["blocked_service_ids"] = list(self._desired_service_ids)

        if result["online"]:
            self._overview_cache = (time.monotonic(), dict(result))
        return result

    async def toggle_feature(self, feature: str, enabled: bool) -> Dict[str, Any]:
        await self._require_session()
        async with self._make_client() as client:
            if feature == "protection":
                resp = await self._request(client, "post", "/control/protection", json={"enabled": enabled})
            elif feature == "adblock":
                f_resp = await self._request(client, "get", "/control/filtering/status")
                interval = 24
                if f_resp.status_code == 200:
                    interval = int(f_resp.json().get("interval") or 24)
                resp = await self._request(
                    client,
                    "post",
                    "/control/filtering/config",
                    json={"enabled": enabled, "interval": interval},
                )
            elif feature == "malware":
                ep = "enable" if enabled else "disable"
                resp = await self._request(client, "post", f"/control/safebrowsing/{ep}")
            elif feature == "parental":
                ep = "enable" if enabled else "disable"
                resp = await self._request(client, "post", f"/control/parental/{ep}")
            elif feature == "safesearch":
                ss_resp = await self._request(client, "get", "/control/safesearch/status")
                payload = (
                    ss_resp.json()
                    if ss_resp.status_code == 200
                    else {
                        "bing": True,
                        "duckduckgo": True,
                        "ecosia": True,
                        "google": True,
                        "pixabay": True,
                        "yandex": True,
                        "youtube": True,
                    }
                )
                payload["enabled"] = enabled
                if enabled:
                    for key in ("bing", "duckduckgo", "ecosia", "google", "pixabay", "yandex", "youtube"):
                        payload[key] = True
                resp = await self._request(client, "put", "/control/safesearch/settings", json=payload)
                if resp.status_code in (404, 405):
                    ep = "enable" if enabled else "disable"
                    resp = await self._request(client, "post", f"/control/safesearch/{ep}")
            elif feature == "doh":
                info_resp = await self._request(client, "get", "/control/dns_info")
                if info_resp.status_code != 200:
                    raise AdGuardError("Failed to fetch dns_info")
                cfg = info_resp.json()
                provider = _detect_provider(cfg.get("upstream_dns") or [])
                cfg["upstream_dns"] = _build_upstreams(provider, enabled)
                cfg["cache_ttl_max"] = _DEFAULT_MAX_CACHE_TTL_SECONDS
                cfg["blocked_response_ttl"] = _DEFAULT_BLOCKED_RESPONSE_TTL_SECONDS
                resp = await self._request(client, "post", "/control/dns_config", json=cfg)
            else:
                raise ValueError(f"Unsupported feature: {feature}")

            if resp.status_code not in (200, 204):
                raise AdGuardError(f"AdGuard returned HTTP {resp.status_code}")
            await self._clear_cache_best_effort(client)

        self.invalidate_cache()
        return {"success": True, "feature": feature, "enabled": enabled}

    async def pause_protection(self, minutes: int) -> Dict[str, Any]:
        await self._require_session()
        duration_ms = minutes * 60 * 1000
        async with self._make_client() as client:
            resp = await self._request(
                client,
                "post",
                "/control/protection",
                json={"enabled": False, "duration": duration_ms},
            )
            if resp.status_code not in (200, 204):
                resp = await self._request(client, "post", "/control/protection", json={"enabled": False})
                if resp.status_code not in (200, 204):
                    raise AdGuardError(f"Failed to pause protection: HTTP {resp.status_code}")
        self.invalidate_cache()
        return {"success": True, "paused": True, "minutes": minutes, "duration_ms": duration_ms}

    async def set_upstream(self, provider: str) -> Dict[str, Any]:
        if provider not in UPSTREAM_PRESETS:
            raise ValueError(f"Unknown upstream provider: {provider}")
        await self._require_session()
        async with self._make_client() as client:
            info_resp = await self._request(client, "get", "/control/dns_info")
            if info_resp.status_code != 200:
                raise AdGuardError("Failed to fetch dns_info")
            cfg = info_resp.json()
            cur_up = [str(u) for u in (cfg.get("upstream_dns") or [])]
            doh_enabled = any(u.startswith("https://") for u in cur_up) if cur_up else True
            new_upstreams = _build_upstreams(provider, doh_enabled)
            cfg["upstream_dns"] = new_upstreams
            cfg["bootstrap_dns"] = ["1.1.1.1", "9.9.9.9"]
            cfg["cache_ttl_max"] = _DEFAULT_MAX_CACHE_TTL_SECONDS
            cfg["blocked_response_ttl"] = _DEFAULT_BLOCKED_RESPONSE_TTL_SECONDS
            resp = await self._request(client, "post", "/control/dns_config", json=cfg)
            if resp.status_code not in (200, 204):
                raise AdGuardError(f"Failed to update dns_config: HTTP {resp.status_code}")
            await self._clear_cache_best_effort(client)
        self.invalidate_cache()
        return {"success": True, "provider": provider, "upstream_dns": new_upstreams}

    async def probe_doh_latencies(self, force: bool = False) -> Dict[str, Optional[float]]:
        """Measure live HTTPS/DoH RTT for each upstream provider with 60s caching."""
        now = time.monotonic()
        cached_ts, cached_vals = self._doh_cache
        if not force and cached_vals and (now - cached_ts) < settings.DOH_PROBE_CACHE_SECONDS:
            return dict(cached_vals)

        async def _measure(client: httpx.AsyncClient, pid: str, url: str) -> Tuple[str, Optional[float]]:
            t0 = time.perf_counter()
            try:
                resp = await client.get(
                    url,
                    params={"dns": _DOH_SAMPLE_QUERY},
                    headers={"Accept": "application/dns-message"},
                )
                if resp.status_code not in (502, 503, 504):
                    return pid, round((time.perf_counter() - t0) * 1000.0, 1)
            except Exception as exc:
                logger.debug("DoH probe failed for %s: %s", pid, exc)
            return pid, None

        async with httpx.AsyncClient(timeout=settings.DOH_PROBE_TIMEOUT_SECONDS) as client:
            results = await asyncio.gather(
                *(_measure(client, pid, meta["doh"]) for pid, meta in UPSTREAM_PRESETS.items())
            )

        latencies = dict(results)
        self._doh_cache = (now, latencies)
        return latencies

    async def get_querylog(
        self,
        limit: int = 50,
        status_filter: str = "all",
        search: str = "",
        client_filter: str = "",
        ip_name_map: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        ip_map = ip_name_map or {}
        clamped_limit = min(max(limit, 1), 200)
        params: Dict[str, Any] = {"limit": clamped_limit}
        if search.strip():
            params["search"] = search.strip()
        if status_filter == "blocked":
            params["response_status"] = "filtered"

        await self._require_session()
        async with self._make_client() as client:
            r_log, r_filt = await asyncio.gather(
                self._request(client, "get", "/control/querylog", params=params),
                self._request(client, "get", "/control/filtering/status"),
                return_exceptions=True,
            )

        if isinstance(r_log, Exception) or r_log.status_code != 200:
            raise AdGuardError("Failed to fetch querylog")

        user_rules: Set[str] = set()
        if not isinstance(r_filt, Exception) and r_filt.status_code == 200:
            user_rules = {str(r).strip().lower() for r in (r_filt.json().get("user_rules") or [])}

        logs: List[Dict[str, Any]] = []
        raw_entries = r_log.json().get("data") or []
        c_filter_lower = client_filter.strip().lower()

        for item in raw_entries:
            reason = str(item.get("reason") or "")
            ans = item.get("answer") or []
            is_zero = any(isinstance(a, dict) and a.get("value") == "0.0.0.0" for a in ans)
            is_blocked = (
                reason.startswith("Filtered")
                or reason in ("FilteredBlackList", "FilteredBlockedService", "FilteredParental", "FilteredSafeBrowsing")
                or is_zero
            )

            if status_filter == "blocked" and not is_blocked:
                continue
            if status_filter == "allowed" and is_blocked:
                continue

            q = item.get("question") or {}
            domain = str(q.get("name") or "").rstrip(".")
            dom_low = domain.lower()

            c_ip = str(item.get("client") or "")
            c_info = item.get("client_info") or {}
            c_name = ip_map.get(c_ip) or c_info.get("name") or c_ip

            if c_filter_lower and c_filter_lower != "all":
                if c_filter_lower not in c_ip.lower() and c_filter_lower not in c_name.lower():
                    continue

            if is_blocked:
                rule_low = str(item.get("rule") or "").strip().lower()
                if "BlockedService" in reason or rule_low in _ALL_SERVICE_ENFORCED_RULES:
                    source = "blocked_service"
                    reason_label = "Блокировка сервиса"
                elif f"||{dom_low}^" in user_rules or dom_low in user_rules:
                    source = "user_rule"
                    reason_label = "Ручное правило"
                elif "Parental" in reason:
                    source = "parental"
                    reason_label = "Родительский контроль"
                elif "SafeBrowsing" in reason:
                    source = "safebrowsing"
                    reason_label = "Фишинг / Угроза"
                else:
                    source = "filter_list"
                    reason_label = "Подписка AdGuard"
            else:
                if f"@@||{dom_low}^" in user_rules or f"@@||{dom_low}^|" in user_rules:
                    source = "exception"
                    reason_label = "Исключение @@"
                else:
                    source = "none"
                    reason_label = "Разрешено"

            t_str = str(item.get("time") or "")
            formatted_time = ""
            if t_str:
                try:
                    dt = datetime.fromisoformat(t_str.replace("Z", "+00:00"))
                    formatted_time = dt.astimezone().strftime("%H:%M:%S")
                except Exception:
                    formatted_time = t_str[:19].replace("T", " ")

            try:
                elapsed = round(float(item.get("elapsedMs") or 0.0), 1)
            except Exception:
                elapsed = 0.0

            logs.append(
                {
                    "time": formatted_time,
                    "domain": domain,
                    "type": str(q.get("type") or "A"),
                    "client_ip": c_ip,
                    "client_name": c_name,
                    "status": "blocked" if is_blocked else "allowed",
                    "source": source,
                    "reason": reason_label,
                    "rule": str(item.get("rule") or ""),
                    "elapsed_ms": elapsed,
                }
            )

        return {"success": True, "logs": logs, "total": len(logs)}

    async def _clear_cache_best_effort(self, client: httpx.AsyncClient) -> None:
        """Flush AdGuard Home DNS cache after rule/service updates without failing the mutation."""
        try:
            await self._request(client, "post", "/control/cache_clear")
        except Exception as exc:
            logger.debug("Best-effort AdGuard cache clear skipped: %s", exc)

    async def _set_user_rules(self, client: httpx.AsyncClient, rules: List[str]) -> None:
        resp = await self._request(client, "post", "/control/filtering/set_rules", json={"rules": rules})
        if resp.status_code not in (200, 204):
            raise AdGuardError(f"Failed to set filtering rules: HTTP {resp.status_code}")
        await self._clear_cache_best_effort(client)
        self.invalidate_cache()

    async def block_domain(self, domain: str) -> Dict[str, Any]:
        await self._require_session()
        rule = f"||{domain}^"
        allow_variants = {f"@@||{domain}^", f"@@||{domain}^|"}
        async with self._make_client() as client:
            filt_resp = await self._request(client, "get", "/control/filtering/status")
            if filt_resp.status_code != 200:
                raise AdGuardError("Failed to fetch filtering status")
            rules = [str(r) for r in (filt_resp.json().get("user_rules") or [])]
            updated = [r for r in rules if r.strip().lower() not in allow_variants]
            if rule not in {r.strip().lower() for r in updated}:
                updated.insert(0, rule)
            await self._set_user_rules(client, updated)
        return {"success": True, "domain": domain, "rule": rule, "action": "blocked"}

    async def unblock_domain(self, domain: str) -> Dict[str, Any]:
        """Smart unblock: remove user block rule OR add @@||domain^ exception if blocked by filter list."""
        await self._require_session()
        block_variants = {f"||{domain}^", domain}
        allow_rule = f"@@||{domain}^"
        async with self._make_client() as client:
            filt_resp = await self._request(client, "get", "/control/filtering/status")
            if filt_resp.status_code != 200:
                raise AdGuardError("Failed to fetch filtering status")
            rules = [str(r) for r in (filt_resp.json().get("user_rules") or [])]
            had_block = any(r.strip().lower() in block_variants for r in rules)
            if had_block:
                updated = [r for r in rules if r.strip().lower() not in block_variants]
                action = "removed_block_rule"
                applied_rule = f"||{domain}^"
            else:
                updated = list(rules)
                if allow_rule not in {r.strip().lower() for r in updated}:
                    updated.insert(0, allow_rule)
                action = "added_exception_rule"
                applied_rule = allow_rule
            await self._set_user_rules(client, updated)
        return {"success": True, "domain": domain, "rule": applied_rule, "action": action}

    async def get_rules(self) -> List[str]:
        await self._require_session()
        async with self._make_client() as client:
            resp = await self._request(client, "get", "/control/filtering/status")
            if resp.status_code != 200:
                raise AdGuardError("Failed to fetch filtering rules")
            return _filter_visible_user_rules(resp.json().get("user_rules") or [])

    async def add_rule(self, domain: str, mode: str) -> Dict[str, Any]:
        await self._require_session()
        if mode == "allow":
            rule = f"@@||{domain}^"
            remove_set = {f"||{domain}^", domain}
        else:
            rule = f"||{domain}^"
            remove_set = {f"@@||{domain}^", f"@@||{domain}^|"}

        async with self._make_client() as client:
            resp = await self._request(client, "get", "/control/filtering/status")
            if resp.status_code != 200:
                raise AdGuardError("Failed to fetch filtering rules")
            rules = [str(r) for r in (resp.json().get("user_rules") or [])]
            updated = [r for r in rules if r.strip().lower() not in remove_set]
            if rule not in {r.strip().lower() for r in updated}:
                updated.insert(0, rule)
            await self._set_user_rules(client, updated)
        return {"success": True, "rule": rule, "rules": _filter_visible_user_rules(updated)}

    async def delete_rule(self, rule: str) -> Dict[str, Any]:
        await self._require_session()
        target = rule.strip()
        async with self._make_client() as client:
            resp = await self._request(client, "get", "/control/filtering/status")
            if resp.status_code != 200:
                raise AdGuardError("Failed to fetch filtering rules")
            rules = [str(r) for r in (resp.json().get("user_rules") or [])]
            updated = [r for r in rules if r.strip() != target]
            await self._set_user_rules(client, updated)
        return {"success": True, "removed": target, "rules": _filter_visible_user_rules(updated)}

    async def get_blocked_services(self, *, force: bool = False) -> Dict[str, Any]:
        now = time.monotonic()
        cached_ts, cached_data = self._services_cache
        if not force and cached_data is not None and (now - cached_ts) < 5.0:
            return dict(cached_data)

        await self._require_session()
        async with self._make_client() as client:
            r_all, r_get = await asyncio.gather(
                self._request(client, "get", "/control/blocked_services/all"),
                self._request(client, "get", "/control/blocked_services/get"),
                return_exceptions=True,
            )

        all_map: Dict[str, str] = {}
        if not isinstance(r_all, Exception) and r_all.status_code == 200:
            for svc in r_all.json().get("blocked_services") or []:
                sid = str(svc.get("id") or "").lower()
                if sid:
                    all_map[sid] = str(svc.get("name") or sid)

        active_ids: List[str] = []
        if not isinstance(r_get, Exception) and r_get.status_code == 200:
            body = r_get.json()
            if isinstance(body, dict):
                active_ids = [str(x).lower() for x in (body.get("ids") or [])]
                if body.get("schedule"):
                    self._blocked_services_schedule = body.get("schedule")
            elif isinstance(body, list):
                active_ids = [str(x).lower() for x in body]

        if self._desired_service_ids is not None:
            active_ids = list(self._desired_service_ids)

        active_set = set(active_ids)
        services: List[Dict[str, Any]] = []
        for sid in CURATED_SERVICES:
            if not all_map or sid in all_map:
                services.append(
                    {
                        "id": sid,
                        "name": all_map.get(sid, sid.capitalize()),
                        "blocked": sid in active_set,
                    }
                )
        payload = {"services": services, "active_ids": active_ids}
        self._services_cache = (time.monotonic(), payload)
        return payload

    def _apply_blocked_services_to_cache(self, normalized_ids: List[str]) -> None:
        """Reflect desired blocked service IDs in short-lived memory caches immediately."""
        active_set = set(normalized_ids)
        now = time.monotonic()
        _, cached_svcs = self._services_cache
        if cached_svcs is not None and isinstance(cached_svcs.get("services"), list):
            updated_svcs = [
                {**svc, "blocked": str(svc.get("id") or "").lower() in active_set}
                for svc in cached_svcs["services"]
            ]
            self._services_cache = (now, {"services": updated_svcs, "active_ids": list(normalized_ids)})
        _, cached_ov = self._overview_cache
        if cached_ov is not None:
            updated_ov = dict(cached_ov)
            updated_ov["blocked_service_ids"] = list(normalized_ids)
            self._overview_cache = (now, updated_ov)

    async def _apply_blocked_services_now(self, normalized_ids: List[str]) -> None:
        await self._require_session()
        async with self._make_client() as client:
            schedule = self._blocked_services_schedule
            if schedule is None:
                r_get = await self._request(client, "get", "/control/blocked_services/get")
                schedule = {"time_zone": "UTC"}
                if r_get.status_code == 200 and isinstance(r_get.json(), dict):
                    schedule = r_get.json().get("schedule") or schedule
                self._blocked_services_schedule = schedule
            resp = await self._request(
                client,
                "put",
                "/control/blocked_services/update",
                json={"ids": normalized_ids, "schedule": schedule},
            )
            if resp.status_code in (404, 405):
                resp = await self._request(client, "post", "/control/blocked_services/set", json=normalized_ids)
            if resp.status_code not in (200, 204):
                raise AdGuardError(f"Failed to update blocked services: HTTP {resp.status_code}")

            # Sync enforced $important rules for active blocked services so regional/EU failovers
            # (e.g. tiktokv.eu, byteeffecttos-g.com) and @@|| user exceptions cannot bypass the block.
            filt_resp = await self._request(client, "get", "/control/filtering/status")
            if filt_resp.status_code == 200 and isinstance(filt_resp.json(), dict):
                raw_rules = [str(r) for r in (filt_resp.json().get("user_rules") or [])]
                manual_rules = _filter_visible_user_rules(raw_rules)
                enforced_rules = _build_service_enforced_rules(normalized_ids)
                merged_rules = enforced_rules + manual_rules
                if merged_rules != raw_rules:
                    r_set = await self._request(
                        client,
                        "post",
                        "/control/filtering/set_rules",
                        json={"rules": merged_rules},
                    )
                    if r_set.status_code not in (200, 204):
                        raise AdGuardError(f"Failed to sync enforced service rules: HTTP {r_set.status_code}")

            await self._clear_cache_best_effort(client)

    async def _drain_blocked_services_worker(self) -> None:
        """Coalescing background worker that applies the latest desired blocked service IDs."""
        try:
            while self._desired_service_ids is not None:
                target_ids = list(self._desired_service_ids)
                await self._apply_blocked_services_now(target_ids)
                if self._desired_service_ids == target_ids:
                    self._desired_service_ids = None
                    break
        except Exception as exc:
            logger.warning("Background blocked_services sync failed: %s", exc)
            self._desired_service_ids = None
        finally:
            self.invalidate_cache()
            self._services_worker_task = None

    async def set_blocked_services(
        self,
        ids: List[str],
        *,
        background: bool = False,
    ) -> Dict[str, Any]:
        normalized_ids = [str(x).strip().lower() for x in ids if str(x).strip()]
        if background:
            self._desired_service_ids = list(normalized_ids)
            self._apply_blocked_services_to_cache(normalized_ids)
            if self._services_worker_task is None or self._services_worker_task.done():
                self._services_worker_task = asyncio.create_task(self._drain_blocked_services_worker())
            return {"success": True, "ids": normalized_ids, "queued": True}

        self._desired_service_ids = None
        await self._apply_blocked_services_now(normalized_ids)
        self.invalidate_cache()
        return {"success": True, "ids": normalized_ids}

    async def refresh_filters(self) -> Dict[str, Any]:
        await self._require_session()
        async with self._make_client(timeout=15.0) as client:
            resp = await self._request(client, "post", "/control/filtering/refresh", json={"whitelist": False})
            if resp.status_code not in (200, 204):
                raise AdGuardError(f"Failed to refresh filters: HTTP {resp.status_code}")
            updated = resp.json().get("updated", 0) if resp.content else 0
        self.invalidate_cache()
        return {"success": True, "updated": updated}

    async def clear_cache(self) -> Dict[str, Any]:
        await self._require_session()
        async with self._make_client() as client:
            resp = await self._request(client, "post", "/control/cache_clear")
            if resp.status_code not in (200, 204):
                raise AdGuardError(f"Failed to clear DNS cache: HTTP {resp.status_code}")
        return {"success": True}

    async def get_rewrites(self) -> List[Dict[str, str]]:
        await self._require_session()
        async with self._make_client() as client:
            resp = await self._request(client, "get", "/control/rewrite/list")
            if resp.status_code != 200:
                raise AdGuardError("Failed to fetch DNS rewrites")
            return [
                {"domain": str(item.get("domain") or ""), "answer": str(item.get("answer") or "")}
                for item in (resp.json() or [])
            ]

    async def add_rewrite(self, domain: str, answer: str) -> Dict[str, Any]:
        await self._require_session()
        async with self._make_client() as client:
            resp = await self._request(client, "post", "/control/rewrite/add", json={"domain": domain, "answer": answer})
            if resp.status_code not in (200, 204):
                raise AdGuardError(f"Failed to add DNS rewrite: HTTP {resp.status_code}")
        return {"success": True, "domain": domain, "answer": answer}

    async def delete_rewrite(self, domain: str, answer: str) -> Dict[str, Any]:
        await self._require_session()
        async with self._make_client() as client:
            resp = await self._request(client, "post", "/control/rewrite/delete", json={"domain": domain, "answer": answer})
            if resp.status_code not in (200, 204):
                raise AdGuardError(f"Failed to delete DNS rewrite: HTTP {resp.status_code}")
        return {"success": True, "domain": domain, "answer": answer}


adguard_client = AdGuardClient()
