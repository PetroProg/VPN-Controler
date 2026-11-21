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

    def _make_client(self, timeout: Optional[float] = None) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=settings.ADGUARD_URL,
            auth=(settings.ADGUARD_USER, settings.ADGUARD_PASSWORD),
            timeout=timeout or settings.ADGUARD_TIMEOUT_SECONDS,
        )

    async def check_health(self) -> bool:
        try:
            async with self._make_client(timeout=3.0) as client:
                resp = await client.get("/control/status")
                return resp.status_code == 200
        except Exception:
            return False

    async def get_overview(self, ip_name_map: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Fetch full dashboard overview (status, 24h stats, toggles, rules, filters)."""
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

        try:
            async with self._make_client() as client:
                resps = await asyncio.gather(
                    client.get("/control/status"),
                    client.get("/control/stats"),
                    client.get("/control/filtering/status"),
                    client.get("/control/safebrowsing/status"),
                    client.get("/control/safesearch/status"),
                    client.get("/control/parental/status"),
                    client.get("/control/dns_info"),
                    client.get("/control/blocked_services/get"),
                    return_exceptions=True,
                )
        except Exception as exc:
            logger.warning("AdGuard overview error: %s", exc)
            return result

        r_stat, r_stats, r_filt, r_safe, r_ss, r_par, r_dns, r_svcs = resps

        if not isinstance(r_stat, Exception) and r_stat.status_code == 200:
            sj = r_stat.json()
            result["online"] = True
            result["running"] = bool(sj.get("running", True))
            result["version"] = str(sj.get("version", ""))
            result["protection"] = bool(sj.get("protection_enabled", True))
            result["protection_disabled_duration_ms"] = int(sj.get("protection_disabled_duration") or 0)

        if not isinstance(r_stats, Exception) and r_stats.status_code == 200:
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
            result["user_rules"] = [str(r) for r in (fj.get("user_rules") or [])]
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
            elif isinstance(sv, list):
                result["blocked_service_ids"] = list(sv)

        return result

    async def toggle_feature(self, feature: str, enabled: bool) -> Dict[str, Any]:
        async with self._make_client() as client:
            if feature == "protection":
                resp = await client.post("/control/protection", json={"enabled": enabled})
            elif feature == "adblock":
                f_resp = await client.get("/control/filtering/status")
                interval = 24
                if f_resp.status_code == 200:
                    interval = int(f_resp.json().get("interval") or 24)
                resp = await client.post(
                    "/control/filtering/config",
                    json={"enabled": enabled, "interval": interval},
                )
            elif feature == "malware":
                ep = "enable" if enabled else "disable"
                resp = await client.post(f"/control/safebrowsing/{ep}")
            elif feature == "parental":
                ep = "enable" if enabled else "disable"
                resp = await client.post(f"/control/parental/{ep}")
            elif feature == "safesearch":
                ss_resp = await client.get("/control/safesearch/status")
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
                resp = await client.put("/control/safesearch/settings", json=payload)
                if resp.status_code in (404, 405):
                    ep = "enable" if enabled else "disable"
                    resp = await client.post(f"/control/safesearch/{ep}")
            elif feature == "doh":
                info_resp = await client.get("/control/dns_info")
                if info_resp.status_code != 200:
                    raise AdGuardError("Failed to fetch dns_info")
                cfg = info_resp.json()
                provider = _detect_provider(cfg.get("upstream_dns") or [])
                cfg["upstream_dns"] = _build_upstreams(provider, enabled)
                resp = await client.post("/control/dns_config", json=cfg)
            else:
                raise ValueError(f"Unsupported feature: {feature}")

            if resp.status_code not in (200, 204):
                raise AdGuardError(f"AdGuard returned HTTP {resp.status_code}")

        return {"success": True, "feature": feature, "enabled": enabled}

    async def pause_protection(self, minutes: int) -> Dict[str, Any]:
        duration_ms = minutes * 60 * 1000
        async with self._make_client() as client:
            resp = await client.post(
                "/control/protection",
                json={"enabled": False, "duration": duration_ms},
            )
            if resp.status_code not in (200, 204):
                resp = await client.post("/control/protection", json={"enabled": False})
                if resp.status_code not in (200, 204):
                    raise AdGuardError(f"Failed to pause protection: HTTP {resp.status_code}")
        return {"success": True, "paused": True, "minutes": minutes, "duration_ms": duration_ms}

    async def set_upstream(self, provider: str) -> Dict[str, Any]:
        if provider not in UPSTREAM_PRESETS:
            raise ValueError(f"Unknown upstream provider: {provider}")
        async with self._make_client() as client:
            info_resp = await client.get("/control/dns_info")
            if info_resp.status_code != 200:
                raise AdGuardError("Failed to fetch dns_info")
            cfg = info_resp.json()
            cur_up = [str(u) for u in (cfg.get("upstream_dns") or [])]
            doh_enabled = any(u.startswith("https://") for u in cur_up) if cur_up else True
            new_upstreams = _build_upstreams(provider, doh_enabled)
            cfg["upstream_dns"] = new_upstreams
            cfg["bootstrap_dns"] = ["1.1.1.1", "9.9.9.9"]
            resp = await client.post("/control/dns_config", json=cfg)
            if resp.status_code not in (200, 204):
                raise AdGuardError(f"Failed to update dns_config: HTTP {resp.status_code}")
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

        async with self._make_client() as client:
            r_log, r_filt = await asyncio.gather(
                client.get("/control/querylog", params=params),
                client.get("/control/filtering/status"),
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
                if f"||{dom_low}^" in user_rules or dom_low in user_rules:
                    source = "user_rule"
                    reason_label = "Ручное правило"
                elif "Parental" in reason:
                    source = "parental"
                    reason_label = "Родительский контроль"
                elif "SafeBrowsing" in reason:
                    source = "safebrowsing"
                    reason_label = "Фишинг / Угроза"
                elif "BlockedService" in reason:
                    source = "blocked_service"
                    reason_label = "Блокировка сервиса"
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

    async def _set_user_rules(self, client: httpx.AsyncClient, rules: List[str]) -> None:
        resp = await client.post("/control/filtering/set_rules", json={"rules": rules})
        if resp.status_code not in (200, 204):
            raise AdGuardError(f"Failed to set filtering rules: HTTP {resp.status_code}")

    async def block_domain(self, domain: str) -> Dict[str, Any]:
        rule = f"||{domain}^"
        allow_variants = {f"@@||{domain}^", f"@@||{domain}^|"}
        async with self._make_client() as client:
            filt_resp = await client.get("/control/filtering/status")
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
        block_variants = {f"||{domain}^", domain}
        allow_rule = f"@@||{domain}^"
        async with self._make_client() as client:
            filt_resp = await client.get("/control/filtering/status")
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
        async with self._make_client() as client:
            resp = await client.get("/control/filtering/status")
            if resp.status_code != 200:
                raise AdGuardError("Failed to fetch filtering rules")
            return [str(r) for r in (resp.json().get("user_rules") or [])]

    async def add_rule(self, domain: str, mode: str) -> Dict[str, Any]:
        if mode == "allow":
            rule = f"@@||{domain}^"
            remove_set = {f"||{domain}^", domain}
        else:
            rule = f"||{domain}^"
            remove_set = {f"@@||{domain}^", f"@@||{domain}^|"}

        async with self._make_client() as client:
            resp = await client.get("/control/filtering/status")
            if resp.status_code != 200:
                raise AdGuardError("Failed to fetch filtering rules")
            rules = [str(r) for r in (resp.json().get("user_rules") or [])]
            updated = [r for r in rules if r.strip().lower() not in remove_set]
            if rule not in {r.strip().lower() for r in updated}:
                updated.insert(0, rule)
            await self._set_user_rules(client, updated)
        return {"success": True, "rule": rule, "rules": updated}

    async def delete_rule(self, rule: str) -> Dict[str, Any]:
        target = rule.strip()
        async with self._make_client() as client:
            resp = await client.get("/control/filtering/status")
            if resp.status_code != 200:
                raise AdGuardError("Failed to fetch filtering rules")
            rules = [str(r) for r in (resp.json().get("user_rules") or [])]
            updated = [r for r in rules if r.strip() != target]
            await self._set_user_rules(client, updated)
        return {"success": True, "removed": target, "rules": updated}

    async def get_blocked_services(self) -> Dict[str, Any]:
        async with self._make_client() as client:
            r_all, r_get = await asyncio.gather(
                client.get("/control/blocked_services/all"),
                client.get("/control/blocked_services/get"),
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
            elif isinstance(body, list):
                active_ids = [str(x).lower() for x in body]

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
        return {"services": services, "active_ids": active_ids}

    async def set_blocked_services(self, ids: List[str]) -> Dict[str, Any]:
        async with self._make_client() as client:
            r_get = await client.get("/control/blocked_services/get")
            schedule = {"time_zone": "UTC"}
            if r_get.status_code == 200 and isinstance(r_get.json(), dict):
                schedule = r_get.json().get("schedule") or schedule
            resp = await client.put(
                "/control/blocked_services/update",
                json={"ids": ids, "schedule": schedule},
            )
            if resp.status_code in (404, 405):
                resp = await client.post("/control/blocked_services/set", json=ids)
            if resp.status_code not in (200, 204):
                raise AdGuardError(f"Failed to update blocked services: HTTP {resp.status_code}")
        return {"success": True, "ids": ids}

    async def refresh_filters(self) -> Dict[str, Any]:
        async with self._make_client(timeout=15.0) as client:
            resp = await client.post("/control/filtering/refresh", json={"whitelist": False})
            if resp.status_code not in (200, 204):
                raise AdGuardError(f"Failed to refresh filters: HTTP {resp.status_code}")
            updated = resp.json().get("updated", 0) if resp.content else 0
        return {"success": True, "updated": updated}

    async def clear_cache(self) -> Dict[str, Any]:
        async with self._make_client() as client:
            resp = await client.post("/control/cache_clear")
            if resp.status_code not in (200, 204):
                raise AdGuardError(f"Failed to clear DNS cache: HTTP {resp.status_code}")
        return {"success": True}

    async def get_rewrites(self) -> List[Dict[str, str]]:
        async with self._make_client() as client:
            resp = await client.get("/control/rewrite/list")
            if resp.status_code != 200:
                raise AdGuardError("Failed to fetch DNS rewrites")
            return [
                {"domain": str(item.get("domain") or ""), "answer": str(item.get("answer") or "")}
                for item in (resp.json() or [])
            ]

    async def add_rewrite(self, domain: str, answer: str) -> Dict[str, Any]:
        async with self._make_client() as client:
            resp = await client.post("/control/rewrite/add", json={"domain": domain, "answer": answer})
            if resp.status_code not in (200, 204):
                raise AdGuardError(f"Failed to add DNS rewrite: HTTP {resp.status_code}")
        return {"success": True, "domain": domain, "answer": answer}

    async def delete_rewrite(self, domain: str, answer: str) -> Dict[str, Any]:
        async with self._make_client() as client:
            resp = await client.post("/control/rewrite/delete", json={"domain": domain, "answer": answer})
            if resp.status_code not in (200, 204):
                raise AdGuardError(f"Failed to delete DNS rewrite: HTTP {resp.status_code}")
        return {"success": True, "domain": domain, "answer": answer}


adguard_client = AdGuardClient()
