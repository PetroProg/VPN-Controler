"""Async client for Tailscale LocalAPI via Unix domain socket."""

from collections import deque
from datetime import datetime, timezone
import logging
from pathlib import Path
import time
from typing import Any, Deque, Dict, List, Optional, Tuple
import httpx

from app.config import settings

logger = logging.getLogger("vpn_controler.tailscale")

FRIENDLY_HOSTNAMES: Dict[str, str] = {
    "desktop-na86l48": "Основной ПК",
    "desktop-be94guv": "DESKTOP-BE94GUV",
    "samsung a54": "Samsung A54",
    "samsung-a54": "Samsung A54",
    "asusvbook": "AsusVBook",
    "fedora": "Fedora-Server",
    "nokia 6": "Nokia 6",
    "nokia-6": "Nokia 6",
    "petroprog": "Сервер petroprog",
}

STATIC_IP_NAMES: Dict[str, str] = {
    "192.168.178.65": "Сервер petroprog",
    "100.107.4.120": "Сервер petroprog",
    "192.168.178.39": "Основной ПК",
    "100.114.251.81": "Основной ПК",
    "100.82.14.22": "DESKTOP-BE94GUV",
    "100.109.120.0": "DESKTOP-BE94GUV",
    "192.168.178.38": "Samsung A54",
    "100.76.188.111": "Samsung A54",
    "100.101.184.122": "AsusVBook",
    "100.73.208.121": "Fedora-Server",
    "100.109.24.95": "Nokia 6",
    "192.168.178.1": "FRITZ!Box",
}


def _format_relative_time(iso_str: str, online: bool) -> str:
    if online:
        return "Онлайн"
    if not iso_str or iso_str.startswith("0001-"):
        return "—"
    try:
        cleaned = iso_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta_sec = max(0, int((datetime.now(timezone.utc) - dt).total_seconds()))
        if delta_sec < 60:
            return "Только что"
        if delta_sec < 3600:
            return f"{delta_sec // 60} мин назад"
        if delta_sec < 86400:
            return f"{delta_sec // 3600} ч назад"
        return f"{delta_sec // 86400} д назад"
    except Exception:
        return "—"


class TailscaleClient:
    """Thread-safe async wrapper over tailscaled LocalAPI Unix socket."""

    def __init__(self, sock_path: Optional[str] = None) -> None:
        self.sock_path = sock_path or settings.TAILSCALE_SOCK_PATH
        self._ping_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._raw_status_cache: Tuple[float, Optional[Dict[str, Any]]] = (0.0, None)
        self._last_traffic: Optional[Tuple[float, int, int]] = None
        self._rx_history: Deque[float] = deque([0.0] * 24, maxlen=24)
        self._tx_history: Deque[float] = deque([0.0] * 24, maxlen=24)
        self._cached_ip_names: Dict[str, str] = dict(STATIC_IP_NAMES)

    def _make_client(self) -> httpx.AsyncClient:
        transport = httpx.AsyncHTTPTransport(uds=self.sock_path)
        return httpx.AsyncClient(
            transport=transport,
            base_url="http://local-tailscaled.sock",
            timeout=settings.TAILSCALE_TIMEOUT_SECONDS,
        )

    async def _fetch_raw_status(self, *, force: bool = False) -> Optional[Dict[str, Any]]:
        now = time.monotonic()
        cached_ts, cached_data = self._raw_status_cache
        if not force and cached_data is not None and (now - cached_ts) < 1.5:
            return cached_data

        if not Path(self.sock_path).exists():
            return None
        try:
            async with self._make_client() as client:
                resp = await client.get("/localapi/v0/status")
                if resp.status_code == 200:
                    payload = resp.json()
                    self._raw_status_cache = (time.monotonic(), payload)
                    return payload
        except Exception as exc:
            logger.warning("Tailscale status fetch failed: %s", exc)
        return None

    async def check_health(self) -> bool:
        data = await self._fetch_raw_status()
        if not data:
            return False
        return data.get("BackendState") == "Running"

    def _get_cached_ping(self, ip: str) -> Optional[float]:
        entry = self._ping_cache.get(ip)
        if not entry:
            return None
        ts, payload = entry
        if (time.monotonic() - ts) <= 300:
            return payload.get("latency_ms")
        return None

    async def get_status(self) -> Dict[str, Any]:
        """Return live Tailscale mesh status, self node info, and peer cards."""
        data = await self._fetch_raw_status()
        if not data:
            return {
                "online": False,
                "backend_state": "Unavailable",
                "version": "",
                "health": ["Tailscale LocalAPI socket unavailable"],
                "self": {
                    "hostname": "petroprog",
                    "ip": settings.HOST_TAILSCALE_IP,
                    "dns_name": settings.TAILSCALE_DNS_NAME,
                    "os": "linux",
                    "relay": "",
                    "online": False,
                },
                "lan_ip": settings.HOST_LAN_IP,
                "encryption": "ChaCha20-Poly1305 (WireGuard)",
                "peers_count": 0,
                "peers_online": 0,
                "peers": [],
            }

        self_node = data.get("Self") or {}
        ts_ips = self_node.get("TailscaleIPs") or [settings.HOST_TAILSCALE_IP]
        primary_ip = next((ip for ip in ts_ips if ":" not in ip), ts_ips[0])
        self_dns = (self_node.get("DNSName") or settings.TAILSCALE_DNS_NAME).rstrip(".")

        peers_list: List[Dict[str, Any]] = []
        online_count = 0
        ip_names = dict(STATIC_IP_NAMES)

        for peer_data in (data.get("Peer") or {}).values():
            hname = peer_data.get("HostName") or "unknown"
            display_name = FRIENDLY_HOSTNAMES.get(hname.lower(), hname)
            is_online = bool(peer_data.get("Online", False))
            if is_online:
                online_count += 1
            p_ips = peer_data.get("TailscaleIPs") or []
            p_ip = next((ip for ip in p_ips if ":" not in ip), p_ips[0] if p_ips else "")
            if p_ip:
                ip_names[p_ip] = display_name

            cur_addr = peer_data.get("CurAddr") or ""
            relay = peer_data.get("Relay") or ""
            direct = bool(cur_addr)
            if not is_online:
                mode = "Offline"
            elif direct:
                mode = "Direct P2P"
            elif relay:
                mode = f"DERP {relay}"
            else:
                mode = "Mesh"

            rx_bytes = int(peer_data.get("RxBytes") or 0)
            tx_bytes = int(peer_data.get("TxBytes") or 0)
            last_seen_raw = peer_data.get("LastSeen") or ""

            peers_list.append(
                {
                    "id": peer_data.get("ID") or hname,
                    "hostname": hname,
                    "display_name": display_name,
                    "ip": p_ip,
                    "dns_name": (peer_data.get("DNSName") or "").rstrip("."),
                    "os": (peer_data.get("OS") or "").lower(),
                    "online": is_online,
                    "active": bool(peer_data.get("Active", False)),
                    "direct": direct,
                    "cur_addr": cur_addr,
                    "relay": relay,
                    "mode": mode,
                    "rx_bytes": rx_bytes,
                    "tx_bytes": tx_bytes,
                    "rx_mb": round(rx_bytes / (1024**2), 1),
                    "tx_mb": round(tx_bytes / (1024**2), 1),
                    "last_seen": last_seen_raw,
                    "last_seen_label": _format_relative_time(last_seen_raw, is_online),
                    "ping_ms": self._get_cached_ping(p_ip) if (p_ip and is_online) else None,
                }
            )

        self._cached_ip_names = ip_names
        peers_list.sort(key=lambda item: (not item["online"], item["display_name"].lower()))

        raw_version = str(data.get("Version") or "")
        short_version = raw_version.split("-")[0] if raw_version else ""

        return {
            "online": data.get("BackendState") == "Running",
            "backend_state": data.get("BackendState") or "Unknown",
            "version": short_version,
            "health": data.get("Health") or [],
            "self": {
                "hostname": self_node.get("HostName") or "petroprog",
                "ip": primary_ip,
                "dns_name": self_dns,
                "os": (self_node.get("OS") or "linux").lower(),
                "relay": self_node.get("Relay") or "",
                "online": bool(self_node.get("Online", True)),
            },
            "lan_ip": settings.HOST_LAN_IP,
            "encryption": "ChaCha20-Poly1305 (WireGuard)",
            "peers_count": len(peers_list),
            "peers_online": online_count,
            "peers": peers_list,
        }

    async def get_traffic(self) -> Dict[str, Any]:
        """Calculate real RX/TX delta throughput across Tailscale Mesh peers."""
        now = time.monotonic()
        data = await self._fetch_raw_status()

        total_rx = 0
        total_tx = 0
        if data:
            for peer_data in (data.get("Peer") or {}).values():
                total_rx += int(peer_data.get("RxBytes") or 0)
                total_tx += int(peer_data.get("TxBytes") or 0)

        rx_kbps = 0.0
        tx_kbps = 0.0
        if self._last_traffic is not None:
            prev_ts, prev_rx, prev_tx = self._last_traffic
            dt = max(0.5, now - prev_ts)
            delta_rx = max(0, total_rx - prev_rx)
            delta_tx = max(0, total_tx - prev_tx)
            rx_kbps = round((delta_rx * 8.0) / (dt * 1000.0), 1)
            tx_kbps = round((delta_tx * 8.0) / (dt * 1000.0), 1)

        if data is not None:
            self._last_traffic = (now, total_rx, total_tx)

        self._rx_history.append(rx_kbps)
        self._tx_history.append(tx_kbps)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rx_kbps": rx_kbps,
            "tx_kbps": tx_kbps,
            "rx_mbps": round(rx_kbps / 1000.0, 2),
            "tx_mbps": round(tx_kbps / 1000.0, 2),
            "total_rx_mb": round(total_rx / (1024**2), 1),
            "total_tx_mb": round(total_tx / (1024**2), 1),
            "history_rx": list(self._rx_history),
            "history_tx": list(self._tx_history),
        }

    async def ping_peer(self, ip: str, force: bool = False) -> Dict[str, Any]:
        """Measure real RTT to a Tailscale peer via LocalAPI disco ping."""
        now = time.monotonic()
        if not force and ip in self._ping_cache:
            ts, cached = self._ping_cache[ip]
            if (now - ts) < settings.TAILSCALE_PING_CACHE_SECONDS:
                return {**cached, "cached": True}

        if not Path(self.sock_path).exists():
            raise RuntimeError("Tailscale socket unavailable")

        async with self._make_client() as client:
            resp = await client.post("/localapi/v0/ping", params={"ip": ip, "type": "disco"})
            if resp.status_code != 200:
                raise RuntimeError(f"Tailscale ping HTTP {resp.status_code}")
            payload = resp.json()

        err_msg = payload.get("Err") or ""
        if err_msg:
            return {
                "success": False,
                "ip": ip,
                "error": err_msg,
                "latency_ms": None,
                "direct": False,
                "mode": "Unreachable",
                "cached": False,
            }

        latency_ms = round(float(payload.get("LatencySeconds") or 0.0) * 1000.0, 1)
        endpoint = payload.get("Endpoint") or ""
        derp = payload.get("DERPRegionCode") or ""
        direct = bool(endpoint)
        mode = "Direct P2P" if direct else (f"DERP {derp}" if derp else "Mesh")

        result = {
            "success": True,
            "ip": ip,
            "node_name": payload.get("NodeName") or "",
            "latency_ms": latency_ms,
            "direct": direct,
            "endpoint": endpoint,
            "derp_region": derp,
            "mode": mode,
            "cached": False,
        }
        self._ping_cache[ip] = (now, result)
        return result

    def get_ip_name_map(self) -> Dict[str, str]:
        return dict(self._cached_ip_names)


tailscale_client = TailscaleClient()
