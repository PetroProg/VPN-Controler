"""FastAPI entrypoint for the standalone mobile-first VPN Controler PWA."""

import asyncio
import logging
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.schemas import (
    BlockedServicesPayload,
    DomainPayload,
    PausePayload,
    PeerPingPayload,
    RewritePayload,
    ToggleFeaturePayload,
    UpstreamPayload,
    UserRuleAddPayload,
    UserRuleDeletePayload,
)
from app.services.adguard import AdGuardError, adguard_client
from app.services.tailscale import tailscale_client

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vpn_controler.api")

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"

app = FastAPI(
    title="VPN Controler",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
)

if (WEB_DIR / "css").exists():
    app.mount("/css", StaticFiles(directory=str(WEB_DIR / "css")), name="css")
if (WEB_DIR / "js").exists():
    app.mount("/js", StaticFiles(directory=str(WEB_DIR / "js")), name="js")
if (WEB_DIR / "icons").exists():
    app.mount("/icons", StaticFiles(directory=str(WEB_DIR / "icons")), name="icons")


def _serve_html(filename: str) -> HTMLResponse:
    target = WEB_DIR / filename
    if not target.exists():
        return HTMLResponse(f"<h1>{filename} not found</h1>", status_code=404)
    return HTMLResponse(
        content=target.read_text(encoding="utf-8"),
        headers={"Cache-Control": "no-cache"},
    )


@app.get("/", response_class=HTMLResponse)
@app.get("/vpn", response_class=HTMLResponse)
async def page_home() -> HTMLResponse:
    return _serve_html("index.html")


@app.get("/settings", response_class=HTMLResponse)
async def page_settings() -> HTMLResponse:
    return _serve_html("settings.html")


@app.get("/manifest.webmanifest")
@app.get("/manifest.json")
async def serve_manifest() -> FileResponse:
    return FileResponse(
        path=str(WEB_DIR / "manifest.webmanifest"),
        media_type="application/manifest+json",
        headers={"Cache-Control": "no-cache"},
    )


@app.get("/sw.js")
async def serve_sw() -> FileResponse:
    return FileResponse(
        path=str(WEB_DIR / "sw.js"),
        media_type="application/javascript",
        headers={
            "Service-Worker-Allowed": "/",
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )


@app.get("/favicon.ico")
async def serve_favicon() -> FileResponse:
    return FileResponse(path=str(WEB_DIR / "icons" / "favicon.svg"), media_type="image/svg+xml")


@app.get("/apple-touch-icon.png")
async def serve_apple_icon() -> FileResponse:
    return FileResponse(path=str(WEB_DIR / "icons" / "apple-touch-icon.png"), media_type="image/png")


@app.get("/api/health")
async def api_health() -> Dict[str, Any]:
    adg_ok, ts_ok = await asyncio.gather(
        adguard_client.check_health(),
        tailscale_client.check_health(),
    )
    return {
        "status": "ok",
        "version": "1.0.0",
        "adguard_online": adg_ok,
        "tailscale_online": ts_ok,
    }


@app.get("/api/meta")
async def api_meta() -> Dict[str, Any]:
    return {
        "host_lan_ip": settings.HOST_LAN_IP,
        "host_tailscale_ip": settings.HOST_TAILSCALE_IP,
        "tailscale_dns_name": settings.TAILSCALE_DNS_NAME,
        "adguard_public_port": settings.ADGUARD_PUBLIC_PORT,
        "https_pwa_url": settings.HTTPS_PWA_URL,
    }


@app.get("/api/vpn/status")
async def api_vpn_status() -> Dict[str, Any]:
    return await tailscale_client.get_status()


@app.get("/api/vpn/traffic")
async def api_vpn_traffic() -> Dict[str, Any]:
    return await tailscale_client.get_traffic()


@app.post("/api/vpn/ping")
async def api_vpn_ping(payload: PeerPingPayload, force: bool = Query(default=True)) -> Dict[str, Any]:
    try:
        return await tailscale_client.ping_peer(payload.ip, force=force)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/dns/overview")
async def api_dns_overview() -> Dict[str, Any]:
    return await adguard_client.get_overview(ip_name_map=tailscale_client.get_ip_name_map())


@app.post("/api/dns/toggle")
async def api_dns_toggle(payload: ToggleFeaturePayload) -> Dict[str, Any]:
    try:
        return await adguard_client.toggle_feature(payload.feature, payload.enabled)
    except AdGuardError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        logger.warning("Toggle %s failed: %s", payload.feature, exc)
        raise HTTPException(status_code=502, detail="AdGuard Home unavailable") from exc


@app.post("/api/dns/pause")
async def api_dns_pause(payload: PausePayload) -> Dict[str, Any]:
    try:
        return await adguard_client.pause_protection(payload.minutes)
    except Exception as exc:
        logger.warning("Pause failed: %s", exc)
        raise HTTPException(status_code=502, detail="AdGuard Home unavailable") from exc


@app.post("/api/dns/upstream")
async def api_dns_upstream(payload: UpstreamPayload) -> Dict[str, Any]:
    try:
        return await adguard_client.set_upstream(payload.provider)
    except Exception as exc:
        logger.warning("Set upstream failed: %s", exc)
        raise HTTPException(status_code=502, detail="AdGuard Home unavailable") from exc


@app.get("/api/dns/doh-latency")
async def api_dns_doh_latency(force: bool = Query(default=False)) -> Dict[str, Any]:
    latencies = await adguard_client.probe_doh_latencies(force=force)
    return {"latencies": latencies}


@app.get("/api/dns/querylog")
async def api_dns_querylog(
    limit: int = Query(default=50, ge=1, le=200),
    filter: str = Query(default="all"),
    search: str = Query(default="", max_length=120),
    client: str = Query(default="", max_length=80),
) -> Dict[str, Any]:
    if filter not in ("all", "blocked", "allowed"):
        raise HTTPException(status_code=400, detail="Invalid filter")
    try:
        return await adguard_client.get_querylog(
            limit=limit,
            status_filter=filter,
            search=search,
            client_filter=client,
            ip_name_map=tailscale_client.get_ip_name_map(),
        )
    except Exception as exc:
        logger.warning("Querylog error: %s", exc)
        return {"success": False, "logs": [], "total": 0}


@app.post("/api/dns/block")
async def api_dns_block(payload: DomainPayload) -> Dict[str, Any]:
    try:
        return await adguard_client.block_domain(payload.domain)
    except Exception as exc:
        logger.warning("Block domain failed: %s", exc)
        raise HTTPException(status_code=502, detail="AdGuard Home unavailable") from exc


@app.post("/api/dns/unblock")
async def api_dns_unblock(payload: DomainPayload) -> Dict[str, Any]:
    try:
        return await adguard_client.unblock_domain(payload.domain)
    except Exception as exc:
        logger.warning("Unblock domain failed: %s", exc)
        raise HTTPException(status_code=502, detail="AdGuard Home unavailable") from exc


@app.get("/api/dns/rules")
async def api_dns_rules_get() -> Dict[str, Any]:
    try:
        rules = await adguard_client.get_rules()
        return {"rules": rules}
    except Exception as exc:
        raise HTTPException(status_code=502, detail="AdGuard Home unavailable") from exc


@app.post("/api/dns/rules")
async def api_dns_rules_add(payload: UserRuleAddPayload) -> Dict[str, Any]:
    try:
        return await adguard_client.add_rule(payload.domain, payload.mode)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="AdGuard Home unavailable") from exc


@app.delete("/api/dns/rules")
async def api_dns_rules_delete(payload: UserRuleDeletePayload) -> Dict[str, Any]:
    try:
        return await adguard_client.delete_rule(payload.rule)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="AdGuard Home unavailable") from exc


@app.get("/api/dns/services")
async def api_dns_services_get() -> Dict[str, Any]:
    try:
        return await adguard_client.get_blocked_services()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="AdGuard Home unavailable") from exc


@app.put("/api/dns/services")
async def api_dns_services_put(payload: BlockedServicesPayload) -> Dict[str, Any]:
    try:
        return await adguard_client.set_blocked_services(payload.ids)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="AdGuard Home unavailable") from exc


@app.post("/api/dns/filters/refresh")
async def api_dns_filters_refresh() -> Dict[str, Any]:
    try:
        return await adguard_client.refresh_filters()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="AdGuard Home unavailable") from exc


@app.post("/api/dns/cache/clear")
async def api_dns_cache_clear() -> Dict[str, Any]:
    try:
        return await adguard_client.clear_cache()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="AdGuard Home unavailable") from exc


@app.get("/api/dns/rewrites")
async def api_dns_rewrites_get() -> Dict[str, Any]:
    try:
        rewrites = await adguard_client.get_rewrites()
        return {"rewrites": rewrites}
    except Exception as exc:
        raise HTTPException(status_code=502, detail="AdGuard Home unavailable") from exc


@app.post("/api/dns/rewrites")
async def api_dns_rewrites_add(payload: RewritePayload) -> Dict[str, Any]:
    try:
        return await adguard_client.add_rewrite(payload.domain, payload.answer)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="AdGuard Home unavailable") from exc


@app.delete("/api/dns/rewrites")
async def api_dns_rewrites_delete(payload: RewritePayload) -> Dict[str, Any]:
    try:
        return await adguard_client.delete_rewrite(payload.domain, payload.answer)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="AdGuard Home unavailable") from exc
