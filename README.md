# VPN Controler (Mobile-First PWA)

Standalone homelab **Tailscale Mesh & AdGuard Home DNS Shield** control center (`:8086`, HTTPS via Tailscale Serve `:8446`).

## Features
- **2 Mobile-First Pages**:
  - **Главная (`/`, `/vpn`)**: Shield-First Hero with live countdown pause (`5 / 15 / 60 min`), 2x2 Bento KPIs, and 3 segments:
    - **Сеть**: Dual-mode Canvas chart (live Tailscale Mesh RX/TX deltas vs 24h DNS queries/blocks), tap-to-expand peer cards with real `Direct P2P` / `DERP` mode & live `localapi/v0/ping`, and 24h top domains/clients.
    - **Лог DNS**: Live search, status/client filters, manual quick-rule form, and 1-tap smart block/unblock (`||domain^` vs `@@||domain^`).
    - **Щит**: Separate toggles (`AdBlocker`, `Malware/SafeBrowsing`, `DoH`, `SafeSearch`, `Parental`), upstream DoH gateway switcher with live RTT probing, and 1-tap blocked services.
  - **Настройки (`/settings`)**: 4 non-blue theme presets (`Warm Paper` default, `Emerald Tactical`, `Obsidian Amber`, `Matte Copper`), density (`Standard` / `Compact`), auto-refresh intervals, `RU / EN` language, `CET / UTC` clock, AdGuard user rules manager, filter list refresh, DNS cache clear, local DNS rewrites (`*.home`), node info, and PWA install/SW cache reset.
- **Security by Design**:
  - Non-root container (`USER appuser`, `UID 1000`), pinned base image (`python:3.12-slim-bookworm`) and AdGuard image (`v0.107.79`), read-only `/var/run/tailscale` socket mount, strict domain/IP Pydantic validation (anti-SSRF & anti-injection), XSS-safe DOM rendering, and `.env` credential isolation.

## Quick Start
```bash
cp .env.example .env
# Edit .env with your AdGuard credentials
docker compose -f compose.yaml up -d --build
```

## Tailscale HTTPS Setup
```bash
tailscale serve --bg --https=8446 http://127.0.0.1:8086
```

## Tests
```bash
docker compose -f compose.yaml run --rm --no-deps vpn-controler pytest -v
```
