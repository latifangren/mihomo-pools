#!/usr/bin/env python3
"""Pin selected vless:// / trojan:// URIs to per-port mihomo listeners.

Local-only. Reads a SAVED snapshot file (one URI per line, e.g. a copy of
a public catalog such as Patterniha/Free-Configs `configs.txt` saved by
the user). It makes no network calls, fetches no list, and prints no
password/UUID. The output config.yaml DOES contain credentials, so it is
written mode 0600 and must never be committed or shared.

Rules enforced (from the mihomo docs checked 2026-10-29, and the
UAC-SNI-Spoofer Auto analysis of 2026-10-28):
  - Pin, don't import raw. Only URIs passed with --pin (by line number
    or by exact remark) are emitted; everything else is only counted.
    A catalog regenerates daily and nodes die, so a raw import would
    pin dead/renamed nodes to fixed ports.
  - Only transports mihomo can express directly are emitted: tcp and
    ws, with security tls/none. REALITY (pbk), ECH/fragment variants,
    and other transports are skipped with a reason, not approximated.
  - A URI whose dial address is 127.0.0.1 (an ECH placeholder) is
    skipped unless --clean-ip is given; then the placeholder is
    replaced by that clean IP and SNI/host/path are kept verbatim.
  - Proxy names are pin-01, pin-02, ... in pin order. No country label
    is assigned here: egress geography is per-IP from a shared
    anycast pool, not per URI. Measure each port (see verify.sh),
    then rename from measured results.
  - Listeners use `type: mixed` with a pinned `proxy:` per listener,
    so no `rules` routing is needed; `rules: [MATCH,DIRECT]` is kept
    as fallthrough. Default listen is 127.0.0.1 only.

Usage:
  # 1. Save the catalog snapshot yourself, inspect it, pick line numbers:
  python3 pin_catalog.py --list --input configs.txt
  # 2. Pin the lines you tested, e.g. lines 3 and 7, ports from 10101:
  python3 pin_catalog.py --input configs.txt --pin 3,7 --output ./config.yaml
  # 3. Replace the secret placeholder, run mihomo, then run ./verify.sh

WARNING: public catalog nodes are run by strangers. Traffic through a
pinned node can be observed by its operator. Do not use these ports
for logins, banking, or anything sensitive, and re-measure before
relying on a pin: the snapshot goes stale when the catalog regenerates.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse



def detect_country(proxy: dict) -> str:
    """Detect country code from remark or SNI/server."""
    import re
    remark = proxy.get("remark", "")
    flag_match = re.search(r'([🇦-🇿]{2})', remark)
    if flag_match:
        flag = flag_match.group(1)
        return "".join([chr(ord(c) - 0x1F1E6 + ord('A')) for c in flag])
    codes = {"US": "US", "USA": "US", "GB": "GB", "UK": "GB", "JP": "JP",
             "SG": "SG", "DE": "DE", "NL": "NL", "LT": "LT", "HK": "HK"}
    for k, v in codes.items():
        if re.search(rf'\b{re.escape(k)}\b', remark.upper()):
            return v
    sni = (proxy.get("sni") or proxy.get("host") or "").lower()
    if sni.endswith(".us"): return "US"
    if sni.endswith(".jp"): return "JP"
    if sni.endswith(".uk"): return "GB"
    if sni.endswith(".sg"): return "SG"
    if sni.endswith(".de"): return "DE"
    if sni.endswith(".nl"): return "NL"
    return "??"

def _first(qs: dict, *keys: str):
    for k in keys:
        v = qs.get(k)
        if v:
            return v[0]
    return None


def _bool(v) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes"}


def parse_uri(line: str):
    """Return (proxy-dict, skip-reason) for one vless/trojan URI."""
    u = urlparse(line.strip())
    scheme = u.scheme.lower()
    if scheme not in {"vless", "trojan"}:
        return None, f"unsupported scheme {scheme!r} (only vless/trojan)"
    qs = parse_qs(u.query)
    security = (_first(qs, "security") or ("tls" if scheme == "trojan" else "none")).lower()
    if security == "reality" or _first(qs, "pbk"):
        return None, "REALITY (pbk) not emitted; test in Xray, not approximated in mihomo"
    if security not in {"tls", "none"}:
        return None, f"unsupported security={security!r}"
    if _first(qs, "fragment"):
        return None, "fragment variant is Xray-specific; not approximated"
    net = (_first(qs, "type") or "tcp").lower()
    if net not in {"tcp", "ws"}:
        return None, f"unsupported transport type={net!r} (only tcp/ws)"
    if not u.hostname or not u.port:
        return None, "missing server/port"
    credential = unquote(u.username or "")
    if not credential:
        return None, "missing uuid/password"
    if scheme == "vless":
        enc = _first(qs, "encryption")
        if enc and enc.lower() != "none":
            return None, f"unsupported encryption={enc!r}"
    sni = _first(qs, "sni", "servername")
    host = _first(qs, "host")
    path = _first(qs, "path", "serviceName") or ""
    if security == "tls" and not (sni or host):
        return None, "TLS without sni/host: no SNI to verify against"
    proxy = {
        "name": "",  # filled by caller
        "type": scheme,
        "server": u.hostname,
        "port": u.port,
        "tls": security == "tls",
        "sni": sni or host or "",
        "network": net,
        "host": host or "",
        "path": unquote(path) if net == "ws" else "",
        "skip_cert_verify": _bool(_first(qs, "allowInsecure", "insecure") or ""),
        "client_fingerprint": _first(qs, "fp") or "",
        "alpn": [a.strip() for a in (_first(qs, "alpn") or "").split(",") if a.strip()],
        "remark": unquote(u.fragment or ""),
        "credential": credential,
    }
    if scheme == "vless":
        proxy["uuid"] = credential
        flow = _first(qs, "flow")
        if flow:
            if net != "tcp":
                return None, f"flow={flow!r} with ws transport not emitted"
            proxy["flow"] = flow
        pe = _first(qs, "packetEncoding")
        if pe:
            proxy["packet_encoding"] = pe
    else:
        proxy["password"] = credential
    return proxy, ""


def dedup_key(p: dict):
    return (p["type"], p["credential"], p["sni"], p["host"], p["path"],
            p["network"], p["port"])


def yaml_str(value: str) -> str:
    return json.dumps(str(value))


def emit_proxy(p: dict) -> list[str]:
    lines = [f"  - name: {p['name']}", f"    type: {p['type']}",
             f"    server: {yaml_str(p['server'])}", f"    port: {p['port']}"]
    if p["type"] == "vless":
        lines.append(f"    uuid: {yaml_str(p['uuid'])}")
        if p.get("flow"):
            lines.append(f"    flow: {yaml_str(p['flow'])}")
        if p.get("packet_encoding"):
            lines.append(f"    packet-encoding: {yaml_str(p['packet_encoding'])}")
    else:
        lines.append(f"    password: {yaml_str(p['password'])}")
    if p["tls"]:
        lines.append("    tls: true")
        if p["sni"]:
            lines.append(f"    sni: {yaml_str(p['sni'])}")
            lines.append(f"    servername: {yaml_str(p['sni'])}")
    if p["skip_cert_verify"]:
        lines.append("    skip-cert-verify: true")
    if p["client_fingerprint"]:
        lines.append(f"    client-fingerprint: {yaml_str(p['client_fingerprint'])}")
    if p["alpn"]:
        lines.append("    alpn:")
        for a in p["alpn"]:
            lines.append(f"      - {yaml_str(a)}")
    if p["network"] == "ws":
        lines.append("    network: ws")
        lines.append("    ws-opts:")
        lines.append(f"      path: {yaml_str(p['path'] or '/')}")
        if p["host"]:
            lines.append("      headers:")
            lines.append(f"        Host: {yaml_str(p['host'])}")
    lines.append("    udp: true")
    return lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--input", required=True, help="saved snapshot file, one URI per line")
    ap.add_argument("--output", help="config.yaml to write (required unless --list)")
    ap.add_argument("--list", action="store_true", help="list lines with scheme/remark/server, emit nothing")
    ap.add_argument("--pin", default="", help="comma list of 1-based line numbers to pin, e.g. 3,7")
    ap.add_argument("--pin-remark", default="", help="comma list of exact remarks (#fragment) to pin")
    ap.add_argument("--country", default="", help="filter pinned nodes by 2-letter country code, e.g. US, JP, SG")
    ap.add_argument("--base-port", type=int, default=10101,
                    help="first listener port (default 10101: clear of the Warp generator's 10001+)")
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--clean-ip", default="",
                    help="replace a 127.0.0.1 dial address (ECH placeholder) with this IP; SNI/host kept")
    ap.add_argument("--secret", default="GANTI-SECRET-PANJANG")
    args = ap.parse_args()

    path = Path(args.input)
    if not path.is_file():
        print(f"input not found: {path}", file=sys.stderr)
        return 2
    raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    entries = [(i + 1, ln.strip()) for i, ln in enumerate(raw_lines) if ln.strip()]

    if args.list:
        for n, ln in entries:
            u = urlparse(ln)
            print(f"{n}: {u.scheme} server={u.hostname}:{u.port} "
                  f"remark={unquote(u.fragment or '') or '-'}")
        print(f"{len(entries)} non-empty lines (nothing emitted; pin by line number after testing).")
        return 0

    if not args.output:
        print("--output is required unless --list", file=sys.stderr)
        return 2
    pins = set()
    for tok in args.pin.split(","):
        tok = tok.strip()
        if tok:
            pins.add(int(tok))
    remarks = {r.strip() for r in args.pin_remark.split(",") if r.strip()}

    chosen, skipped = [], []
    seen = set()
    for n, ln in entries:
        proxy, reason = parse_uri(ln)
        if proxy is None:
            if n in pins or unquote(urlparse(ln).fragment or "") in remarks:
                skipped.append((n, reason))
            continue
        if args.country:
            c = detect_country(proxy)
            if c != args.country.strip().upper():
                continue
        elif pins or remarks:
            if n not in pins and proxy["remark"] not in remarks:
                continue
        if proxy["server"] == "127.0.0.1":
            if not args.clean_ip:
                skipped.append((n, "dial address 127.0.0.1 (ECH placeholder); re-run with --clean-ip <IP>"))
                continue
            proxy["server"] = args.clean_ip
        key = dedup_key(proxy)
        if key in seen:
            skipped.append((n, "duplicate of an earlier pinned URI (same credential/SNI/path, clean-IP copy)"))
            continue
        seen.add(key)
        proxy["line"] = n
        chosen.append(proxy)

    if not chosen:
        print("no usable pins; all pinned lines skipped:", file=sys.stderr)
        for n, why in skipped:
            print(f"  line {n}: {why}", file=sys.stderr)
        return 1

    out = Path(args.output)
    lines = ["allow-lan: true", "mode: rule", "external-controller: 127.0.0.1:9090",
             f"secret: {yaml_str(args.secret)}", "", "listeners:"]
    for i, p in enumerate(chosen):
        p["name"] = f"pin-{i + 1:02d}"
        p["port_local"] = args.base_port + i
        lines.append(f"  - {{ name: {p['name']}, type: mixed, port: {p['port_local']}, "
                     f"listen: {args.listen}, proxy: {p['name']} }}")
    lines += ["", "proxies:"]
    for p in chosen:
        lines += emit_proxy(p)
    lines += ["", "rules:", "  - MATCH,DIRECT", ""]
    out.write_text("\n".join(lines), encoding="utf-8")
    os.chmod(out, stat.S_IRUSR | stat.S_IWUSR)  # 0600: contains credentials

    pinned = out.parent / "pinned.txt"
    plines = ["# port -> pinned URI (line in snapshot, remark, dial server, SNI).",
              "# No country label: measure with verify.sh, then rename from results.", ""]
    for p in chosen:
        plines.append(f"{p['port_local']}: {p['name']} line={p['line']} "
                      f"remark={p['remark'] or '-'} server={p['server']}:{p['port']} sni={p['sni'] or '-'}")
    pinned.write_text("\n".join(plines) + "\n", encoding="utf-8")

    verify = out.parent / "verify.sh"
    vlines = ["#!/bin/sh", "# Measure the egress country of each pinned port, then rename from results.",
              "# Do not trust catalog remarks as country labels.", ""]
    for p in chosen:
        vlines.append(f'echo "== {p["name"]} :{p["port_local"]} =="')
        vlines.append(f"curl -s -x http://{args.listen}:{p['port_local']} https://ipwho.is/ ; echo")
    verify.write_text("\n".join(vlines) + "\n", encoding="utf-8")
    os.chmod(verify, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    print(f"wrote {out} ({len(chosen)} pins, ports {args.base_port}-{args.base_port + len(chosen) - 1}, mode 0600)")
    print(f"wrote {pinned} and {verify}")
    for n, why in skipped:
        print(f"skipped line {n}: {why}", file=sys.stderr)
    if args.secret == "GANTI-SECRET-PANJANG":
        print("WARNING: replace the placeholder secret in config.yaml before running mihomo.", file=sys.stderr)
    print("Names are pin-01, pin-02, ... (unverified). Run verify.sh, then rename from measured countries.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
