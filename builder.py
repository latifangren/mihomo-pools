#!/usr/bin/env python3
"""
Mihomo Pools Pipeline Builder (v2 - Robust Parsing & Strict Validation)
Fetches public VLESS/Trojan proxies, validates them via handshake probes,
detects egress countries, and produces Dual Output subscriptions:
1. Native Mihomo YAML Proxy Providers (dist/providers/<CC>.yaml and ALL.yaml)
2. Plain URI lists (dist/plain/<CC>.txt and ALL.txt)
3. Base64 subscriptions (dist/subs/<CC>.txt and ALL.txt)
"""

import argparse
import base64
import concurrent.futures
import datetime
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.request
from collections import defaultdict
from urllib.parse import unquote

SOURCES = [
    "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/v2FreeHub/v2hub-configs/refs/heads/main/Sub-AutoUpdate",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/mix",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_1.txt",
]

FLAG_MAP = {
    "US": "🇺🇸", "SG": "🇸🇬", "ID": "🇮🇩", "JP": "🇯🇵", "DE": "🇩🇪",
    "NL": "🇳🇱", "GB": "🇬🇧", "CA": "🇨🇦", "FR": "🇫🇷", "HK": "🇭🇰",
    "KR": "🇰🇷", "TW": "🇹🇼", "IN": "🇮🇳", "AU": "🇦🇺", "RU": "🇷🇺",
    "BR": "🇧🇷", "TR": "🇹🇷", "FI": "🇫🇮", "SE": "🇸🇪", "CH": "🇨🇭",
    "IT": "🇮🇹", "ES": "🇪🇸", "PL": "🇵🇱", "UA": "🇺🇦", "MY": "🇲🇾",
    "TH": "🇹🇭", "VN": "🇻🇳", "PH": "🇵🇭", "AE": "🇦🇪", "ZA": "🇿🇦",
}

UUID_REGEX = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
GEO_CACHE = {}


def get_flag(cc: str) -> str:
    if not cc or len(cc) != 2:
        return "🌐"
    cc = cc.upper()
    if cc in FLAG_MAP:
        return FLAG_MAP[cc]
    try:
        return "".join(chr(0x1F1E6 + ord(c) - ord('A')) for c in cc)
    except Exception:
        return "🌐"


def get_country_from_remark(remark: str) -> tuple[str, str]:
    if not remark:
        return "", ""
    flag_match = re.search(r'([\U0001F1E6-\U0001F1FF]{2})', remark)
    if flag_match:
        flag = flag_match.group(1)
        chars = [chr(ord(c) - 0x1F1E6 + ord('A')) for c in flag]
        code = "".join(chars).upper()
        return code, flag

    country_aliases = {
        "INDONESIA": "ID", "IDN": "ID",
        "SINGAPORE": "SG", "SGP": "SG",
        "UNITED STATES": "US", "USA": "US", "AMERICA": "US",
        "JAPAN": "JP", "JPN": "JP", "TOKYO": "JP",
        "GERMANY": "DE", "DEU": "DE", "FRANKFURT": "DE",
        "NETHERLANDS": "NL", "NLD": "NL", "AMSTERDAM": "NL",
        "UNITED KINGDOM": "GB", "ENGLAND": "GB", "LONDON": "GB",
        "HONG KONG": "HK", "HKG": "HK",
        "KOREA": "KR", "SEOUL": "KR",
        "TAIWAN": "TW", "MALAYSIA": "MY",
        "AUSTRALIA": "AU", "CANADA": "CA",
        "FRANCE": "FR", "INDIA": "IN",
    }
    rem_upper = remark.upper()
    for alias, code in country_aliases.items():
        if re.search(rf'\b{re.escape(alias)}\b', rem_upper):
            return code, get_flag(code)
    return "", ""


def resolve_geoip(host_or_ip: str) -> tuple[str, str]:
    if not host_or_ip:
        return "??", "🌐"
    if host_or_ip in GEO_CACHE:
        return GEO_CACHE[host_or_ip]
    try:
        ip = socket.gethostbyname(host_or_ip)
        if ip in GEO_CACHE:
            GEO_CACHE[host_or_ip] = GEO_CACHE[ip]
            return GEO_CACHE[ip]
        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
            return "??", "🌐"
        req = urllib.request.Request(
            f"https://ipwho.is/{ip}",
            headers={"User-Agent": "curl/8.0"}
        )
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode())
        if data.get("success", False):
            code = data.get("country_code", "??").upper()
            flag = get_flag(code)
            res = (code, flag)
        else:
            res = ("??", "🌐")
        GEO_CACHE[ip] = res
        GEO_CACHE[host_or_ip] = res
        return res
    except Exception:
        res = ("??", "🌐")
        GEO_CACHE[host_or_ip] = res
        return res


def parse_uri(line: str) -> tuple[dict | None, str]:
    raw = line.strip()
    if not raw:
        return None, "empty"

    if not (raw.startswith("vless://") or raw.startswith("trojan://")):
        return None, "unsupported scheme"

    scheme = "vless" if raw.startswith("vless://") else "trojan"
    rest = raw[len(scheme) + 3:]

    # Match: user@server:port
    match = re.match(r"^([^@]+)@([^:/?#]+):(\d+)", rest)
    if not match:
        return None, "invalid credential@server:port format"

    credential, server, port_str = match.groups()
    try:
        port = int(port_str)
    except ValueError:
        return None, f"invalid port {port_str!r}"

    credential = unquote(credential).strip()
    if not credential:
        return None, "missing credential"

    # Validate UUID for vless
    if scheme == "vless":
        if not UUID_REGEX.match(credential):
            return None, f"invalid vless uuid format {credential!r}"

    # Extract all query params safely using regex across rest of line
    after_host = rest[match.end():]
    parts = after_host.split("#")
    if len(parts) > 1 and "=" not in parts[-1]:
        remark = unquote(parts[-1]).strip()
        query_part = "#".join(parts[:-1])
    else:
        remark = ""
        query_part = after_host

    # Extract key=val pairs
    params = {}
    for k, v in re.findall(r"([a-zA-Z0-9_-]+)=([^&?#]+)", query_part):
        params[k.lower()] = v.strip()

    # Security
    sec = params.get("security", "").lower()
    if sec == "reality" or "pbk" in params:
        return None, "REALITY not supported"
    if "fragment" in params:
        return None, "fragment variant not supported"

    if not sec:
        sec = "tls" if (port == 443 or scheme == "trojan") else "none"

    if sec not in {"tls", "none"}:
        return None, f"unsupported security {sec!r}"

    # Transport Network
    net = params.get("type", "").lower()
    path = unquote(params.get("path", "") or params.get("servicename", ""))

    if not net:
        if path and path.startswith("/"):
            net = "ws"
        else:
            net = "tcp"

    if net not in {"tcp", "ws"}:
        return None, f"unsupported network {net!r}"

    # SNI and Host
    sni = params.get("sni") or params.get("servername") or ""
    host = params.get("host") or ""

    if sni and ("@" in sni or " " in sni):
        sni = ""
    if host and ("@" in host or " " in host):
        host = ""

    if not sni and host:
        sni = host
    if not host and sni:
        host = sni

    # If TLS is enabled, we need SNI or a domain server
    if sec == "tls":
        if not sni:
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$", server):
                sni = server
                host = server
            else:
                return None, "TLS without valid SNI"

    # If WS is enabled, ensure path is valid
    if net == "ws":
        if not path:
            path = "/"
        elif not path.startswith("/"):
            path = "/" + path

    proxy = {
        "raw_uri": raw,
        "type": scheme,
        "server": server,
        "port": port,
        "tls": sec == "tls",
        "sni": sni,
        "network": net,
        "host": host,
        "path": path if net == "ws" else "",
        "skip_cert_verify": params.get("allowinsecure", "") in {"1", "true"} or params.get("insecure", "") in {"1", "true"},
        "client_fingerprint": params.get("fp") or "chrome",
        "alpn": [unquote(a.strip()) for a in params.get("alpn", "").split(",") if a.strip()],
        "remark": remark,
        "credential": credential,
    }

    if scheme == "vless":
        proxy["uuid"] = credential
        flow = params.get("flow")
        if flow and net == "tcp":
            proxy["flow"] = flow
        pe = params.get("packetencoding") or params.get("packet_encoding")
        if pe:
            proxy["packet_encoding"] = pe
    else:
        proxy["password"] = credential

    return proxy, ""


def probe_node(proxy: dict, timeout: float = 3.5) -> dict:
    server = proxy["server"]
    port = proxy["port"]
    sni = proxy.get("sni") or proxy.get("host") or server
    is_tls = proxy.get("tls", False)
    is_ws = proxy.get("network") == "ws"
    ws_path = proxy.get("path") or "/"
    ws_host = proxy.get("host") or sni
    remark = proxy.get("remark", "")

    code, flag = get_country_from_remark(remark)
    if not code and sni and sni != server:
        code, flag = resolve_geoip(sni)
    if not code or code == "??":
        code, flag = resolve_geoip(server)

    if not code or code == "??":
        code = "OTHER"
        flag = "🌐"

    res = {
        "status": "UNKNOWN",
        "rtt_ms": 0,
        "country_code": code,
        "country_flag": flag,
        "proxy": proxy,
    }

    start_time = time.time()
    raw_sock = None
    tls_sock = None
    try:
        raw_sock = socket.create_connection((server, port), timeout=timeout)
        active_sock = raw_sock

        if is_tls:
            tls_ctx = ssl.create_default_context()
            if proxy.get("skip_cert_verify"):
                tls_ctx.check_hostname = False
                tls_ctx.verify_mode = ssl.CERT_NONE
            if proxy.get("alpn"):
                tls_ctx.set_alpn_protocols(proxy["alpn"])
            active_sock = tls_ctx.wrap_socket(raw_sock, server_hostname=sni)
            tls_sock = active_sock

        if is_ws:
            req = (
                f"GET {ws_path} HTTP/1.1\r\n"
                f"Host: {ws_host}\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode("utf-8")
            active_sock.sendall(req)
            resp = active_sock.recv(256)
            if not resp:
                res["status"] = "DEAD"
                return res

            first_line = resp.split(b"\r\n")[0].decode("utf-8", errors="ignore")
            if any(first_line.startswith(c) for c in ["HTTP/1.1 400", "HTTP/1.1 404", "HTTP/1.1 500", "HTTP/1.1 502", "HTTP/1.1 503"]):
                res["status"] = "DEAD"
                return res

            res["status"] = "ALIVE"
            res["rtt_ms"] = round((time.time() - start_time) * 1000, 1)
            return res
        else:
            res["status"] = "ALIVE"
            res["rtt_ms"] = round((time.time() - start_time) * 1000, 1)
            return res
    except (socket.timeout, TimeoutError):
        res["status"] = "TIMEOUT"
        return res
    except Exception:
        res["status"] = "FAILED"
        return res
    finally:
        if tls_sock:
            try: tls_sock.close()
            except Exception: pass
        elif raw_sock:
            try: raw_sock.close()
            except Exception: pass


def fetch_source_uris(urls: list[str]) -> list[str]:
    uris = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    for url in urls:
        print(f"Fetching: {url}")
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as r:
                body = r.read().decode("utf-8", errors="ignore")
        except Exception as e:
            print(f"  Failed: {e}")
            continue

        raw_lines = [line.strip() for line in body.splitlines() if line.strip()]
        if len(raw_lines) == 1 and not raw_lines[0].startswith(("vless://", "trojan://")):
            try:
                decoded = base64.b64decode(raw_lines[0]).decode("utf-8", errors="ignore")
                raw_lines = [line.strip() for line in decoded.splitlines() if line.strip()]
            except Exception:
                pass

        count = 0
        for line in raw_lines:
            if line.startswith(("vless://", "trojan://")):
                uris.append(line)
                count += 1
        print(f"  Got {count} URIs")
    return uris


def format_mihomo_proxy_yaml(p: dict, display_name: str) -> str:
    lines = [
        f"  - name: {json.dumps(display_name, ensure_ascii=False)}",
        f"    type: {p['type']}",
        f"    server: {json.dumps(p['server'], ensure_ascii=False)}",
        f"    port: {p['port']}",
    ]
    if p["type"] == "vless":
        lines.append(f"    uuid: {json.dumps(p['uuid'], ensure_ascii=False)}")
        if p.get("flow"):
            lines.append(f"    flow: {json.dumps(p['flow'], ensure_ascii=False)}")
        if p.get("packet_encoding"):
            lines.append(f"    packet-encoding: {json.dumps(p['packet_encoding'], ensure_ascii=False)}")
    else:
        lines.append(f"    password: {json.dumps(p['password'], ensure_ascii=False)}")

    lines.append(f"    tls: {str(p.get('tls', False)).lower()}")
    lines.append(f"    udp: true")

    if p.get("sni"):
        lines.append(f"    sni: {json.dumps(p['sni'], ensure_ascii=False)}")
        lines.append(f"    servername: {json.dumps(p['sni'], ensure_ascii=False)}")

    if p.get("client_fingerprint"):
        lines.append(f"    client-fingerprint: {json.dumps(p['client_fingerprint'], ensure_ascii=False)}")

    if p.get("skip_cert_verify"):
        lines.append("    skip-cert-verify: true")

    if p.get("alpn"):
        lines.append("    alpn:")
        for a in p["alpn"]:
            lines.append(f"      - {json.dumps(a, ensure_ascii=False)}")

    if p.get("network") == "ws":
        lines.append("    network: ws")
        lines.append("    ws-opts:")
        lines.append(f"      path: {json.dumps(p.get('path') or '/', ensure_ascii=False)}")
        ws_host = p.get("host") or p.get("sni")
        if ws_host:
            lines.append("      headers:")
            lines.append(f"        Host: {json.dumps(ws_host, ensure_ascii=False)}")

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Mihomo Pools Multi-Country Subscription Builder")
    ap.add_argument("--input", default="", help="Path to local configs.txt snapshot")
    ap.add_argument("--fetch", action="store_true", help="Fetch fresh configs from public sources")
    ap.add_argument("--outdir", default="dist", help="Output directory (default: dist)")
    ap.add_argument("--concurrency", type=int, default=30, help="Max parallel probe workers (default: 30)")
    ap.add_argument("--timeout", type=float, default=3.5, help="Socket probe timeout in seconds (default: 3.5)")
    ap.add_argument("--limit-per-country", type=int, default=30, help="Max alive nodes per country (default: 30)")
    args = ap.parse_args()

    uris = []
    if args.input and os.path.exists(args.input):
        print(f"Reading local input: {args.input}")
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
            uris.extend([line.strip() for line in f if line.strip().startswith(("vless://", "trojan://"))])

    if args.fetch:
        print("Fetching online sources...")
        uris.extend(fetch_source_uris(SOURCES))

    if not uris:
        print("No URIs found to process. Provide --input or --fetch.")
        sys.exit(1)

    print(f"Total raw URIs collected: {len(uris)}")

    # Parse and deduplicate
    unique_proxies = {}
    for uri in uris:
        p, reason = parse_uri(uri)
        if not p:
            continue
        key = (p["type"], p["credential"], p["server"], p["port"], p["sni"], p["path"])
        if key not in unique_proxies:
            unique_proxies[key] = p

    proxies_to_probe = list(unique_proxies.values())
    print(f"Unique valid proxies: {len(proxies_to_probe)}")

    # Probe concurrently
    alive_by_country = defaultdict(list)
    alive_all = []

    print(f"Starting probes with {args.concurrency} workers (timeout={args.timeout}s)...")
    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        future_map = {executor.submit(probe_node, p, args.timeout): p for p in proxies_to_probe}
        for future in concurrent.futures.as_completed(future_map):
            res = future.result()
            if res["status"] == "ALIVE":
                cc = res["country_code"]
                alive_by_country[cc].append(res)
                alive_all.append(res)

    duration = round(time.time() - start_time, 2)
    print(f"Probe completed in {duration}s. Total ALIVE nodes: {len(alive_all)}")
    for cc, items in sorted(alive_by_country.items()):
        print(f"  - {get_flag(cc)} {cc}: {len(items)} nodes")

    # Generate Output Dirs
    outdir = args.outdir
    providers_dir = os.path.join(outdir, "providers")
    plain_dir = os.path.join(outdir, "plain")
    subs_dir = os.path.join(outdir, "subs")

    os.makedirs(providers_dir, exist_ok=True)
    os.makedirs(plain_dir, exist_ok=True)
    os.makedirs(subs_dir, exist_ok=True)

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Groupings to export: each country + ALL
    export_groups = dict(alive_by_country)
    export_groups["ALL"] = alive_all

    index_rows = []

    for cc, items in export_groups.items():
        items.sort(key=lambda x: x["rtt_ms"])
        if cc != "ALL" and args.limit_per_country > 0:
            items = items[:args.limit_per_country]

        flag = get_flag(cc) if cc != "ALL" else "🌐"

        # 1. Plain text list
        plain_lines = [x["proxy"]["raw_uri"] for x in items]
        plain_content = "\n".join(plain_lines) + "\n"
        with open(os.path.join(plain_dir, f"{cc}.txt"), "w", encoding="utf-8") as f:
            f.write(plain_content)

        # 2. Base64 sub
        b64_content = base64.b64encode(plain_content.encode("utf-8")).decode("utf-8")
        with open(os.path.join(subs_dir, f"{cc}.txt"), "w", encoding="utf-8") as f:
            f.write(b64_content + "\n")

        # 3. Mihomo Proxy Provider YAML
        yaml_proxies = []
        for idx, item in enumerate(items, 1):
            p = item["proxy"]
            rtt = int(item["rtt_ms"])
            node_name = f"{flag} {cc}-{idx:02d} | {rtt}ms | {p['type']}"
            yaml_proxies.append(format_mihomo_proxy_yaml(p, node_name))

        yaml_content = f"# Mihomo Proxy Provider - {cc}\n# Updated: {timestamp}\n# Total Proxies: {len(items)}\n\nproxies:\n"
        yaml_content += "\n".join(yaml_proxies) + "\n"
        with open(os.path.join(providers_dir, f"{cc}.yaml"), "w", encoding="utf-8") as f:
            f.write(yaml_content)

        if cc != "ALL":
            index_rows.append((cc, flag, len(items)))

    # Stats / Index JSON
    stats = {
        "updated_at": timestamp,
        "total_alive": len(alive_all),
        "countries": {cc: len(items) for cc, items in sorted(alive_by_country.items())}
    }
    with open(os.path.join(outdir, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    # Build index.html
    html_lines = [
        "<!DOCTYPE html>",
        "<html lang='en'><head><meta charset='utf-8'><title>Mihomo Proxy Pools</title>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        "<style>",
        "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; max-width: 850px; margin: 40px auto; padding: 0 20px; }",
        "h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }",
        "table { width: 100%; border-collapse: collapse; margin-top: 20px; }",
        "th, td { padding: 12px; border: 1px solid #30363d; text-align: left; }",
        "th { background: #161b22; color: #58a6ff; }",
        "a { color: #58a6ff; text-decoration: none; }",
        "a:hover { text-decoration: underline; }",
        "code { background: #161b22; padding: 2px 6px; border-radius: 4px; color: #79c0ff; }",
        "</style></head><body>",
        f"<h1>🚀 Mihomo Proxy Pools Subscription</h1>",
        f"<p>Automated multi-country proxy subscriptions for Mihomo / Clash Meta / Xray.</p>",
        f"<p><strong>Last Updated:</strong> <code>{timestamp}</code> | <strong>Total Alive:</strong> <code>{len(alive_all)}</code></p>",
        "<table>",
        "<tr><th>Region</th><th>Active</th><th>Mihomo Provider (YAML)</th><th>Base64 Sub</th><th>Plain URIs</th></tr>",
        f"<tr><td>🌐 ALL</td><td>{len(alive_all)}</td><td><a href='providers/ALL.yaml'>providers/ALL.yaml</a></td><td><a href='subs/ALL.txt'>subs/ALL.txt</a></td><td><a href='plain/ALL.txt'>plain/ALL.txt</a></td></tr>"
    ]
    for cc, flag, cnt in sorted(index_rows):
        html_lines.append(f"<tr><td>{flag} {cc}</td><td>{cnt}</td><td><a href='providers/{cc}.yaml'>providers/{cc}.yaml</a></td><td><a href='subs/{cc}.txt'>subs/{cc}.txt</a></td><td><a href='plain/{cc}.txt'>plain/{cc}.txt</a></td></tr>")
    html_lines.append("</table></body></html>")

    with open(os.path.join(outdir, "index.html"), "w", encoding="utf-8") as f:
        f.write("\n".join(html_lines) + "\n")

    print("\n[SUCCESS] Subscription files successfully written to dist/")


if __name__ == "__main__":
    main()
