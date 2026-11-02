#!/usr/bin/env python3
"""Direct TCP/TLS/WS handshake probe with Country/GeoIP detection for VLESS and Trojan nodes."""
import argparse
import json
import re
import socket
import ssl
import sys
import time
import urllib.request
from pin_catalog import parse_uri

GEO_CACHE = {}

def get_country_from_remark(remark: str) -> tuple[str, str]:
    """Extract (country_code, flag) from remark if present."""
    # Look for 2-letter uppercase country code around flag emoji
    flag_match = re.search(r'([\U0001F1E6-\U0001F1FF]{2})', remark)
    if flag_match:
        flag = flag_match.group(1)
        # convert flag emoji to ASCII 2-letter code
        chars = [chr(ord(c) - 0x1F1E6 + ord('A')) for c in flag]
        code = "".join(chars)
        return code, flag

    # Common country names or codes
    codes = {
        "US": ("US", "🇺🇸"), "USA": ("US", "🇺🇸"), "UNITED STATES": ("US", "🇺🇸"),
        "GB": ("GB", "🇬🇧"), "UK": ("GB", "🇬🇧"),
        "JP": ("JP", "🇯🇵"), "JAPAN": ("JP", "🇯🇵"),
        "SG": ("SG", "🇸🇬"), "SINGAPORE": ("SG", "🇸🇬"),
        "DE": ("DE", "🇩🇪"), "GERMANY": ("DE", "🇩🇪"),
        "NL": ("NL", "🇳🇱"), "NETHERLANDS": ("NL", "🇳🇱"),
        "LT": ("LT", "🇱🇹"), "LITHUANIA": ("LT", "🇱🇹"),
        "HK": ("HK", "🇭🇰"), "HONG KONG": ("HK", "🇭🇰"),
        "ID": ("ID", "🇮🇩"), "INDONESIA": ("ID", "🇮🇩"),
    }
    rem_upper = remark.upper()
    for k, v in codes.items():
        if re.search(rf'\b{re.escape(k)}\b', rem_upper):
            return v
    return "", ""

def resolve_geoip(host_or_ip: str) -> tuple[str, str, str]:
    """Lookup IP GeoIP via ipwho.is with caching."""
    if host_or_ip in GEO_CACHE:
        return GEO_CACHE[host_or_ip]
    try:
        ip = socket.gethostbyname(host_or_ip)
        if ip in GEO_CACHE:
            GEO_CACHE[host_or_ip] = GEO_CACHE[ip]
            return GEO_CACHE[ip]
        req = urllib.request.Request(f"https://ipwho.is/{ip}", headers={"User-Agent": "curl/8.0"})
        with urllib.request.urlopen(req, timeout=2.5) as r:
            data = json.loads(r.read().decode())
        if data.get("success", False):
            code = data.get("country_code", "??")
            flag = data.get("flag", {}).get("emoji", "")
            country_name = data.get("country", "Unknown")
            res = (code, flag, country_name)
        else:
            res = ("??", "", "Unknown")
        GEO_CACHE[ip] = res
        GEO_CACHE[host_or_ip] = res
        return res
    except Exception:
        res = ("??", "", "Unknown")
        GEO_CACHE[host_or_ip] = res
        return res

def probe_node(uri: str, timeout: float = 3.5) -> dict:
    proxy, reason = parse_uri(uri)
    if not proxy:
        return {"status": "SKIPPED", "error": reason}
    
    server = proxy["server"]
    port = proxy["port"]
    sni = proxy.get("sni") or proxy.get("host") or server
    is_tls = proxy.get("tls", False)
    is_ws = proxy.get("network") == "ws"
    ws_path = proxy.get("path") or "/"
    ws_host = proxy.get("host") or sni
    remark = proxy.get("remark", "-")

    # 1. Detect Country
    code, flag = get_country_from_remark(remark)
    country_name = ""
    if not code and sni and sni != server:
        code, flag, country_name = resolve_geoip(sni)
    if not code:
        code, flag, country_name = resolve_geoip(server)

    res = {
        "type": proxy["type"],
        "server": f"{server}:{port}",
        "sni": sni,
        "transport": f"{proxy['network']}+{'tls' if is_tls else 'plain'}",
        "remark": remark,
        "country_code": code,
        "country_flag": flag,
        "country_name": country_name
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
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode("utf-8")
            active_sock.sendall(req)
            resp = active_sock.recv(512)
            if not resp:
                res["status"] = "DEAD"
                res["error"] = "Empty response from WS server"
                return res
            header_line = resp.split(b"\r\n")[0].decode("utf-8", errors="ignore")
            total_time = (time.time() - start_time) * 1000
            res["status"] = "ALIVE"
            res["rtt_ms"] = round(total_time, 1)
            res["ws_response"] = header_line
            return res
        else:
            total_time = (time.time() - start_time) * 1000
            res["status"] = "ALIVE"
            res["rtt_ms"] = round(total_time, 1)
            return res

    except socket.timeout:
        res["status"] = "TIMEOUT"
        res["error"] = f"Connection timed out (> {timeout}s)"
        return res
    except ssl.SSLError as e:
        res["status"] = "TLS_ERROR"
        res["error"] = str(e)
        return res
    except Exception as e:
        res["status"] = "FAILED"
        res["error"] = str(e)
        return res
    finally:
        if tls_sock:
            try: tls_sock.close()
            except: pass
        elif raw_sock:
            try: raw_sock.close()
            except: pass

def main():
    ap = argparse.ArgumentParser(description="Probe VLESS/Trojan nodes with GeoIP country detection.")
    ap.add_argument("input", help="configs.txt snapshot file")
    ap.add_argument("--max", type=int, default=30, help="max nodes to test (default: 30)")
    ap.add_argument("--country", default="", help="filter by country code (e.g. US, JP, SG, GB)")
    args = ap.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip()]

    target_country = args.country.strip().upper()
    print(f"Total lines: {len(lines)}. Filter country: {target_country or 'ALL'}\n")

    tested_count = 0
    alive_count = 0
    matched_lines = []

    for i, line in enumerate(lines):
        if tested_count >= args.max:
            break
        if not (line.startswith("vless://") or line.startswith("trojan://")):
            continue
        
        # Probe node
        res = probe_node(line)
        tested_count += 1
        
        c_code = res.get("country_code", "??")
        c_flag = res.get("country_flag", "")
        
        # If country filter is active, skip non-matching
        if target_country and c_code != target_country:
            continue

        status = res["status"]
        if status == "ALIVE":
            alive_count += 1
            matched_lines.append((i + 1, res))
            print(f"[{i+1}] \033[92mALIVE\033[0m {c_flag} {c_code} {res['type'].upper()} ({res['rtt_ms']}ms) -> {res['server']} [SNI: {res['sni']}] Remark: {res['remark']}")
        else:
            print(f"[{i+1}] \033[91m{status}\033[0m {c_flag} {c_code} {res['type'].upper()} -> {res['server']} ({res.get('error', '-')})")

    print(f"\nSummary: {alive_count} matching ALIVE nodes found.")
    if matched_lines:
        line_nums = ",".join(str(item[0]) for item in matched_lines)
        print(f"To pin these lines in config.yaml, run:\npython3 pin_catalog.py --input {args.input} --pin {line_nums} --output config.yaml")

if __name__ == "__main__":
    main()
