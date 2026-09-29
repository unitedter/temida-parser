#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Temida Parser — сбор, тест и переименование V2Ray-конфигов.
Самодостаточный: использует официальный Xray-core, без python-v2ray.
"""

import os
import io
import re
import sys
import json
import time
import base64
import socket
import zipfile
import tempfile
import subprocess
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed


def _ensure_pip():
    try:
        __import__("flagz")
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install",
                               "--quiet", "--upgrade", "flagz"])

_ensure_pip()

try:
    import flagz
    HAS_FLAGZ = True
except ImportError:
    HAS_FLAGZ = False


SOURCES = [
    "https://raw.githubusercontent.com/igctndd-hub/LikeVPN/refs/heads/main/LikeVPN.txt",
    "https://raw.githubusercontent.com/topgee-lab/topgee17/refs/heads/main/parsing",
    "https://gitverse.ru/api/repos/SlavaKat/FreeProxyNova/raw/branch/master/\U0001F193ProxyNova \u276F \U0001F3D9\U0001F54A\u270A Ручной выбор Обход БС (Тест)",
    "https://solovyov-jenya2004.vercel.app/random/?n=200",
    "https://sub.vlessfo.ru/vlessforu/working_configs.txt",
    "https://gitverse.ru/api/repos/Akres/VPN/raw/branch/master/all",
    "https://raw.githubusercontent.com/LimeHi/LimeVPN/refs/heads/main/blacklist.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/1.txt",
    "https://github.com/terik21/HiddifySubs-VlessKeys/raw/refs/heads/main/WhiteKeys",
]

MAX_PING_MS = 250
OUTPUT_FILE = "temida.txt"
TEST_URL = "http://www.gstatic.com/generate_204"
FETCH_TIMEOUT = 30
WORKERS = 20
XRAY_URL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"

URI_RE = re.compile(r"^(vless|vmess|trojan)://", re.I)
FLAG_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")
B64_BLOCK_RE = re.compile(r"base64:([A-Za-z0-9+/=]+)")


def fetch_url(url):
    try:
        req = Request(url, headers={"User-Agent": "Mozilla/5.0 (TemidaParser/1.0)"})
        with urlopen(req, timeout=FETCH_TIMEOUT) as r:
            raw = r.read()
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1")
    except Exception as e:
        print(f"[ERROR] {url}: {e}", file=sys.stderr)
        return None


def _fix_b64(s):
    s = s.strip().replace("\n", "").replace("\r", "")
    miss = len(s) % 4
    return s + "=" * (4 - miss) if miss else s


def _try_b64(text):
    c = text.strip()
    if not c or not re.fullmatch(r"[A-Za-z0-9+/=\s]+", c):
        return None
    try:
        dec = base64.b64decode(_fix_b64(c)).decode("utf-8", errors="ignore")
        return dec if URI_RE.search(dec) else None
    except Exception:
        return None


def extract_uris(text):
    uris = []
    for m in B64_BLOCK_RE.finditer(text):
        d = _try_b64(m.group(1))
        if d:
            uris.extend(extract_uris(d))
    d = _try_b64(text)
    if d:
        return extract_uris(d)
    for m in re.finditer(
        r"(?:^|\s)(vless|vmess|trojan)://[^\s]+",
        text, re.I | re.M,
    ):
        uris.append(m.group(0).strip())
    return uris


def _parse_vless(uri):
    u = urlparse(uri)
    q = parse_qs(u.query)
    uid = unquote(u.username or "")
    host = u.hostname
    port = u.port
    if not (uid and host and port):
        return None
    net = q.get("type", ["tcp"])[0]
    sec = q.get("security", ["none"])[0]
    sni = q.get("sni", [""])[0]
    flow = q.get("flow", [""])[0]
    fp = q.get("fp", [""])[0]
    pbk = q.get("pbk", [""])[0]
    sid = q.get("sid", [""])[0]
    path = q.get("path", ["/"])[0]
    host_hdr = q.get("host", [""])[0]
    svc = q.get("serviceName", [""])[0]

    stream = {"network": net, "security": sec if sec != "none" else "none"}
    if sec == "tls":
        stream["tlsSettings"] = {"serverName": sni or host, "allowInsecure": True}
    elif sec == "reality":
        stream["realitySettings"] = {
            "serverName": sni, "fingerprint": fp or "chrome",
            "publicKey": pbk, "shortId": sid, "show": False,
        }
    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_hdr or host}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": svc}
    elif net == "tcp" and q.get("headerType", [""])[0] == "http":
        stream["tcpSettings"] = {"header": {"type": "http", "request": {
            "path": [path], "headers": {"Host": [host_hdr or host]}}}}

    return {
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [
            {"id": uid, "encryption": "none", "flow": flow}]}]},
        "streamSettings": stream,
    }


def _parse_vmess(uri):
    b64 = uri[8:]
    pad = "=" * (-len(b64) % 4)
    d = json.loads(base64.b64decode(b64 + pad).decode("utf-8"))
    host = d["add"]
    port = int(d["port"])
    net = d.get("net", "tcp")
    tls = d.get("tls", "")
    sni = d.get("sni", "") or d.get("host", "")
    path = d.get("path", "/")
    host_hdr = d.get("host", "")
    stream = {"network": net, "security": "tls" if tls else "none"}
    if tls:
        stream["tlsSettings"] = {"serverName": sni or host, "allowInsecure": True}
    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_hdr or host}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": path}
    return {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port, "users": [{
            "id": d["id"], "alterId": int(d.get("aid", 0)),
            "security": d.get("scy", "auto")}]}]},
        "streamSettings": stream,
    }


def _parse_trojan(uri):
    u = urlparse(uri)
    q = parse_qs(u.query)
    pwd = unquote(u.username or "")
    host = u.hostname
    port = u.port or 443
    if not (pwd and host):
        return None
    sec = q.get("security", ["tls"])[0]
    sni = q.get("sni", [""])[0] or host
    net = q.get("type", ["tcp"])[0]
    path = q.get("path", ["/"])[0]
    host_hdr = q.get("host", [""])[0]
    stream = {"network": net, "security": sec}
    if sec == "tls":
        stream["tlsSettings"] = {"serverName": sni, "allowInsecure": True}
    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_hdr or host}}
    return {
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": pwd}]},
        "streamSettings": stream,
    }


def uri_to_outbound(uri):
    try:
        if uri.startswith("vless://"):
            return _parse_vless(uri)
        if uri.startswith("vmess://"):
            return _parse_vmess(uri)
        if uri.startswith("trojan://"):
            return _parse_trojan(uri)
    except Exception:
        return None
    return None


def ensure_xray(root: Path) -> Path:
    xray_dir = root / "xray"
    xray_bin = xray_dir / "xray"
    if xray_bin.exists():
        return xray_bin
    print("[*] Скачиваю Xray-core...")
    xray_dir.mkdir(parents=True, exist_ok=True)
    with urlopen(XRAY_URL, timeout=180) as r:
        data = r.read()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        z.extractall(xray_dir)
    xray_bin.chmod(0o755)
    return xray_bin


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_one(xray_bin, outbound, timeout_ms):
    port = _free_port()
    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks",
                      "settings": {"udp": False, "auth": "noauth"}}],
        "outbounds": [outbound],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        cfg_path = f.name

    proc = None
    try:
        proc = subprocess.Popen(
            [str(xray_bin), "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 1.0
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            return None

        start = time.time()
        try:
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--socks5-hostname", f"127.0.0.1:{port}",
                 "--max-time", f"{timeout_ms/1000:.2f}",
                 TEST_URL],
                capture_output=True, text=True,
                timeout=timeout_ms / 1000 + 1,
            )
        except subprocess.TimeoutExpired:
            return None
        elapsed = (time.time() - start) * 1000
        if r.stdout.strip() in ("200", "204"):
            return elapsed
        return None
    except Exception:
        return None
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            os.unlink(cfg_path)
        except OSError:
            pass


def extract_flag(t):
    m = FLAG_RE.search(t or "")
    return m.group(0) if m else None


def flag_to_country(flag):
    if not HAS_FLAGZ or not flag:
        return None
    try:
        code = "".join(chr(ord(c) - 0x1F1E6 + ord("A")) for c in flag)
        return flagz.by_code(code).name
    except Exception:
        return None


def rename_config(uri, idx):
    flag = extract_flag(uri)
    country = flag_to_country(flag) if flag else None
    name = f"{flag} {country} {idx:02d} TEMIDA PARS" if country \
           else f"\U0001F310 Unknown {idx:02d} TEMIDA PARS"
    return f"{uri.split('#', 1)[0]}#{name}"


def main():
    root = Path("./")
    xray_bin = ensure_xray(root)

    all_uris = []
    for src in SOURCES:
        print(f"[*] {src[:80]}...")
        t = fetch_url(src)
        if t:
            f = extract_uris(t)
            print(f"    -> {len(f)} URI")
            all_uris.extend(f)

    seen, uniq = set(), []
    for u in all_uris:
        k = u.split("#", 1)[0]
        if k not in seen:
            seen.add(k)
            uniq.append(u)
    print(f"[*] Уникальных URI: {len(uniq)}")
    if not uniq:
        print("[ERROR] Нет конфигов", file=sys.stderr)
        sys.exit(1)

    tasks = []
    for u in uniq:
        ob = uri_to_outbound(u)
        if ob:
            tasks.append((u, ob))
    print(f"[*] Распарсено: {len(tasks)}")
    if not tasks:
        print("[ERROR] Ни один URI не распарсен", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Тестирую (потоков: {WORKERS})...")
    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(test_one, xray_bin, ob, MAX_PING_MS): u
                   for u, ob in tasks}
        done = 0
        for fut in as_completed(futures):
            done += 1
            u = futures[fut]
            try:
                ping = fut.result()
            except Exception:
                ping = None
            if ping is not None and ping <= MAX_PING_MS:
                results.append((u, ping))
            if done % 50 == 0:
                print(f"    [{done}/{len(tasks)}] рабочих: {len(results)}")

    print(f"[*] Рабочих <= {MAX_PING_MS} мс: {len(results)}")

    results.sort(key=lambda x: x[1])
    renamed = [rename_config(u, i) for i, (u, _) in enumerate(results, 1)]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(renamed))
    print(f"[OK] {len(renamed)} -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
