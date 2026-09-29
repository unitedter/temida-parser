#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Temida Parser — сбор, тест и переименование V2Ray-конфигов."""

import subprocess, sys, importlib.util

REQUIRED_PACKAGES = {"python-v2ray": "python_v2ray", "flagz": "flagz"}


def _is_installed(name):
    return importlib.util.find_spec(name) is not None


def ensure_dependencies():
    missing = [p for p, m in REQUIRED_PACKAGES.items() if not _is_installed(m)]
    if missing:
        print(f"[*] Устанавливаю: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install",
                               "--upgrade", "--quiet", *missing])
    if sys.platform.startswith("linux"):
        try:
            subprocess.check_call(["sudo", "apt-get", "update", "-qq"],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
            subprocess.check_call(["sudo", "apt-get", "install", "-y", "-qq",
                                   "unzip", "curl", "wget", "ca-certificates"],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[WARN] apt: {e}", file=sys.stderr)


ensure_dependencies()

import json, base64, re
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError
from python_v2ray.downloader import BinaryDownloader
from python_v2ray.tester import ConnectionTester
from python_v2ray.config_parser import parse_uri

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
TIMEOUT = 30

URI_RE = re.compile(r"^(vless|vmess|trojan|ss|hysteria2?|mvless)://", re.I)
FLAG_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")
B64_BLOCK_RE = re.compile(r"base64:([A-Za-z0-9+/=]+)")


def fetch_url(url):
    try:
        req = Request(url, headers={"User-Agent": "Mozilla/5.0 (TemidaParser/1.0)"})
        with urlopen(req, timeout=TIMEOUT) as r:
            raw = r.read()
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1")
    except (URLError, TimeoutError, OSError) as e:
        print(f"[ERROR] {url}: {e}", file=sys.stderr)
        return None


def fix_b64(s):
    s = s.strip().replace("\n", "").replace("\r", "")
    miss = len(s) % 4
    return s + "=" * (4 - miss) if miss else s


def try_b64(text):
    c = text.strip()
    if not c or not re.fullmatch(r"[A-Za-z0-9+/=\s]+", c):
        return None
    try:
        dec = base64.b64decode(fix_b64(c)).decode("utf-8", errors="ignore")
        return dec if URI_RE.search(dec) else None
    except Exception:
        return None


def _parse_xray_json(text):
    uris = []
    for m in re.finditer(r'"outbounds"\s*:\s*(\[.*?\])\s*[,}]', text, re.DOTALL):
        try:
            outbounds = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
        for ob in outbounds:
            if ob.get("protocol") not in ("vless", "vmess", "trojan"):
                continue
            try:
                vnext = ob["settings"]["vnext"][0]
                addr, port = vnext["address"], vnext["port"]
                user = vnext["users"][0]
                uid = user["id"]
                flow = user.get("flow", "")
                st = ob.get("streamSettings", {})
                net, sec = st.get("network", "tcp"), st.get("security", "")
                sni = pbk = sid = fp = ""
                if sec == "reality":
                    rs = st.get("realitySettings", {})
                    sni = rs.get("serverName", "")
                    pbk = rs.get("publicKey", "")
                    sid = rs.get("shortId", "")
                    fp = rs.get("fingerprint", "")
                elif sec == "tls":
                    sni = st.get("tlsSettings", {}).get("serverName", "")
                p = []
                if sec:  p.append(f"security={sec}")
                if sni:  p.append(f"sni={sni}")
                if pbk:  p.append(f"pbk={pbk}")
                if sid:  p.append(f"sid={sid}")
                if fp:   p.append(f"fp={fp}")
                if flow: p.append(f"flow={flow}")
                p.append(f"type={net}")
                uris.append(f"vless://{uid}@{addr}:{port}?{'&'.join(p)}#Xray")
            except (KeyError, IndexError, TypeError):
                continue
    return uris


def extract_uris(text):
    uris = []
    for m in B64_BLOCK_RE.finditer(text):
        d = try_b64(m.group(1))
        if d:
            uris.extend(extract_uris(d))
    d = try_b64(text)
    if d:
        return extract_uris(d)
    if '"outbounds"' in text and '"protocol"' in text:
        uris.extend(_parse_xray_json(text))
    for m in re.finditer(
        r"(?:^|\s)(vless|vmess|trojan|ss|hysteria2?|mvless)://[^\s]+",
        text, re.I | re.M,
    ):
        uris.append(m.group(0).strip())
    return uris


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
    print("[*] Бинарники Xray/Hysteria...")
    BinaryDownloader(root).ensure_all()

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
    print(f"[*] Уникальных: {len(uniq)}")
    if not uniq:
        print("[ERROR] Нет конфигов", file=sys.stderr)
        sys.exit(1)

    parsed = []
    for u in uniq:
        try:
            p = parse_uri(u)
            if p:
                parsed.append(p)
        except Exception:
            pass
    print(f"[*] Распарсено: {len(parsed)}")

    print("[*] Тестирование...")
    tester = ConnectionTester(
        vendor_path=str(root / "vendor"),
        core_engine_path=str(root / "core_engine"),
    )
    results = tester.test_uris(parsed)

    fast = [r for r in results
            if r.get("status") == "success"
            and 0 < r.get("ping_ms", -1) <= MAX_PING_MS]
    print(f"[*] <= {MAX_PING_MS} мс: {len(fast)}")

    renamed = [rename_config(r.get("uri", ""), i)
               for i, r in enumerate(fast, 1) if r.get("uri")]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(renamed))
    print(f"[OK] {len(renamed)} -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
