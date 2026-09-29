#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Temida Parser — сбор, реальный замер пинга и гео-флагов конфигов."""

import os, io, re, sys, json, time, base64, socket, zipfile, tempfile, subprocess
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.parse import urlparse, urlunparse, parse_qs, unquote, quote
from concurrent.futures import ThreadPoolExecutor, as_completed


# ---------- flagz (необязательный, для англ. фолбэка) ----------
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


# ---------- настройки ----------
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

OUTPUT_FILE        = "temida.txt"
TEST_URL           = "http://www.gstatic.com/generate_204"
REQUEST_TIMEOUT_MS = 3000
PING_LIMIT_MS      = 250
PING_ATTEMPTS      = 2
TCP_CHECK_TIMEOUT  = 3.0
WORKERS            = 20
FETCH_TIMEOUT      = 30
XRAY_URL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"

URI_RE       = re.compile(r"^(vless|vmess|trojan)://", re.I)
FLAG_RE      = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")
B64_BLOCK_RE = re.compile(r"base64:([A-Za-z0-9+/=]+)")


# ============================================================
#  ПОЛНЫЙ СЛОВАРЬ СТРАН (ISO 3166-1 alpha-2 → русское название)
# ============================================================

RU_COUNTRIES = {
    "AD": "Андорра",
    "AE": "ОАЭ",
    "AF": "Афганистан",
    "AG": "Антигуа и Барбуда",
    "AI": "Ангилья",
    "AL": "Албания",
    "AM": "Армения",
    "AO": "Ангола",
    "AQ": "Антарктида",
    "AR": "Аргентина",
    "AS": "Американское Самоа",
    "AT": "Австрия",
    "AU": "Австралия",
    "AW": "Аруба",
    "AX": "Аландские острова",
    "AZ": "Азербайджан",
    "BA": "Босния и Герцеговина",
    "BB": "Барбадос",
    "BD": "Бангладеш",
    "BE": "Бельгия",
    "BF": "Буркина-Фасо",
    "BG": "Болгария",
    "BH": "Бахрейн",
    "BI": "Бурунди",
    "BJ": "Бенин",
    "BL": "Сен-Бартелеми",
    "BM": "Бермуды",
    "BN": "Бруней",
    "BO": "Боливия",
    "BQ": "Бонайре",
    "BR": "Бразилия",
    "BS": "Багамы",
    "BT": "Бутан",
    "BV": "Остров Буве",
    "BW": "Ботсвана",
    "BY": "Беларусь",
    "BZ": "Белиз",
    "CA": "Канада",
    "CC": "Кокосовые острова",
    "CD": "Конго (ДРК)",
    "CF": "ЦАР",
    "CG": "Конго",
    "CH": "Швейцария",
    "CI": "Кот-д’Ивуар",
    "CK": "Острова Кука",
    "CL": "Чили",
    "CM": "Камерун",
    "CN": "Китай",
    "CO": "Колумбия",
    "CR": "Коста-Рика",
    "CU": "Куба",
    "CV": "Кабо-Верде",
    "CW": "Кюрасао",
    "CX": "Остров Рождества",
    "CY": "Кипр",
    "CZ": "Чехия",
    "DE": "Германия",
    "DJ": "Джибути",
    "DK": "Дания",
    "DM": "Доминика",
    "DO": "Доминикана",
    "DZ": "Алжир",
    "EC": "Эквадор",
    "EE": "Эстония",
    "EG": "Египет",
    "EH": "Западная Сахара",
    "ER": "Эритрея",
    "ES": "Испания",
    "ET": "Эфиопия",
    "FI": "Финляндия",
    "FJ": "Фиджи",
    "FK": "Фолкленды",
    "FM": "Микронезия",
    "FO": "Фареры",
    "FR": "Франция",
    "GA": "Габон",
    "GB": "Великобритания",
    "GD": "Гренада",
    "GE": "Грузия",
    "GF": "Французская Гвиана",
    "GG": "Гернси",
    "GH": "Гана",
    "GI": "Гибралтар",
    "GL": "Гренландия",
    "GM": "Гамбия",
    "GN": "Гвинея",
    "GP": "Гваделупа",
    "GQ": "Экваториальная Гвинея",
    "GR": "Греция",
    "GS": "Южная Георгия",
    "GT": "Гватемала",
    "GU": "Гуам",
    "GW": "Гвинея-Бисау",
    "GY": "Гайана",
    "HK": "Гонконг",
    "HM": "Остров Херд",
    "HN": "Гондурас",
    "HR": "Хорватия",
    "HT": "Гаити",
    "HU": "Венгрия",
    "ID": "Индонезия",
    "IE": "Ирландия",
    "IL": "Израиль",
    "IM": "Остров Мэн",
    "IN": "Индия",
    "IO": "Британская территория в Индийском океане",
    "IQ": "Ирак",
    "IR": "Иран",
    "IS": "Исландия",
    "IT": "Италия",
    "JE": "Джерси",
    "JM": "Ямайка",
    "JO": "Иордания",
    "JP": "Япония",
    "KE": "Кения",
    "KG": "Кыргызстан",
    "KH": "Камбоджа",
    "KI": "Кирибати",
    "KM": "Коморы",
    "KN": "Сент-Китс и Невис",
    "KP": "КНДР",
    "KR": "Южная Корея",
    "KW": "Кувейт",
    "KY": "Каймановы острова",
    "KZ": "Казахстан",
    "LA": "Лаос",
    "LB": "Ливан",
    "LC": "Сент-Люсия",
    "LI": "Лихтенштейн",
    "LK": "Шри-Ланка",
    "LR": "Либерия",
    "LS": "Лесото",
    "LT": "Литва",
    "LU": "Люксембург",
    "LV": "Латвия",
    "LY": "Ливия",
    "MA": "Марокко",
    "MC": "Монако",
    "MD": "Молдова",
    "ME": "Черногория",
    "MF": "Сен-Мартен",
    "MG": "Мадагаскар",
    "MH": "Маршалловы Острова",
    "MK": "Северная Македония",
    "ML": "Мали",
    "MM": "Мьянма",
    "MN": "Монголия",
    "MO": "Макао",
    "MP": "Северные Марианские острова",
    "MQ": "Мартиника",
    "MR": "Мавритания",
    "MS": "Монтсеррат",
    "MT": "Мальта",
    "MU": "Маврикий",
    "MV": "Мальдивы",
    "MW": "Малави",
    "MX": "Мексика",
    "MY": "Малайзия",
    "MZ": "Мозамбик",
    "NA": "Намибия",
    "NC": "Новая Каледония",
    "NE": "Нигер",
    "NF": "Остров Норфолк",
    "NG": "Нигерия",
    "NI": "Никарагуа",
    "NL": "Нидерланды",
    "NO": "Норвегия",
    "NP": "Непал",
    "NR": "Науру",
    "NU": "Ниуэ",
    "NZ": "Новая Зеландия",
    "OM": "Оман",
    "PA": "Панама",
    "PE": "Перу",
    "PF": "Французская Полинезия",
    "PG": "Папуа — Новая Гвинея",
    "PH": "Филиппины",
    "PK": "Пакистан",
    "PL": "Польша",
    "PM": "Сен-Пьер и Микелон",
    "PN": "Питкэрн",
    "PR": "Пуэрто-Рико",
    "PS": "Палестина",
    "PT": "Португалия",
    "PW": "Палау",
    "PY": "Парагвай",
    "QA": "Катар",
    "RE": "Реюньон",
    "RO": "Румыния",
    "RS": "Сербия",
    "RU": "Россия",
    "RW": "Руанда",
    "SA": "Саудовская Аравия",
    "SB": "Соломоновы Острова",
    "SC": "Сейшелы",
    "SD": "Судан",
    "SE": "Швеция",
    "SG": "Сингапур",
    "SH": "Остров Святой Елены",
    "SI": "Словения",
    "SJ": "Шпицберген и Ян-Майен",
    "SK": "Словакия",
    "SL": "Сьерра-Леоне",
    "SM": "Сан-Марино",
    "SN": "Сенегал",
    "SO": "Сомали",
    "SR": "Суринам",
    "SS": "Южный Судан",
    "ST": "Сан-Томе и Принсипи",
    "SV": "Сальвадор",
    "SX": "Синт-Мартен",
    "SY": "Сирия",
    "SZ": "Эсватини",
    "TC": "Тёркс и Кайкос",
    "TD": "Чад",
    "TF": "Французские Южные территории",
    "TG": "Того",
    "TH": "Таиланд",
    "TJ": "Таджикистан",
    "TK": "Токелау",
    "TL": "Восточный Тимор",
    "TM": "Туркменистан",
    "TN": "Тунис",
    "TO": "Тонга",
    "TR": "Турция",
    "TT": "Тринидад и Тобаго",
    "TV": "Тувалу",
    "TW": "Тайвань",
    "TZ": "Танзания",
    "UA": "Украина",
    "UG": "Уганда",
    "UM": "Внешние малые острова США",
    "US": "США",
    "UY": "Уругвай",
    "UZ": "Узбекистан",
    "VA": "Ватикан",
    "VC": "Сент-Винсент и Гренадины",
    "VE": "Венесуэла",
    "VG": "Британские Виргинские острова",
    "VI": "Виргинские Острова США",
    "VN": "Вьетнам",
    "VU": "Вануату",
    "WF": "Уоллис и Футуна",
    "WS": "Самоа",
    "XK": "Косово",
    "YE": "Йемен",
    "YT": "Майотта",
    "ZA": "ЮАР",
    "ZM": "Замбия",
    "ZW": "Зимбабве",
}


# ============================================================
#  ФЛАГИ И НАЗВАНИЯ
# ============================================================

def code_to_flag(code):
    if not code or len(code) != 2:
        return "\U0001F310"
    return "".join(chr(ord(c) + 0x1F1E6 - ord("A")) for c in code.upper())


def country_info(code):
    """'BY' → ('🇧🇾', 'Беларусь'). Фолбэки: словарь → flagz → код."""
    code = (code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return "\U0001F310", "Unknown"

    flag = code_to_flag(code)
    name = RU_COUNTRIES.get(code)
    if name:
        return flag, name
    if HAS_FLAGZ:
        try:
            return flag, flagz.by_code(code).name
        except Exception:
            pass
    return flag, code


# ============================================================
#  URL-энкодинг и загрузка
# ============================================================

def _encode_url(url: str) -> str:
    p = urlparse(url)
    return urlunparse((
        p.scheme, p.netloc,
        quote(p.path,     safe="/%"),
        quote(p.params,   safe=""),
        quote(p.query,    safe="=&%"),
        quote(p.fragment, safe="%"),
    ))


def fetch_url(url: str):
    safe = _encode_url(url)
    try:
        req = Request(safe, headers={"User-Agent": "Mozilla/5.0 (TemidaParser/1.0)"})
        with urlopen(req, timeout=FETCH_TIMEOUT) as r:
            raw = r.read()
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1")
    except Exception as e:
        print(f"[ERROR] {url[:60]}... -> {e}", file=sys.stderr)
        return None


# ============================================================
#  Base64 / Xray-JSON / URI-парсеры
# ============================================================

def _fix_b64(s):
    s = s.strip().replace("\n", "").replace("\r", "")
    m = len(s) % 4
    return s + "=" * (4 - m) if m else s


def _try_b64(text):
    c = text.strip()
    if not c or not re.fullmatch(r"[A-Za-z0-9+/=\s]+", c):
        return None
    try:
        dec = base64.b64decode(_fix_b64(c)).decode("utf-8", errors="ignore")
        return dec if URI_RE.search(dec) else None
    except Exception:
        return None


def _parse_xray_json(text):
    uris = []
    for m in re.finditer(r'"outbounds"\s*:\s*(\[.*?\])\s*[,}]', text, re.DOTALL):
        try:
            obs = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
        for ob in obs:
            if ob.get("protocol") not in ("vless", "vmess", "trojan"):
                continue
            try:
                vnext  = ob["settings"]["vnext"][0]
                addr   = vnext["address"]
                port   = vnext["port"]
                user   = vnext["users"][0]
                uid    = user["id"]
                flow   = user.get("flow", "")
                st     = ob.get("streamSettings", {})
                net    = st.get("network", "tcp")
                sec    = st.get("security", "")
                sni = pbk = sid = fp = ""
                if sec == "reality":
                    rs  = st.get("realitySettings", {})
                    sni = rs.get("serverName", "")
                    pbk = rs.get("publicKey", "")
                    sid = rs.get("shortId", "")
                    fp  = rs.get("fingerprint", "")
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
                uris.append(f"vless://{uid}@{addr}:{port}?{'&'.join(p)}#from-json")
            except (KeyError, IndexError, TypeError):
                continue
    return uris


def extract_uris(text):
    uris = []
    for m in B64_BLOCK_RE.finditer(text):
        d = _try_b64(m.group(1))
        if d:
            uris.extend(extract_uris(d))
    d = _try_b64(text)
    if d:
        return extract_uris(d)
    if '"outbounds"' in text and '"protocol"' in text:
        uris.extend(_parse_xray_json(text))
    for m in re.finditer(
        r"(?:^|\s)(vless|vmess|trojan)://[^\s]+",
        text, re.I | re.M,
    ):
        uris.append(m.group(0).strip())
    return uris


def _parse_vless(uri):
    u = urlparse(uri); q = parse_qs(u.query)
    uid  = unquote(u.username or "")
    host = u.hostname
    port = u.port
    if not (uid and host and port):
        return None
    net      = q.get("type", ["tcp"])[0]
    sec      = q.get("security", ["none"])[0]
    sni      = q.get("sni", [""])[0]
    flow     = q.get("flow", [""])[0]
    fp       = q.get("fp", [""])[0]
    pbk      = q.get("pbk", [""])[0]
    sid      = q.get("sid", [""])[0]
    path     = q.get("path", ["/"])[0]
    host_hdr = q.get("host", [""])[0]
    svc      = q.get("serviceName", [""])[0]

    stream = {"network": net}
    if sec == "tls":
        stream["security"]    = "tls"
        stream["tlsSettings"] = {"serverName": sni or host, "allowInsecure": True}
    elif sec == "reality":
        stream["security"]        = "reality"
        stream["realitySettings"] = {
            "serverName": sni, "fingerprint": fp or "chrome",
            "publicKey": pbk, "shortId": sid, "show": False,
        }
    else:
        stream["security"] = "none"
    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_hdr or host}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": svc}

    return {
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [
            {"id": uid, "encryption": "none", "flow": flow}]}]},
        "streamSettings": stream,
    }


def _parse_vmess(uri):
    b64 = uri[8:]
    pad = "=" * (-len(b64) % 4)
    d   = json.loads(base64.b64decode(b64 + pad).decode("utf-8"))
    host = d["add"]
    port = int(d["port"])
    net  = d.get("net", "tcp")
    tls  = d.get("tls", "")
    sni  = d.get("sni", "") or d.get("host", "")
    path = d.get("path", "/")
    hh   = d.get("host", "")

    stream = {"network": net}
    if tls:
        stream["security"]    = "tls"
        stream["tlsSettings"] = {"serverName": sni or host, "allowInsecure": True}
    else:
        stream["security"] = "none"
    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": hh or host}}
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
    u = urlparse(uri); q = parse_qs(u.query)
    pwd  = unquote(u.username or "")
    host = u.hostname
    port = u.port or 443
    if not (pwd and host):
        return None
    sec  = q.get("security", ["tls"])[0]
    sni  = q.get("sni", [""])[0] or host
    net  = q.get("type", ["tcp"])[0]
    path = q.get("path", ["/"])[0]
    hh   = q.get("host", [""])[0]

    stream = {"network": net, "security": sec}
    if sec == "tls":
        stream["tlsSettings"] = {"serverName": sni, "allowInsecure": True}
    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": hh or host}}

    return {
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": pwd}]},
        "streamSettings": stream,
    }


def uri_to_outbound(uri):
    try:
        if uri.startswith("vless://"):  return _parse_vless(uri)
        if uri.startswith("vmess://"):  return _parse_vmess(uri)
        if uri.startswith("trojan://"): return _parse_trojan(uri)
    except Exception:
        return None
    return None


def extract_host_port(outbound):
    proto = outbound.get("protocol")
    s     = outbound.get("settings", {})
    try:
        if proto in ("vless", "vmess"):
            v = s["vnext"][0]
            return v["address"], int(v["port"])
        if proto == "trojan":
            v = s["servers"][0]
            return v["address"], int(v["port"])
    except (KeyError, IndexError, TypeError, ValueError):
        pass
    return None, None


# ============================================================
#  GeoIP (ip-api.com, batch)
# ============================================================

def resolve_ips(hosts):
    out = {}
    def _one(h):
        try:
            return h, socket.gethostbyname(h)
        except Exception:
            return h, None
    with ThreadPoolExecutor(max_workers=50) as ex:
        for h, ip in ex.map(_one, hosts):
            if ip:
                out[h] = ip
    return out


def geo_lookup(ips):
    ips = list({ip for ip in ips if ip})
    result = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        payload = [{"query": ip, "fields": "query,countryCode"} for ip in chunk]
        try:
            req = Request(
                "http://ip-api.com/batch?fields=query,countryCode",
                data=json.dumps(payload).encode("utf-8"),
                method="POST",
            )
            req.add_header("Content-Type", "application/json")
            with urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
            for item in data:
                q  = item.get("query")
                cc = item.get("countryCode")
                if q and cc:
                    result[q] = cc
        except Exception as e:
            print(f"[WARN] geo batch {i//100}: {e}", file=sys.stderr)
        time.sleep(0.5)
    return result


# ============================================================
#  Xray + тест
# ============================================================

def ensure_xray(root: Path):
    xray_dir = root / "xray"
    xray_bin = xray_dir / "xray"
    if not xray_bin.exists():
        print("[*] Скачиваю Xray-core...")
        xray_dir.mkdir(parents=True, exist_ok=True)
        with urlopen(XRAY_URL, timeout=180) as r:
            data = r.read()
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            z.extractall(xray_dir)
        xray_bin.chmod(0o755)
    try:
        v = subprocess.run([str(xray_bin), "version"],
                           capture_output=True, text=True, timeout=5)
        first = (v.stdout or v.stderr).splitlines()
        print(f"    Xray: {first[0] if first else 'OK'}")
    except Exception as e:
        print(f"    [!] version: {e}")
    return xray_bin, xray_dir


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def tcp_check(host, port, timeout=TCP_CHECK_TIMEOUT):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _ping_via_socks(port):
    secs = int(REQUEST_TIMEOUT_MS / 1000) or 3
    pings = []
    for _ in range(PING_ATTEMPTS):
        start = time.time()
        try:
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--socks5-hostname", f"127.0.0.1:{port}",
                 "--connect-timeout", str(secs),
                 "--max-time", str(secs),
                 TEST_URL],
                capture_output=True, text=True,
                timeout=secs + 2,
            )
        except subprocess.TimeoutExpired:
            continue
        if r.stdout.strip() in ("200", "204"):
            pings.append((time.time() - start) * 1000)
    return min(pings) if pings else None


def test_one(xray_bin, xray_dir, outbound):
    port = _free_port()
    cfg = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": port, "listen": "127.0.0.1", "protocol": "socks",
            "settings": {"udp": False, "auth": "noauth"},
        }],
        "outbounds": [outbound],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
        cfg_path = f.name

    proc = None
    try:
        env = os.environ.copy()
        env["XRAY_LOCATION_ASSET"] = str(xray_dir)
        proc = subprocess.Popen(
            [str(xray_bin), "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
        )
        deadline = time.time() + 3.0
        started = False
        while time.time() < deadline:
            if proc.poll() is not None:
                return None
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    started = True
                    break
            except OSError:
                time.sleep(0.05)
        if not started:
            return None
        return _ping_via_socks(port)
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


def rename_config(uri, idx, code):
    flag, name = country_info(code)
    return f"{uri.split('#', 1)[0]}#{flag} {name} {idx:02d} TEMIDA PARS"


# ============================================================
#  MAIN
# ============================================================

def main():
    root = Path("./")
    xray_bin, xray_dir = ensure_xray(root)

    # 1. Сбор URI
    all_uris = []
    for src in SOURCES:
        print(f"[*] {src[:70]}...")
        t = fetch_url(src)
        if not t:
            print("    -> пропущен")
            continue
        found = extract_uris(t)
        print(f"    -> {len(found)} URI")
        all_uris.extend(found)

    seen, uniq = set(), []
    for u in all_uris:
        k = u.split("#", 1)[0]
        if k not in seen:
            seen.add(k); uniq.append(u)
    print(f"[*] Уникальных URI: {len(uniq)}")
    if not uniq:
        print("[ERROR] Нет конфигов", file=sys.stderr); sys.exit(1)

    # 2. Парсинг
    parsed = []
    for u in uniq:
        ob = uri_to_outbound(u)
        if not ob:
            continue
        h, p = extract_host_port(ob)
        if h and p:
            parsed.append((u, ob, h, p))
    print(f"[*] Распарсено: {len(parsed)}")
    if not parsed:
        print("[ERROR] Ничего не распарсено", file=sys.stderr); sys.exit(1)

    # 3. Резолв + GeoIP
    print("[*] Резолвлю IP-адреса серверов...")
    hosts = {h for _, _, h, _ in parsed}
    host_to_ip = resolve_ips(hosts)
    print(f"    разрезолвлено {len(host_to_ip)} из {len(hosts)}")

    print("[*] Определяю страны через ip-api.com...")
    ip_to_cc = geo_lookup(host_to_ip.values())
    print(f"    гео найдено для {len(ip_to_cc)} IP")

    host_to_cc = {}
    for h, ip in host_to_ip.items():
        if ip in ip_to_cc:
            host_to_cc[h] = ip_to_cc[ip]

    # 4. TCP pre-check
    print(f"[*] TCP-проверка host:port (timeout {TCP_CHECK_TIMEOUT}s, потоков {WORKERS})...")
    alive = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(tcp_check, h, p): (u, ob, h, p) for u, ob, h, p in parsed}
        for f in as_completed(futs):
            if f.result():
                alive.append(futs[f])
    print(f"    TCP-reachable: {len(alive)} / {len(parsed)}")
    if not alive:
        print("[ERROR] Ни один сервер не отвечает по TCP", file=sys.stderr); sys.exit(1)

    # 5. Полный тест
    print(f"[*] Реальный тест: max-time={REQUEST_TIMEOUT_MS}ms, "
          f"attempts={PING_ATTEMPTS}, фильтр <= {PING_LIMIT_MS}ms")
    results = []
    any_ok = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(test_one, xray_bin, xray_dir, ob): (u, h)
                for u, ob, h, _ in alive}
        done = 0
        for f in as_completed(futs):
            done += 1
            u, h = futs[f]
            try:
                ping = f.result()
            except Exception:
                ping = None
            if ping is not None:
                any_ok += 1
                if ping <= PING_LIMIT_MS:
                    results.append((u, h, ping))
            if done % 50 == 0:
                print(f"    [{done}/{len(alive)}] рабочих: {len(results)} "
                      f"(успешных ответов: {any_ok})")

    print(f"[*] Успешных ответов всего: {any_ok}")
    print(f"[*] Из них <= {PING_LIMIT_MS} мс: {len(results)}")

    # 6. Сортировка + переименование
    results.sort(key=lambda x: x[2])
    renamed = [rename_config(u, i, host_to_cc.get(h, ""))
               for i, (u, h, _) in enumerate(results, 1)]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(renamed))
    print(f"[OK] {len(renamed)} -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
