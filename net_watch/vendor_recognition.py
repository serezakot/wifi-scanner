#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vendor_recognition.py — многосигнальный классификатор устройств локальной сети.

это модуль, который вызывает arp_scan.py: для каждого НОВОГО устройства (arp_scan.py уже знает его
MAC/IP) вызывается identify_devices() и возвращает уточнённый vendor

Идея классификации не менялась: ни один отдельный признак (вендор по
MAC, открытый порт, TTL...) не даёт 100%-й гарантии типа устройства,
поэтому вместо жёсткой цепочки if/elif используется система накопления
улик — каждый источник данных добавляет "голос" за один или несколько
типов устройства со своим весом, побеждает тип с наибольшей суммой.

Источники данных:
    1. Офлайн-база OUI пакета `manuf`            — вендор по MAC
    2. Bettercap REST API (сессия + события)     — если Bettercap запущен
    3. TCP-порт-скан (20+ портов) + HTTP-баннер   — сигнатуры служб
    4. NetBIOS Name Service (UDP/137)             — имя ПК на Windows
    5. mDNS/Bonjour (через zeroconf)              — AirPlay/Chromecast/...
    6. SSDP/UPnP (M-SEARCH)                       — XML-описание устройства
    7. TTL из ping                                — грубая подсказка по ОС
    8. Ручные метки known_devices.json            — для приватных/рандо-
       мизированных MAC (iOS/Android) единственный способ 100% гарантии
    9. Tuya LAN-протокол (UDP 6666/6667)          — умные розетки/лампы
   10. TP-Link Kasa/Tapo (UDP 9999)                — прямой опрос
   11. Shelly HTTP API (/shelly)                   — прямой опрос

Установка зависимостей:
    pip install manuf zeroconf requests --break-system-packages

Важно: используйте только в сети, которой вы владеете или на
сканирование которой у вас есть разрешение.
"""

import json
import os
import re
import socket
import struct
import subprocess
import time
import select
import hashlib
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

try:
    from manuf import manuf as _manuf_mod
    _MANUF_AVAILABLE = True
except ImportError:
    _MANUF_AVAILABLE = False

try:
    from zeroconf import Zeroconf, ServiceBrowser
    _ZEROCONF_AVAILABLE = True
except ImportError:
    _ZEROCONF_AVAILABLE = False

try:
    from Crypto.Cipher import AES as _AES
    _PYCRYPTODOME_AVAILABLE = True
except ImportError:
    _PYCRYPTODOME_AVAILABLE = False


BETTERCAP_URL = "http://127.0.0.1:8081/api/session"
EVENTS_URL = "http://127.0.0.1:8081/api/events"
BETTERCAP_AUTH = HTTPBasicAuth("netwatch", "192837465")
BETTERCAP_TIMEOUT = 3

PORT_TIMEOUT = 0.5
PING_TIMEOUT = 1
HTTP_TIMEOUT = 2
MDNS_SWEEP_SECONDS = 4
SSDP_SWEEP_SECONDS = 3
NBNS_TIMEOUT = 1.0
MAX_WORKERS = 32

KNOWN_DEVICES_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "known_devices.json"
)

# Небольшой запасной словарь OUI — ТОЛЬКО для префиксов, которых нет в
# офлайн-базе пакета manuf (проверено: 80:af:ca, 28:70:3e, 3c:6a:d2 в его
# базе отсутствуют на момент написания). Если manuf найдёт вендора — его
# ответ имеет приоритет, т.к. это живая, регулярно обновляемая база.
FALLBACK_OUIS = {
    "80:af:ca": "Cudy Technology (Wi-Fi адаптер / роутер)",
    "28:70:3e": "TP-Link",
    "3c:6a:d2": "AsusTek",
}

# Порт -> (название службы, {тип устройства: вес})
PORT_SIGNATURES = {
    21:    ("FTP",                   {"Сетевое хранилище (NAS)": 15}),
    22:    ("SSH",                   {"Linux/Unix / встраиваемое устройство": 15}),
    23:    ("Telnet",                {"Сетевое оборудование / IoT (Telnet)": 20}),
    139:   ("NetBIOS-SSN",           {"ПК на Windows": 25}),
    445:   ("SMB",                   {"ПК на Windows": 25, "NAS / Samba-сервер (Linux)": 25}),
    548:   ("AFP",                   {"Устройство Apple / NAS": 25}),
    554:   ("RTSP",                  {"IP-камера видеонаблюдения": 55}),
    631:   ("IPP",                   {"Сетевой принтер": 40}),
    1883:  ("MQTT",                  {"IoT-устройство (умный дом)": 30}),
    3389:  ("RDP",                   {"ПК на Windows": 55}),
    5000:  ("UPnP/Synology-DSM",     {"Synology NAS": 30}),
    5555:  ("ADB",                   {"Устройство Android": 45}),
    8008:  ("Chromecast (HTTP)",     {"Google Chromecast / Google TV": 50}),
    8009:  ("Chromecast (CAST v2)",  {"Google Chromecast / Google TV": 55}),
    9100:  ("JetDirect / RAW-печать", {"Сетевой принтер": 60}),
    32400: ("Plex Media Server",     {"Медиа-сервер (Plex)": 45}),
    62078: ("iOS lockdownd",         {"Apple iPhone / iPad": 60}),
}

# Порты, с которых дополнительно снимаем HTTP(S)-баннер: port -> is_https
HTTP_BANNER_PORTS = {80: False, 443: True, 8080: False, 8443: True}

SCAN_PORTS = sorted(set(PORT_SIGNATURES) | set(HTTP_BANNER_PORTS))

HTTP_KEYWORDS = {
    "mikrotik":    "Сетевое оборудование (роутер/AP)",
    "routeros":    "Сетевое оборудование (роутер/AP)",
    "dd-wrt":      "Сетевое оборудование (роутер/AP)",
    "openwrt":     "Сетевое оборудование (роутер/AP)",
    "synology":    "Synology NAS",
    "qnap":        "QNAP NAS",
    "hikvision":   "IP-камера видеонаблюдения",
    "dahua":       "IP-камера видеонаблюдения",
    "ip camera":   "IP-камера видеонаблюдения",
    "hp laserjet": "Сетевой принтер",
    "laserjet":    "Сетевой принтер",
    "printer":     "Сетевой принтер",
    "roku":        "Медиаплеер (Roku)",
    "smart tv":    "Смарт-ТВ",
    "webos":       "Смарт-ТВ (LG webOS)",
    "tizen":       "Смарт-ТВ (Samsung Tizen)",
    "tasmota":     "IoT-устройство на прошивке Tasmota (умная розетка/реле)",
    "esphome":     "IoT-устройство на прошивке ESPHome (DIY умный дом)",
    "sonoff":      "IoT-устройство Sonoff",
    "espurna":     "IoT-устройство на прошивке ESPurna",
    "shelly":      "Умное реле/розетка Shelly",
    "philips hue": "Мост Philips Hue (умное освещение)",
}

MDNS_SERVICE_HINTS = {
    "_airplay._tcp.local.":         ("Apple TV / AirPlay-приёмник", 40),
    "_raop._tcp.local.":            ("Apple-устройство (AirPlay Audio)", 30),
    "_companion-link._tcp.local.":  ("Устройство Apple (iPhone/iPad/Mac)", 25),
    "_device-info._tcp.local.":     ("Устройство Apple", 15),
    "_googlecast._tcp.local.":      ("Google Chromecast / Google TV", 45),
    "_ipp._tcp.local.":             ("Сетевой принтер", 40),
    "_ipps._tcp.local.":            ("Сетевой принтер", 40),
    "_printer._tcp.local.":         ("Сетевой принтер", 35),
    "_smb._tcp.local.":             ("ПК/NAS с сетевым доступом", 15),
    "_ssh._tcp.local.":             ("Linux/Unix / встраиваемое устройство", 10),
    "_spotify-connect._tcp.local.": ("Медиаустройство (Spotify Connect)", 20),
    "_homekit._tcp.local.":         ("Устройство умного дома (HomeKit)", 25),
    "_hap._tcp.local.":             ("Устройство умного дома (HomeKit)", 25),
    "_workstation._tcp.local.":     ("Рабочая станция (Unix)", 10),
    "_hue._tcp.local.":             ("Мост Philips Hue (умное освещение)", 45),
    "_esphome._tcp.local.":         ("IoT-устройство на прошивке ESPHome (DIY умный дом)", 40),
    "_wled._tcp.local.":            ("Адресная LED-лента WLED", 45),
    "_shelly._tcp.local.":          ("Умное реле/розетка Shelly", 45),
    "_sonos._tcp.local.":           ("Колонка Sonos", 40),
    "_soundtouch._tcp.local.":      ("Колонка Bose SoundTouch", 40),
    "_axis-video._tcp.local.":      ("IP-камера Axis", 45),
    "_matterc._udp.local.":         ("Устройство умного дома (Matter)", 25),
    "_matter._tcp.local.":          ("Устройство умного дома (Matter)", 25),
    "_amzn-wplay._tcp.local.":      ("Устройство Amazon (Echo/Fire TV)", 35),
}

COMMON_MDNS_SERVICES = list(MDNS_SERVICE_HINTS.keys())

# Для каких служб TXT-запись содержит точное имя модели — и под каким ключом
MDNS_MODEL_TXT_KEYS = {
    "_googlecast._tcp.local.": ("md",),
    "_airplay._tcp.local.":    ("model",),
    "_raop._tcp.local.":       ("model",),
    "_hap._tcp.local.":        ("md",),
    "_hue._tcp.local.":        ("modelid",),
}

# --- Tuya (LAN-протокол, открытая документация проекта tinytuya, MIT) ---
TUYA_UDP_PORTS = (6666, 6667)          # 3.1 (открытый) и 3.3+ (шифрованный)
TUYA_PREFIX_VALUE = 0x000055AA
# Фиксированный ключ, который Tuya использует ИСКЛЮЧИТЕЛЬНО для расшифровки
# собственного широковещательного анонса устройства в локальной сети (не для
# управления и не для реальных команд — это не обход какой-либо защиты).
TUYA_UDP_KEY = hashlib.md5(b"yGAdlopoPVldABfn").digest()

# --- TP-Link Kasa/Tapo (легаси LAN-протокол, порт 9999) ---
KASA_PORT = 9999
KASA_DISCOVERY_QUERY = json.dumps({"system": {"get_sysinfo": {}}}).encode()


# =========================================================================
#                          БАЗОВАЯ СТРУКТУРА УСТРОЙСТВА
# =========================================================================

@dataclass
class Device:
    ip: str
    mac: str
    vendor: str = ""
    hostname: str = ""
    is_gateway: bool = False
    open_ports: set = field(default_factory=set)
    http_info: dict = field(default_factory=dict)      # port -> (server, title)
    nbns_name: str = ""
    nbns_workgroup: str = ""
    mdns_names: list = field(default_factory=list)
    mdns_services: list = field(default_factory=list)
    mdns_models: list = field(default_factory=list)
    ssdp_info: dict = field(default_factory=dict)
    ttl: Optional[int] = None
    bettercap_events: list = field(default_factory=list)
    tuya_info: dict = field(default_factory=dict)
    kasa_info: dict = field(default_factory=dict)
    shelly_info: dict = field(default_factory=dict)
    scores: dict = field(default_factory=lambda: defaultdict(float))
    evidence_log: list = field(default_factory=list)

    def add_evidence(self, device_type: str, weight: float, reason: str):
        self.scores[device_type] += weight
        self.evidence_log.append(f"{reason}  →  «{device_type}» (+{weight:.0f})")

    def classify(self):
        if not self.scores:
            return "Неизвестный клиент", 0
        best_type = max(self.scores, key=self.scores.get)
        confidence = min(100, int(round(self.scores[best_type])))
        return best_type, confidence


# =========================================================================
#                          ВСПОМОГАТЕЛЬНЫЕ УТИЛИТЫ
# =========================================================================

def is_locally_administered(mac: str) -> bool:
    """Бит U/L (0x02) первого байта MAC — признак приватного/рандомизированного
    адреса (характерно для iOS 14+/Android 10+ с включённой приватностью Wi-Fi).
    Для таких адресов ЛЮБАЯ база OUI бессильна в принципе — это не баг скрипта,
    а сознательное решение производителя ОС."""
    try:
        first_byte = int(mac.split(":")[0], 16)
        return bool(first_byte & 0x02)
    except Exception:
        return False


_mac_parser = _manuf_mod.MacParser() if _MANUF_AVAILABLE else None


def get_vendor_by_mac(mac: str) -> str:
    prefix = mac.lower()[:8]
    if prefix in FALLBACK_OUIS:
        return FALLBACK_OUIS[prefix]
    if _mac_parser:
        vendor = _mac_parser.get_manuf_long(mac) or _mac_parser.get_manuf(mac)
        if vendor:
            return vendor
    if is_locally_administered(mac):
        return "Приватный/рандомизированный MAC (вендор недоступен)"
    return "Неизвестный вендор"


def load_known_devices() -> dict:
    if os.path.exists(KNOWN_DEVICES_PATH):
        try:
            with open(KNOWN_DEVICES_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_known_device(mac: str, label: str):
    """Сохранить постоянную ручную метку для MAC (высшая по весу улика,
    см. apply_known_device_evidence). CLI для этого больше нет, но функция
    остаётся — вызвать её можно откуда угодно, например из своего скрипта:
    `python3 -c "import test; test.save_known_device('AA:BB:...', 'Мой iPhone')"`."""
    data = load_known_devices()
    data[mac.lower()] = label
    with open(KNOWN_DEVICES_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def get_default_gateway() -> str:
    try:
        out = subprocess.check_output(["ip", "route"], text=True)
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


# =========================================================================
#                          BETTERCAP REST API
# =========================================================================

def fetch_bettercap_data():
    session_data, events_data = None, []
    try:
        r1 = requests.get(BETTERCAP_URL, auth=BETTERCAP_AUTH, timeout=BETTERCAP_TIMEOUT)
        if r1.status_code == 200:
            session_data = r1.json()
        r2 = requests.get(EVENTS_URL, auth=BETTERCAP_AUTH, timeout=BETTERCAP_TIMEOUT)
        if r2.status_code == 200:
            events_data = r2.json()
    except Exception:
        pass  # Bettercap недоступен — продолжаем без него, это не ошибка
    return session_data, events_data


def build_bettercap_hosts(bc_data) -> dict:
    hosts = {}
    if not bc_data:
        return hosts
    gw = bc_data.get("gateway", {}) or {}
    if gw.get("mac"):
        hosts[gw["mac"].lower()] = {
            "hostname": gw.get("hostname", "gateway"),
            "vendor": gw.get("vendor", ""),
        }
    for host in bc_data.get("lan", {}).get("hosts", []):
        h_mac = (host.get("mac") or "").lower()
        if h_mac:
            hosts[h_mac] = {
                "hostname": host.get("hostname", ""),
                "vendor": host.get("vendor", ""),
            }
    return hosts


def build_ip_events(bc_events) -> dict:
    ip_events = defaultdict(list)
    if isinstance(bc_events, list):
        for event in bc_events:
            text = str(event.get("text", ""))
            for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text):
                ip_events[ip].append(text)
    return ip_events


# =========================================================================
#                          TCP ПОРТ-СКАН + HTTP-БАННЕР
# =========================================================================

def scan_ports(ip: str, ports=SCAN_PORTS, timeout=PORT_TIMEOUT) -> set:
    open_ports = set()

    def check(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return port
        except OSError:
            pass
        return None

    with ThreadPoolExecutor(max_workers=max(1, len(ports))) as ex:
        for res in ex.map(check, ports):
            if res:
                open_ports.add(res)
    return open_ports


def grab_http_banner(ip: str, port: int, https: bool):
    scheme = "https" if https else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT, verify=False, allow_redirects=True)
        server = r.headers.get("Server", "")
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""
        return server, title
    except requests.RequestException:
        return "", ""


# =========================================================================
#                          NETBIOS NAME SERVICE (UDP/137)
# =========================================================================

def _encode_netbios_name(name: str = "*") -> bytes:
    raw = (name + "\x00" * 16)[:16].encode("latin-1", errors="replace")
    encoded = bytearray()
    for b in raw:
        encoded.append(0x41 + (b >> 4))
        encoded.append(0x41 + (b & 0x0F))
    return bytes([len(encoded)]) + bytes(encoded) + b"\x00"


def query_nbns(ip: str, timeout=NBNS_TIMEOUT):
    """NBSTAT-запрос (RFC 1002 §4.2.18) — просим у хоста список его NetBIOS-имён.
    Возвращает (имя_компьютера, рабочая_группа) либо ("", "") если хост не
    отвечает по NetBIOS (типично для не-Windows устройств — это нормально,
    а не ошибка)."""
    packet = (
        struct.pack(">H", 0x1337)      # transaction id
        + struct.pack(">H", 0x0000)    # flags: обычный запрос
        + struct.pack(">HHHH", 1, 0, 0, 0)  # QDCOUNT=1, остальные 0
        + _encode_netbios_name("*")
        + struct.pack(">HH", 0x0021, 0x0001)  # QTYPE=NBSTAT, QCLASS=IN
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (ip, 137))
            data, _ = s.recvfrom(2048)
    except OSError:
        return "", ""
    return _parse_nbns_response(data)


def _parse_nbns_response(data: bytes):
    try:
        if len(data) < 57:
            return "", ""
        offset = 12                                    # конец заголовка
        name_len = data[offset]
        offset += 1 + name_len + 1                      # закодированное имя + 0x00
        offset += 2 + 2 + 4                              # TYPE + CLASS + TTL
        offset += 2                                       # RDLENGTH (значение не нужно)
        num_names = data[offset]
        offset += 1

        hostname, workgroup = "", ""
        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            raw_name = data[offset:offset + 15].decode("ascii", errors="replace").strip()
            suffix = data[offset + 15]
            flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]
            is_group = bool(flags & 0x8000)
            if is_group and suffix == 0x00 and not workgroup:
                workgroup = raw_name
            elif not is_group and suffix == 0x00 and not hostname:
                hostname = raw_name
            offset += 18
        return hostname, workgroup
    except Exception:
        return "", ""


# =========================================================================
#                          mDNS / BONJOUR (через zeroconf)
# =========================================================================

def _txt_get(properties: dict, *keys) -> str:
    """properties — словарь TXT-записи mDNS (ключи/значения в bytes)."""
    for k in keys:
        v = properties.get(k.encode() if isinstance(k, str) else k)
        if v is not None:
            return v.decode(errors="replace") if isinstance(v, bytes) else str(v)
    return ""


def mdns_discover(sweep_seconds=MDNS_SWEEP_SECONDS) -> dict:
    """ip -> {"services": [...], "names": [...], "models": [...]}
    "models" — точное имя модели устройства, если оно было в TXT-записи
    (например, у Chromecast/AirPlay/HomeKit/Hue устройство само сообщает
    свою модель — это не догадка, а прямой ответ устройства)."""
    if not _ZEROCONF_AVAILABLE:
        return {}

    results = defaultdict(lambda: {"services": set(), "names": set(), "models": set()})

    class _Listener:
        def add_service(self, zc, service_type, name):
            info = zc.get_service_info(service_type, name, timeout=800)
            if not info:
                return
            props = info.properties or {}
            model = ""
            keys = MDNS_MODEL_TXT_KEYS.get(service_type)
            if keys:
                model = _txt_get(props, *keys)
            friendly = _txt_get(props, "fn")  # friendly name (Chromecast и др.)
            server_name = (info.server or "").rstrip(".")

            for addr in info.parsed_addresses():
                if ":" in addr:   # пропускаем IPv6, оставляем IPv4 для сопоставления с ARP
                    continue
                entry = results[addr]
                entry["services"].add(service_type)
                short_name = name.split(".")[0]
                if short_name:
                    entry["names"].add(short_name)
                if server_name:
                    entry["names"].add(server_name)
                if friendly:
                    entry["names"].add(friendly)
                if model:
                    entry["models"].add(model)

        def update_service(self, zc, service_type, name):
            pass

        def remove_service(self, zc, service_type, name):
            pass

    zc = Zeroconf()
    try:
        ServiceBrowser(zc, COMMON_MDNS_SERVICES, _Listener())
        time.sleep(sweep_seconds)
    finally:
        zc.close()

    return {ip: {"services": list(v["services"]), "names": list(v["names"]), "models": list(v["models"])}
            for ip, v in results.items()}


# =========================================================================
#                          SSDP / UPnP (M-SEARCH)
# =========================================================================

def ssdp_discover(sweep_seconds=SSDP_SWEEP_SECONDS) -> dict:
    """Один multicast-запрос слышат все UPnP-устройства сети разом."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()

    results = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(sweep_seconds)
        sock.sendto(msg, ("239.255.255.250", 1900))

        end_time = time.time() + sweep_seconds
        while time.time() < end_time:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            headers = _parse_ssdp_headers(data.decode(errors="ignore"))
            entry = results.setdefault(addr[0], {})
            entry.update({k: v for k, v in headers.items() if v})
        sock.close()
    except OSError:
        return results

    for ip, info in results.items():
        location = info.get("location")
        if location:
            info.update(_fetch_ssdp_description(location))
    return results


def _parse_ssdp_headers(raw: str) -> dict:
    headers = {}
    for line in raw.split("\r\n")[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return {
        "server": headers.get("server", ""),
        "location": headers.get("location", ""),
        "st": headers.get("st", ""),
    }


def _fetch_ssdp_description(location_url: str) -> dict:
    try:
        r = requests.get(location_url, timeout=HTTP_TIMEOUT)
        text = r.text

        def _tag(name):
            m = re.search(fr"<{name}>(.*?)</{name}>", text, re.IGNORECASE | re.DOTALL)
            return m.group(1).strip() if m else ""

        return {
            "manufacturer": _tag("manufacturer"),
            "modelName": _tag("modelName"),
            "friendlyName": _tag("friendlyName"),
        }
    except requests.RequestException:
        return {}


# =========================================================================
#                          IoT-ЭКОСИСТЕМЫ: Tuya / Kasa / Shelly
# =========================================================================
# Это те же самые локальные протоколы обнаружения, которые используют
# официальные приложения (Smart Life/Tuya Smart, Kasa) при поиске устройств
# в ВАШЕЙ ЖЕ сети — не эксплойты и не обход авторизации, а штатные
# незащищённые (по задумке производителя) discovery-запросы/анонсы.

def _aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    cipher = _AES.new(key, _AES.MODE_ECB)
    padded = cipher.decrypt(data)
    pad_len = padded[-1]
    if 0 < pad_len <= 16:
        return padded[:-pad_len]
    return padded


def _tuya_decode_payload(data: bytes):
    """Разбирает кадр LAN-протокола Tuya (заголовок 0x000055AA, см. проект
    tinytuya, MIT-лицензия) и при возможности снимает AES-ECB с фиксированным
    "широковещательным" ключом. Возвращает dict или None."""
    try:
        if len(data) < 24:
            return None
        prefix, _seqno, _cmd, length = struct.unpack(">4I", data[:16])
        if prefix != TUYA_PREFIX_VALUE:
            return None
        body = data[16:16 + length]
        payload = body[:-8]  # отбрасываем CRC(4) + suffix(4)

        if payload[:1] == b"{" and payload[-1:] == b"}":
            return json.loads(payload.decode(errors="ignore"))

        if _PYCRYPTODOME_AVAILABLE:
            decrypted = _aes_ecb_decrypt(TUYA_UDP_KEY, payload)
            return json.loads(decrypted.decode(errors="ignore"))
        return None
    except Exception:
        return None


def tuya_discover(sweep_seconds=SSDP_SWEEP_SECONDS) -> dict:
    """Пассивно слушаем самоанонсы Tuya-совместимых устройств на UDP 6666/6667.
    Под платформой Tuya продаётся огромное число розеток/ламп/датчиков под
    десятками разных брендов — это единственный признак, который их всех
    объединяет. ip -> {"gwId":..., "productKey":..., "version":...}"""
    results = {}
    socks = []
    for port in TUYA_UDP_PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            socks.append(s)
        except OSError:
            pass  # порт занят/нет прав — просто теряем этот источник улик

    if not socks:
        return results

    end_time = time.time() + sweep_seconds
    try:
        while True:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
            ready, _, _ = select.select(socks, [], [], remaining)
            for s in ready:
                try:
                    data, addr = s.recvfrom(4096)
                except OSError:
                    continue
                ip = addr[0]
                entry = results.setdefault(ip, {"detected": True})
                parsed = _tuya_decode_payload(data)
                if parsed:
                    entry["gwId"] = parsed.get("gwId", entry.get("gwId", ""))
                    entry["productKey"] = parsed.get("productKey", entry.get("productKey", ""))
                    entry["version"] = str(parsed.get("version", entry.get("version", "")))
    finally:
        for s in socks:
            s.close()
    return results


def _kasa_xor_encrypt(data: bytes) -> bytes:
    key = 171
    out = bytearray()
    for b in data:
        key ^= b
        out.append(key)
    return bytes(out)


def _kasa_xor_decrypt(data: bytes) -> bytes:
    key = 171
    out = bytearray()
    for c in data:
        out.append(key ^ c)
        key = c
    return bytes(out)


def query_kasa(ip: str, timeout=1.0):
    """Легаси LAN-протокол TP-Link Kasa/Tapo (порт 9999, без аутентификации по
    задумке производителя — этим же запросом пользуется приложение Kasa)."""
    try:
        payload = _kasa_xor_encrypt(KASA_DISCOVERY_QUERY)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (ip, KASA_PORT))
            data, _ = s.recvfrom(4096)
        info = json.loads(_kasa_xor_decrypt(data).decode(errors="ignore"))
        return info.get("system", {}).get("get_sysinfo", {})
    except Exception:
        return None


def probe_shelly(ip: str, timeout=HTTP_TIMEOUT):
    """У устройств Shelly (Gen1 и Gen2+) есть незащищённый эндпоинт /shelly,
    который сразу отдаёт JSON с точной моделью — так же, как его использует
    официальное приложение Shelly Cloud/Smart Control при первой настройке."""
    try:
        r = requests.get(f"http://{ip}/shelly", timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict) and any(k in data for k in ("type", "model", "app")):
                return data
    except Exception:
        pass
    return None


# =========================================================================
#                          TTL (ping)
# =========================================================================

def get_ttl(ip: str) -> Optional[int]:
    try:
        out = subprocess.run(
            ["ping", "-c", "1", "-W", str(PING_TIMEOUT), ip],
            capture_output=True, text=True, timeout=PING_TIMEOUT + 1,
        ).stdout
        m = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return None


# =========================================================================
#                          ДВИЖОК НАКОПЛЕНИЯ УЛИК
# =========================================================================

def apply_known_device_evidence(dev: Device, known: dict):
    label = known.get(dev.mac.lower())
    if label:
        dev.add_evidence(label, 200, "Ручная метка в known_devices.json")


def apply_gateway_evidence(dev: Device, gateway_ip: str):
    if gateway_ip and dev.ip == gateway_ip:
        dev.add_evidence("Маршрутизатор / Шлюз", 90, "IP совпадает со шлюзом сети")
    hostname_l = (dev.hostname or "").lower()
    if any(k in hostname_l for k in ("gateway", "router", "orbi", "eero", "keenetic")):
        dev.add_evidence("Маршрутизатор / Шлюз", 40, f"Имя устройства похоже на роутер: {dev.hostname}")


def apply_oui_evidence(dev: Device):
    v = dev.vendor.lower()
    if "raspberry pi" in v:
        dev.add_evidence("Raspberry Pi / встраиваемое устройство", 40, f"Вендор MAC: {dev.vendor}")
    elif "apple" in v:
        dev.add_evidence("Устройство Apple", 20, f"Вендор MAC: {dev.vendor}")
    elif any(k in v for k in ("tp-link", "asustek", "asus", "cudy", "netgear",
                               "mikrotik", "routerboard", "ubiquiti", "d-link", "keenetic")):
        dev.add_evidence("Сетевое оборудование (роутер/AP)", 20, f"Вендор MAC: {dev.vendor}")
    elif "synology" in v:
        dev.add_evidence("Synology NAS", 30, f"Вендор MAC: {dev.vendor}")
    elif "samsung" in v:
        dev.add_evidence("Устройство Samsung (телефон/ТВ)", 15, f"Вендор MAC: {dev.vendor}")
    elif "amazon" in v:
        dev.add_evidence("Устройство Amazon (Echo/Fire TV)", 25, f"Вендор MAC: {dev.vendor}")
    elif "xiaomi" in v:
        dev.add_evidence("Устройство Xiaomi", 20, f"Вендор MAC: {dev.vendor}")
    elif "intel" in v:
        dev.add_evidence("ПК/ноутбук (сетевая карта Intel)", 10, f"Вендор MAC: {dev.vendor}")
    elif dev.vendor.startswith("Приватный"):
        dev.evidence_log.append("MAC рандомизирован (приватный адрес) — вендор в принципе недоступен")
    elif dev.vendor != "Неизвестный вендор":
        dev.add_evidence(f"Клиент ({dev.vendor.split()[0]})", 10, f"Вендор MAC: {dev.vendor}")


def apply_port_evidence(dev: Device):
    for port in dev.open_ports:
        sig = PORT_SIGNATURES.get(port)
        if not sig:
            continue
        service_name, weights = sig
        for dtype, w in weights.items():
            dev.add_evidence(dtype, w, f"Открыт порт {port}/{service_name}")


def apply_http_evidence(dev: Device):
    for port, (server, title) in dev.http_info.items():
        text = f"{server} {title}".lower()
        for kw, dtype in HTTP_KEYWORDS.items():
            if kw in text:
                dev.add_evidence(dtype, 35, f"HTTP({port}) баннер содержит «{kw}»: {server or title}")


def apply_nbns_evidence(dev: Device):
    if dev.nbns_name:
        dev.add_evidence("ПК на Windows", 50,
                          f"NetBIOS-имя: {dev.nbns_name} (группа: {dev.nbns_workgroup or '?'})")
        dev.hostname = dev.hostname or dev.nbns_name


def apply_mdns_evidence(dev: Device):
    for svc in dev.mdns_services:
        hint = MDNS_SERVICE_HINTS.get(svc)
        if hint:
            dtype, w = hint
            dev.add_evidence(dtype, w, f"mDNS-служба: {svc}")

    for model in dev.mdns_models:
        dev.add_evidence(f"Устройство: {model}", 55, f"mDNS TXT-запись сообщила точную модель: {model}")

    if dev.mdns_names:
        name = dev.mdns_names[0]
        dev.hostname = dev.hostname or name
        low = name.lower()
        if "iphone" in low:
            dev.add_evidence("Apple iPhone", 30, f"mDNS-имя: {name}")
        elif "ipad" in low:
            dev.add_evidence("Apple iPad", 30, f"mDNS-имя: {name}")
        elif any(k in low for k in ("macbook", "imac", "mac-mini", "macmini")):
            dev.add_evidence("Apple Mac", 30, f"mDNS-имя: {name}")
        elif any(k in low for k in ("android", "galaxy", "pixel", "redmi", "xiaomi")):
            dev.add_evidence("Устройство Android", 30, f"mDNS-имя: {name}")
        elif any(k in low for k in ("desktop-", "laptop-", "pc-")):
            dev.add_evidence("ПК на Windows", 25, f"mDNS-имя: {name}")


def apply_ssdp_evidence(dev: Device):
    info = dev.ssdp_info
    if not info:
        return
    text = " ".join(str(v) for v in info.values()).lower()
    bits = [info.get("manufacturer", ""), info.get("modelName", ""), info.get("friendlyName", "")]
    bits = [b for b in bits if b]
    label = " / ".join(bits) if bits else info.get("server", "SSDP-устройство")

    if any(k in text for k in ("router", "internetgatewaydevice", "mikrotik")):
        dev.add_evidence("Сетевое оборудование (роутер/AP)", 40, f"SSDP/UPnP: {label}")
    elif any(k in text for k in ("mediarenderer", "smarttv", "roku")):
        dev.add_evidence("Смарт-ТВ / медиаплеер", 40, f"SSDP/UPnP: {label}")
    elif "printer" in text:
        dev.add_evidence("Сетевой принтер", 40, f"SSDP/UPnP: {label}")
    elif "camera" in text:
        dev.add_evidence("IP-камера видеонаблюдения", 40, f"SSDP/UPnP: {label}")
    elif bits:
        dev.add_evidence(f"UPnP-устройство ({bits[0]})", 25, f"SSDP/UPnP: {label}")


def apply_ttl_evidence(dev: Device):
    if dev.ttl is None:
        return
    if dev.ttl > 128:
        dev.add_evidence("Сетевое оборудование (роутер/коммутатор)", 10, f"TTL={dev.ttl} (старт ~255)")
    elif dev.ttl > 64:
        dev.add_evidence("ПК на Windows", 12, f"TTL={dev.ttl} (старт ~128)")
    else:
        dev.add_evidence("Linux / Android / Apple-устройство", 8, f"TTL={dev.ttl} (старт ~64)")


def apply_tuya_evidence(dev: Device):
    info = dev.tuya_info
    if not info:
        return
    bits = []
    if info.get("productKey"):
        bits.append(f"productKey={info['productKey']}")
    if info.get("version"):
        bits.append(f"протокол v{info['version']}")
    detail = ", ".join(bits) if bits else "анонс без расшифровки (нет pycryptodome или устройство v3.4+)"
    dev.add_evidence("Умное Wi-Fi устройство на платформе Tuya (розетка/лампа/датчик)", 45,
                      f"Tuya UDP-анонс: {detail}")


def apply_kasa_evidence(dev: Device):
    info = dev.kasa_info
    if not info:
        return
    model = info.get("model", "")
    alias = info.get("alias", "")
    dev_type = (info.get("mic_type") or info.get("type") or "").upper()
    label = " / ".join(b for b in (model, alias) if b) or "TP-Link Kasa/Tapo"

    if "PLUG" in dev_type or "SWITCH" in dev_type:
        dtype = "Умная розетка/выключатель TP-Link Kasa"
    elif "BULB" in dev_type or "LIGHT" in dev_type:
        dtype = "Умная лампа TP-Link Kasa"
    elif "CAMERA" in dev_type:
        dtype = "IP-камера TP-Link Kasa"
    else:
        dtype = "Умное устройство TP-Link Kasa/Tapo"
    dev.add_evidence(dtype, 60, f"Прямой ответ по протоколу Kasa (UDP/9999): {label}")
    dev.hostname = dev.hostname or alias


def apply_shelly_evidence(dev: Device):
    info = dev.shelly_info
    if not info:
        return
    model = info.get("model") or info.get("type") or info.get("app") or "Shelly"
    dev.add_evidence(f"Умное реле/розетка Shelly ({model})", 60, f"Прямой ответ устройства /shelly: {model}")
    if not dev.hostname and info.get("mac"):
        dev.hostname = f"Shelly-{info['mac'][-6:]}"


def apply_bettercap_event_evidence(dev: Device):
    text = " ".join(dev.bettercap_events).lower()
    if "airplay" in text or "companion-link" in text:
        dev.add_evidence("Устройство Apple", 30, "Bettercap-событие: AirPlay/companion-link")
    if "chromecast" in text or "googlecast" in text:
        dev.add_evidence("Google Chromecast / Google TV", 30, "Bettercap-событие: Chromecast")


# =========================================================================
#                          ОРКЕСТРОВКА ОДНОГО УСТРОЙСТВА
# =========================================================================

def probe_device(mac, ip, gateway_ip, bc_hosts, ip_events, mdns_data, ssdp_data, tuya_data, known) -> Device:
    dev = Device(ip=ip, mac=mac)
    dev.vendor = get_vendor_by_mac(mac)

    bc_info = bc_hosts.get(mac.lower(), {})
    dev.hostname = bc_info.get("hostname", "")
    dev.bettercap_events = ip_events.get(ip, [])

    m = mdns_data.get(ip, {})
    dev.mdns_services = m.get("services", [])
    dev.mdns_names = m.get("names", [])
    dev.mdns_models = m.get("models", [])
    dev.ssdp_info = ssdp_data.get(ip, {})
    dev.tuya_info = tuya_data.get(ip, {})

    dev.open_ports = scan_ports(ip)
    for port, https in HTTP_BANNER_PORTS.items():
        if port in dev.open_ports:
            server, title = grab_http_banner(ip, port, https)
            if server or title:
                dev.http_info[port] = (server, title)
    if 80 in dev.open_ports:
        dev.shelly_info = probe_shelly(ip) or {}

    dev.nbns_name, dev.nbns_workgroup = query_nbns(ip)
    dev.ttl = get_ttl(ip)
    dev.kasa_info = query_kasa(ip) or {}

    apply_known_device_evidence(dev, known)
    apply_gateway_evidence(dev, gateway_ip)
    apply_oui_evidence(dev)
    apply_port_evidence(dev)
    apply_http_evidence(dev)
    apply_nbns_evidence(dev)
    apply_mdns_evidence(dev)
    apply_ssdp_evidence(dev)
    apply_tuya_evidence(dev)
    apply_kasa_evidence(dev)
    apply_shelly_evidence(dev)
    apply_ttl_evidence(dev)
    apply_bettercap_event_evidence(dev)

    return dev


# =========================================================================
#                          ТОЧКА ВХОДА ДЛЯ arp_scan.py
# =========================================================================

def identify_devices(devices: list) -> dict:
    """
    devices: [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.23"}, ...]
    Возвращает {mac: vendor_строка}, готовую для записи в devices.vendor.

    Это синхронная (блокирующая) функция — как и весь остальной код в
    этом файле. arp_scan.py вызывает её через asyncio.to_thread, чтобы не
    блокировать event loop на время mDNS/SSDP-развёрток и порт-сканов.
    """
    if not devices:
        return {}

    known = load_known_devices()

    bc_data, bc_events = fetch_bettercap_data()
    gateway_ip = ((bc_data or {}).get("gateway", {}) or {}).get("ipv4", "") or get_default_gateway()
    bc_hosts = build_bettercap_hosts(bc_data)
    ip_events = build_ip_events(bc_events)

    mdns_data = mdns_discover()
    ssdp_data = ssdp_discover()
    tuya_data = tuya_discover()

    result = {}
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, max(1, len(devices)))) as ex:
        futures = {
            ex.submit(probe_device, d["mac"], d["ip"], gateway_ip, bc_hosts, ip_events,
                      mdns_data, ssdp_data, tuya_data, known): d["mac"]
            for d in devices
        }
        for fut in as_completed(futures):
            mac = futures[fut]
            dev = fut.result()
            device_type, confidence = dev.classify()
            vendor = dev.vendor or "Неизвестный вендор"
            if confidence > 0:
                vendor = f"{vendor} ({device_type}, {confidence}%)"
            result[mac] = vendor

    return result