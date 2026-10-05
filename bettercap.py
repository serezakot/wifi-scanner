import asyncio
import logging
import re

import aiohttp
import tldextract
from datetime import datetime
from traffic_colector import _active_sessions   # It instantly identifies the device's current session number and can record it, along with the domain, in the database.


logger = logging.getLogger("wifi_scanner.traffic")


#записываем сюда кеш что бы не лезть каждый раз в sql
_device_cache = {}

def clear_device_cache(ip_or_host:str):
    """Removes the IP from the cache. Called from arp_scan.py when the device goes offline."""
    _device_cache.pop(ip_or_host, None)


async def get_device_id(pool , ip ):
    """Returns the device_id based on the IP address. It checks the cache first, then the database."""

    if ip in _device_cache:
        return _device_cache[ip]

    async with pool.acquire() as conn:
        async with conn.cursor() as cursor:
            await cursor.execute(
                "SELECT id FROM devices WHERE (ip = %s) AND is_online = TRUE",
                (ip,)
            )
            result = await cursor.fetchone()
            if result:
                _device_cache[ip] = result[0]
                return result[0]
    return None

def parse_event(event: dict):
    """Extracts (device_ip, domain) from a Bettercap event.
    Returns None if the event is not relevant (invalid tag, missing domain,
    service domain). This is the only place where the decision on what to record is made."""
    tag = event.get("tag", "")
    data = event.get("data")

    if tag not in ("net.sniff.dns", "net.sniff.https"):
        return None
    if not isinstance(data, dict):
        return None

    message = data.get("message", "")
    if not isinstance(message, str):
        return None

    if tag == "net.sniff.dns":
        # data.to = IP of the device that requested the domain
        # data.from = 192.168.0.1 (router responding)
        device_ip = data.get("to", "")
        m = re.compile(r'\x1b\[33m(.*?)\x1b\[0m').search(message)
        domain = m.group(1).strip() if m else ""

    else:   #     net.sniff.https
        # data.from = IP of the device that opened the connection
        # domain in message: "sni 192.168.0.2 > https://example.com"
        device_ip = data.get("from")
        m = re.compile(r'https?://([^/\s:]+)').search(message)
        domain = m.group(1).strip() if m else ""

    if not device_ip or not domain:
        return None

    if any(domain.endswith(s) for s in (".local", ".arpa", ".internal")):
        return None

    return device_ip, domain


async def save_domain_log(pool, device_ip:str , domain:str, now):
    """Writes a single entry to dns_logs. Returns True if the write succeeded."""
    device_id = await get_device_id(pool, device_ip)
    session_id = _active_sessions.get(device_ip)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if device_id is None or session_id is None:
        return False

    async with pool.acquire() as conn:
        async with conn.cursor() as cursor:
            await cursor.execute(
                """
                INSERT INTO dns_logs (device_id, session_id, timestamp, domain) 
                VALUES (%s, %s, %s, %s)
                """,
                (device_id, session_id,  now, domain)
            )
            logger.info(f" Записан сайт {domain} для устройства {device_ip} ")

    return True

async def pool_bettercap_events(pool):
    auth = aiohttp.BasicAuth("netwatch", "192837465")
    await asyncio.sleep(10)

    # Time of the last processed event.
    _last_event_time = datetime.now()

    async with aiohttp.ClientSession(auth=aiohttp.BasicAuth("netwatch", "192837465")) as session:
        while True:
            try:
                async with session.get("http://127.0.0.1:8081/api/events", timeout=aiohttp.ClientTimeout(total=2)) as resp:
                    if resp.status != 200:
                        await  asyncio.sleep(1)
                        continue

                    events = await resp.json()

                seen_this_batch: set[tuple] = set()
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                written = 0
                newest_time = _last_event_time

                for event in events:
                    data = event.get("data")
                    raw_time = data.get("time", "") if isinstance(data, dict) else ""
                    try:
                        event_time = datetime.fromisoformat(raw_time[:19])
                    except (ValueError, TabError):
                        continue

                    #Skip events that have already been processed
                    if event_time <= _last_event_time:
                        continue

                    # Store the latest timestamp from this batch
                    if event_time > newest_time:
                        newest_time = event_time

                    parsed = parse_event(event)
                    if parsed is None:
                        continue

                    device_ip , domain = parsed

                    key = (device_ip, domain)
                    if key in seen_this_batch:
                        continue
                    seen_this_batch.add(key)


                    if await save_domain_log(pool, device_ip, domain, now):
                        logger.info("dns_logs: %s → %s", device_ip, domain)
                        written += 1

                if newest_time > _last_event_time:
                    _last_event_time = newest_time

            except Exception:
                logger.exception("dns_logs: ошибка при обработке событий")

            await asyncio.sleep(1)


async def fetch_bettercap_session():
    auth = aiohttp.BasicAuth("netwatch", "192837465")                       # handles basic authentication ( HTTP Basic Authentication)
    async with aiohttp.ClientSession(auth=auth) as session:                                 # open an HTTP session for sending requests ( with the login and password from auth )
        try:
            async with session.get("http://127.0.0.1:8081/api/session", timeout=aiohttp.ClientTimeout(total=2)) as resp:  # make a test request to the local bettercap api with maximum response timeout of 2 seconds
                if resp.status == 200:
                    return await resp.json()
        except Exception:
            pass
        return None


async def start_bettercap(pool):
    killer = await asyncio.create_subprocess_exec(
        "sudo", "killall", "-9", "bettercap",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await killer.wait()
    await asyncio.sleep(1)  # ждём пока порт освободится

    caplet_path = "/home/sergiy-kot/Desktop/education/Net_Sentinel/api_server.cap"
    logger.info(f"Пробуем запустить Bettercap с файлом: {caplet_path}")
    process = await asyncio.create_subprocess_exec(
        "sudo", "/usr/local/bin/bettercap", "-iface", "wlp1s0", "-caplet", caplet_path
        # stdin=asyncio.subprocess.PIPE,
        # stdout=asyncio.subprocess.DEVNULL,
        # stderr=asyncio.subprocess.DEVNULL,
    )

# waiting for the bettercap REST API to respond this means the caplet has finished executing and it is turly up and runnign
    for _ in range(15):
        if process.returncode is not None: # chack if there is a response it means the process has died
            logger.error(f"Bettercap завершился сразу после запуска (код {process.returncode})")
            return None
        await asyncio.sleep(1)
        if await fetch_bettercap_session() is not None:
            logger.info("Bettercap успешно запущен, REST API отвечает")
            asyncio.create_task(pool_bettercap_events(pool))
            return process

    logger.error("Bettercap не запустился — REST API не отвечает")
    process.terminate()
    return None

async def stop_bettercap(process):
    if process is None or process.returncode is not None:
        return
    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
    except asyncio.TimeoutError:
        process.kill()




















