import asyncio
import re
import logging

from datetime import datetime

logger = logging.getLogger("wifi_scanner.traffic")

_active_sessions: dict[str, int ] = {}

def set_session(ip: str, session_id: int):
    _active_sessions[ip] = session_id

def clear_session(ip: str):
    _active_sessions.pop(ip, None)

async def run(command):
    proces = await asyncio.create_subprocess_exec(
        *command,
        stdout= asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL
    )
    await proces.wait()

async def setup_iptables():
    await run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"]) #enable IP forwarding at the linux kernel lvl
# **by default the kernel discards packets not addressed to this host **after enabling , forwards them furhter according to the routing table

    await run(["sudo", "iptables", "-F"])                        # flushes all rules from chains of the filter table (INPUT , FORWARD , ACCEPT ,)
    await run(["sudo", "iptables", "-t", "nat", "-F"])           # flushes all rules from chains of the table nat (PREROUTING, POSTROUTING, OUTPUT)
    await run(["sudo", "iptables", "-Z"])                        # resets the packet and byte counters in all rules across all tables
    await run(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"])

#  automatic source IP substitution directly within the linux kernel on the fly
#   while tracking where to return the respons
    await run(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING",
                "-o", "wlp1s0", "-j", "MASQUERADE"])
    logger.info("iptables: форвардинг и NAT настроены, счётчики обнулены")



async def block_device_traffic(ip: str) -> None:
    for direction in ("-s", "-d"):
        await asyncio.create_subprocess_exec("sudo", "iptables", "-I", "FORWARD", "1", direction, ip, "-j", "DROP")

async def unblock_device_traffic(ip: str) -> None:
    for direction in ("-s", "-d"):
        await asyncio.create_subprocess_exec("sudo", "iptables", "-D", "FORWARD", direction, ip, "-j", "DROP")

async def add_device_rules(ip: str):
    """
    adds a counter rule for the device's upload/download traffic
    """
    await run(["sudo", "iptables", "-A", "FORWARD", "-s", ip, "-j", "ACCEPT"])
    await run(["sudo", "iptables", "-A", "FORWARD", "-d", ip, "-j", "ACCEPT"])
    logger.info("iptables: добавлены правила для %s", ip)

async def remove_device_rules(ip:str):
    """
    removes devices counter rules when it goes offline
    -D - delete the first matching rule from the chain
    after deletion the kernel stops counting bytes for this IP
    UPON THE NEXT CONNECTION THE NEW RULES COUNTER WILL START WITH ZERO
    """
    await run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "ACCEPT"])
    await run(["sudo", "iptables", "-D", "FORWARD", "-d", ip, "-j", "ACCEPT"])
    logger.info("iptables: удалены правила для %s", ip)


async def count_bytes():
    result = await asyncio.create_subprocess_exec(
    "sudo", "iptables", "-L", "FORWARD", "-v", "-n", "-x",
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.DEVNULL,
    )
    stdout , _ = await result.communicate() #feeds input
    output = stdout.decode("utf-8")

    counters = {}
    ip_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 9:
            continue
        try:
            byte_count = int(parts[1])
            source = parts[7]       # where is the packege form
            destination = parts[8]  # where is the packege going
        except (ValueError, IndexError):
            continue

        if ip_re.match(source) and destination == "0.0.0.0/0":
            # upload
            counters.setdefault(source, {"bytes_in": 0, "bytes_out": 0})
            counters[source]["bytes_out"] += byte_count
        elif source == "0.0.0.0/0" and ip_re.match(destination):
            counters.setdefault(destination, {"bytes_in":0, "bytes_out": 0})
            counters[destination]["bytes_in"] += byte_count

    return counters

async def collect_traffic_loop(pool):
    while True:
        await asyncio.sleep(60)
        try:
            counters = await count_bytes()
            if not counters:
                continue

            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            async with pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    await cursor.execute("SELECT id, ip FROM devices WHERE is_online = TRUE")
                    rows = await cursor.fetchall()
                    id_by_ip = {ip:  dev_id for dev_id, ip in rows}

                    written = 0
                    for ip, stats in counters.items():
                        dev_id = id_by_ip.get(ip)   # Looking for the device_id for this IP:
                        session_id = _active_sessions.get(ip)

                        if dev_id is None or session_id is None:
                            continue

                        await cursor.execute(
                        """
                            INSERT INTO traffic_stats
                                (device_id, session_id, timestamp, bytes_in, bytes_out)
                            VALUES (%s, %s, %s, %s, %s)
                        """,
                                    (dev_id, session_id, now, stats["bytes_in"], stats["bytes_out"]),
                        )
                        written += 1

            logger.info("traffic_stats: записан трафик для %d устройств", written)
        except Exception:
            logger.exception("traffic_stats: ошибка при записи счётчиков")