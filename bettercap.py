import asyncio
import aiohttp

from datetime import datetime
from arp_scan import logger




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


async def start_bettercap():
    process = await asyncio.create_subprocess_exec(
        "sudo", "/usr/local/bin/bettercap", "-caplet", "./api_server.cap",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

# waiting for the bettercap REST API to respond this means the caplet has finished executing and it is turly up and runnign
    for _ in range(15):
        if process.returncode is not None: # chack if there is a response it means the process has died
            logger.error(f"Bettercap завершился сразу после запуска (код {process.returncode})")
            return None
        await asyncio.sleep(1)
        if await fetch_bettercap_session() is not None:
            logger.info("Bettercap успешно запущен, REST API отвечает")
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



async def traffic_snapshot_once(pool):
    session_data = await fetch_bettercap_session()
    if not session_data:
        logger.error("traffic_stats: Bettercap недоступен, пропускаю снятие счётчиков")
        return
    traffic = session_data.get("packets", {}).get("traffic", {}) # look for the "packets and traffic" key : if it's not there don't crack the program instead create an empty {}
    if not traffic:
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    async with pool.acquire() as conn:              # gives an available connection from the pool to me
        async with conn.cursor() as cursor:         # a tool within the connetion through wich we send SQL commands and recive results
            await cursor.execute("SELECT id , ip from devices")
            id_ip_devices = cursor.fetchall()           # we take all found lines from the databese
            id_by_ip = {ip: dev_id for dev_id, ip in await id_ip_devices}

            for ip , stats in traffic.items():
                dev_id = id_by_ip.get(ip)
                if dev_id is None:
                    continue     # the device hasn't appeared in "devices " yet (waiting rfor 'arp-scan)
                await cursor.execute(
                    """
                    INSERT INTO traffic_stats (device_id,  timestamp, bytes_in, bytes_out)
                    VALUES (%s, %s, %s, %s)
                    """,
                            (dev_id, now , stats.get("received", 0), stats.get("sent", 0)),
                )



async def collect_trafic_starts(pool):
    while True:
        await asyncio.sleep(60)
        try:
            await traffic_snapshot_once(pool)
        except Exception:
            logger.exception("traffic_stats: ошибка снятия счётчиков")





















