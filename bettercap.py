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
    caplet_path = "/home/sergiy-kot/Desktop/education/Net_Sentinel/api_server.cap"
    logger.info(f"Пробуем запустить Bettercap с файлом: {caplet_path}")
    process = await asyncio.create_subprocess_exec(
        "sudo", "/usr/local/bin/bettercap", "-iface", "wlp1s0", "-caplet", caplet_path,
        stdin=asyncio.subprocess.PIPE,
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




















