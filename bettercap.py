import asyncio
import aiohttp

from arp_scan import logger


async def start_bettercap():
    process = await asyncio.create_subprocess_exec(
        "sudo", "/usr/local/bin/bettercap", "-caplet", "./api_server.cap",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

    # ждём пока REST API bettercap ответит — значит caplet отработал и он реально жив
    auth = aiohttp.BasicAuth("netwatch", "192837465")
    async with aiohttp.ClientSession(auth=auth) as session:
        for _ in range(15):
            await asyncio.sleep(1)
            try:
                async with session.get("http://127.0.0.1:8081/api/session", timeout=aiohttp.ClientTimeout(total=2)) as resp:
                    if resp.status == 200:
                        logger.info("Bettercap успешно запущен, REST API отвечает")
                        return process
            except aiohttp.ClientError:
                pass

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