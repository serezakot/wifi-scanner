import asyncio
import aiomysql

from arp_scan import check_device , logger
from bettercap import start_bettercap, stop_bettercap

async def main():
    # create a mysql connection pool using our special agent
    pool = await aiomysql.create_pool(
        host = '127.0.0.1',
        port = 3306,
        user = 'netwatch_user',
        password = 'NetWatch#2026!',
        db = 'netwatch',
        autocommit = True
    )

    logger.info("WiFi Scanner Daemon started successfully.")

    bettercap_process = await  start_bettercap()
    if bettercap_process is None:
        logger.error("Bettercap не запустился, демон остановлен.")
        pool.close()
        return

    try:
        while True:
            await check_device(pool)
            await asyncio.sleep(10)
    except KeyboardInterrupt:
        logger.info("Deamon stopped by user ")
    finally:
        pool.close()
        await pool.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
