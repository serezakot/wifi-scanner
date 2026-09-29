import asyncio
import aiomysql

from arp_scan import check_device , logger
from bettercap import start_bettercap, stop_bettercap
from traffic_colector import set_session, collect_traffic_loop, setup_iptables


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

    #Updating session counters for the first launch.
    async with pool.acquire() as conn:
        async with conn.cursor() as cursor:
            await cursor.execute("UPDATE devices SET is_online = FALSE")
            await cursor.execute("UPDATE device_sessions SET ended_at = NOW() WHERE ended_at IS NULL")

    await setup_iptables()

    bettercap_process = await  start_bettercap()
    if bettercap_process is None:
        logger.error("Bettercap не запустился, демон остановлен.")
        pool.close()
        await pool.closed()
        return

    traffic_task = asyncio.create_task(collect_traffic_loop(pool))

    try:
        while True:
            if bettercap_process.returncode is not None:
                logger.error(f"ВНИМАНИЕ: Bettercap неожиданно закрылся! Код ошибки: {bettercap_process.returncode}")
            await check_device(pool)
            await asyncio.sleep(10)
    except KeyboardInterrupt:
        logger.info("Deamon stopped by user ")
    finally:
        traffic_task.cancel()
        try:
            await traffic_task
        except asyncio.CancelledError:
            pass
        await stop_bettercap(bettercap_process)
        pool.close()
        await pool.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
