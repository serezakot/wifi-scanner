import logging
import asyncio

from aiohttp import web
from net_watch.traffic_colector import block_device_traffic, unblock_device_traffic
from net_watch.bettercap import pause_monitoring, resume_monitoring, list_enabled
logger = logging.getLogger("wifi-scanver.control")

# connection with TUI
HOST = "127.0.0.1"
PORT = 9090

_blocked_ips = set()

def is_blocked_ips(ip):
    return ip in _blocked_ips

def block(ip: str):
    _blocked_ips.add(ip)
    asyncio.create_task(block_device_traffic(ip))
    logger.info("control_api: интернет ЗАБЛОКИРОВАН для %s", ip)

def unblock(ip:str):
    _blocked_ips.discard(ip)
    asyncio.create_task(unblock_device_traffic(ip))
    logger.info("control_api: интернет РАЗБЛОКИРОВАН для %s", ip)

def list_blocked():
    return sorted(_blocked_ips)


async def handle_command(request: web.Request):
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "invalid json"}, status=400)

    action = body.get("action")
    ip = body.get("ip")

    if not ip:
        return web.json_response({"error": "missing ip"}, status=400)

    if action == "block":
        block(ip)
    elif action == "unblock":
        unblock(ip)
    elif action == "pause_monitoring":
        pause_monitoring(ip)
        logger.info("control_api: DNS-мониторинг ПАУЗА для %s", ip)
    elif action == "resume_monitoring":
        resume_monitoring(ip)
        logger.info("control_api: DNS-мониторинг ВОЗОБНОВЛЁН для %s", ip)
    else:
        return web.json_response({"error": f"unknown action: {action}"}, status=400)

    return web.json_response({"ok": True, "blocked": list_blocked() , "monitoring_enabled": list_enabled(),})

async def handle_status(request: web.Request) -> web.Response:
    """current blocklist A TUI is needed to know what to display,
    since the state lives only in the daemon's memory. """
    return web.json_response({
        "blocked": list_blocked(),
        "monitoring_enabled": list_enabled(),
    })


async def start_control_api() -> web.AppRunner:
    app = web.Application()                                     ## create the main web application instance (container) using aiohttp
    app.router.add_post("/api/command", handle_command)    # register a POST request handler: routes requests from /api/command to handle_command
    app.router.add_get("/api/status", handle_status)        # Register a POST request handler: routes requests from /api/status to handlestatus

    runner = web.AppRunner(app)                                 # Wrap the app in AppRunner — manages the application's lifecycle and background tasks
    await runner.setup()                                        # Asynchronously set up the application (initializes internal structures and event channels)
    site = web.TCPSite(runner, HOST, PORT)                      # Create a network site binding the runner to a specific IP address (HOST) and port (PORT)
    await site.start()                                          # Open the network socket in the OS kernel and physically start accepting incoming HTTP requests

    logger.info("Control API: слушаю http://%s:%d", HOST, PORT)
    return runner


async def stop_control_api(runner: web.AppRunner | None) -> None:
    if runner is not None:
        await runner.cleanup()















