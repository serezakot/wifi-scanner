import asyncio
import aiohttp
import logging

import test

from datetime import datetime


logger = logging.getLogger("wifi_scanner")
logger.setLevel(logging.INFO)
logger.propagate = False

class AsyncTelegram(logging.Handler):
    def __init__(self, token, chat_id):
        super().__init__()
        self.token = token
        self.chat_id = chat_id

    async def send_massage(self, msg):
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        async with aiohttp.ClientSession() as session:
            try:
                await session.post(url, json={
                    "chat_id": self.chat_id,
                    "text": msg},
                                   timeout = 2,
                                   )
            except Exception as e:
                print(f"Telegram sending error")

    def emit(self, record):
        msg = self.format(record)
        asyncio.create_task(self.send_massage(msg))


fmt = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

telegram = AsyncTelegram(token="YOU TG TOKEN", chat_id="YOU TG CHAT ID" )
telegram.setLevel(logging.INFO)
telegram.setFormatter(fmt)

console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(fmt)

logger.addHandler(telegram)
logger.addHandler(console)


#  runs arp-scan and gets diveices on the local network
async def scan():
    proces = await asyncio.create_subprocess_exec(
        "arp-scan",
        "--localnet",
        "--ouifile=/usr/share/arp-scan/ieee-oui.txt",
        "--macfile=/etc/arp-scan/mac-vendor.txt",
        "--format=${ip}\t${mac}\t${vendor}",
        stdout=asyncio.subprocess.PIPE,  # for standard output
        stderr=asyncio.subprocess.PIPE   # for the error stream
    )

    stdout , stderr = await proces.communicate()

    return stdout.decode("utf-8")


#   converts the arp-scan result into a list of devices
async def extract_device():
    text = await scan()
    devices = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            ip , mac , vendor = parts
            devices.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor
            })

    return devices


async def check_device(pool):
    current_device = await extract_device()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    async with pool.acquire() as conn:              # gives an available connection from the pool to me
        async with conn.cursor() as cursor:         # a tool within the connection through which we send SQL commands and receive results
            await cursor.execute("SELECT id , mac ,vendor, is_online FROM devices ")
            db_devices = await cursor.fetchall()                                                    # we take all found lines from the databese
            db_macs = {row[1]: {"id":row[0], "vendor":row[2], "is_online":row[3]} for row in db_devices}             # transform the resulting list from teh databese into a convinient dictionary

            current_macs = {dev["mac"] for dev in current_device}

            new_devices = [dev for dev in current_device if dev["mac"] not in db_macs]


            try:                                                                                                    # executing asynchronous code within an asynchronous deamon without  breaking the asynchronous nature
                fingerprinted_venders = await asyncio.to_thread(test.identify_devices , new_devices)         #
            except Exception:                                                                                      #
                logger.exception("test.py: error detecting devices ")
                return

            for cur in current_device:
                mac = cur["mac"]
                ip = cur["ip"]


                if mac not in db_macs:

                    if mac not in fingerprinted_venders:
                        logger.warning(f"test.py: could not identify the device: {mac} " )
                        continue

                    vendor = fingerprinted_venders[mac]

                    await cursor.execute(
                     """
                     INSERT INTO devices (mac, ip, vendor, first_seen, last_seen, is_online) 
                     VALUES (%s, %s, %s, %s, %s, TRUE)
                     """,
                            (mac, ip, vendor, now, now)
                    )
                    dev_id = cursor.lastrowid                   # take the unique numeric ID
# OPEN A SESSION
                    await cursor.execute("""INSERT INTO device_sessions (device_id, started_at) VALUES (%s,      %s)""",
                                                                                                    (dev_id  , now) )
                    logger.info(
                        "NEW DEVICE DETECTED\n"
                        f"IP: {ip}\n"
                        f"MAC: {mac}\n"
                        f"Vendor: {vendor}"
                       )

                else:
                    dev_id = db_macs[mac]["id"]
                    vendor = db_macs[mac]["vendor"]
                    was_online = db_macs[mac]["is_online"]

                    await cursor.execute(
                           """
                        UPDATE devices
                        SET ip = %s, vendor = %s , last_seen = %s , is_online = TRUE
                        WHERE id = %s 
                        """,
                        (ip , vendor, now , dev_id)
                    )

                    if not was_online:
                        await cursor.execute(
                            "INSERT INTO device_sessions (device_id , started_at) VALUES (%s , %s )",
                                                                                        (dev_id , now)
                        )

            for mac, data in db_macs.items():
                if mac not in current_macs and data["is_online"]:
                    dev_id = data["id"]
                    await cursor.execute(
                        "UPDATE devices SET is_online = FALSE WHERE id = %s",
                                                                    (dev_id,)
                    )























