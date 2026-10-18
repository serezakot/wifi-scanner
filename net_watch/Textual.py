import aiohttp
import aiomysql

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Header, Footer, DataTable, Static, OptionList
from textual.widgets.option_list import Option

DB_CONFIG = dict(
    host="127.0.0.1", port=3306,
    user="YOUR_USER_FOR_DB", password="YOUR_PASSWORD_FOR_DB",
    db="netwatch", autocommit=True,
)
API_URL = "http://127.0.0.1:9090"
REFRESH_SECONDS = 3

def _format_bytes(n) -> str:
    n = float(n or 0)
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024 or unit == "ГБ":
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"


def _format_dt(dt) -> str:
    if dt is None:
        return "—"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _format_duration(seconds) -> str:
    if seconds is None:
        return "—"
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}ч {m}м"
    if m:
        return f"{m}м {s}с"
    return f"{s}с"


def _current_row_key(table: DataTable):
    """Значение ключа строки под курсором (обычно IP), или None."""
    if not table.row_count or table.cursor_row is None:
        return None
    try:
        row_key, _ = table.coordinate_to_cell_key(table.cursor_coordinate)
        return row_key.value
    except Exception:
        return None



_SQL_BYTES_TODAY = """
    SELECT COALESCE(SUM(d.in_b), 0), COALESCE(SUM(d.out_b), 0)
    FROM (
        SELECT session_id,
               MAX(bytes_in)  - MIN(bytes_in)  AS in_b,
               MAX(bytes_out) - MIN(bytes_out) AS out_b
        FROM traffic_stats
        WHERE device_id = %s AND DATE(timestamp) = CURDATE()
        GROUP BY session_id
    ) d
"""

_SQL_BYTES_BY_DAY = """
    SELECT day, SUM(in_b) AS bytes_in, SUM(out_b) AS bytes_out
    FROM (
        SELECT DATE(timestamp) AS day, session_id,
               MAX(bytes_in)  - MIN(bytes_in)  AS in_b,
               MAX(bytes_out) - MIN(bytes_out) AS out_b
        FROM traffic_stats
        WHERE device_id = %s
        GROUP BY DATE(timestamp), session_id
    ) d
    GROUP BY day
    ORDER BY day DESC
"""


_SQL_SESSIONS = """
    SELECT started_at, ended_at,
           TIMESTAMPDIFF(SECOND, started_at, COALESCE(ended_at, NOW())) AS duration_seconds
    FROM device_sessions
    WHERE device_id = %s
    ORDER BY started_at DESC
"""



class BackScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Назад")]


class MainScreen(Screen):
    BINDINGS = [
        Binding("r", "refresh_now", "Обновить"),
        Binding("b", "show_blocked", "Блокировки"),
        Binding("q", "quit", "Выход"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(id="devices_table")
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("№", "IP", "MAC", "Вендор", "Статус", "Последний виден")


        self.set_interval(REFRESH_SECONDS, self.refresh_table)
        await self.refresh_table()

    async def refresh_table(self) -> None:
        async with self.app.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT id, ip, mac, vendor, os_type, is_online, last_seen "
                    "FROM devices WHERE ip IS NOT NULL "
                    "ORDER BY is_online DESC, last_seen DESC"
                )
                rows = await cursor.fetchall()

        table = self.query_one(DataTable)
        selected_key = _current_row_key(table)

        table.clear()
        cursor_row = 0
        for i, (dev_id, ip, mac, vendor, os_type, is_online, last_seen) in enumerate(rows, start=1):
            status = "🟢 online" if is_online else "⚪ offline"
            seen = "—" if is_online else _format_dt(last_seen)
            table.add_row(str(i), ip, mac, vendor or "?", status, seen, key=str(dev_id))
            if str(dev_id) == selected_key:
                cursor_row = i - 1

        if table.row_count:
            table.cursor_coordinate = (cursor_row, 0)

    async def action_refresh_now(self) -> None:
        await self.refresh_table()

    def action_show_blocked(self) -> None:
        self.app.push_screen(BlockedListScreen())

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        device_id = int(event.row_key.value)
        self.app.push_screen(DeviceDetailScreen(device_id))



class DeviceDetailScreen(BackScreen):
    OPT_TOGGLE = "toggle_monitoring"
    OPT_SESSIONS = "sessions"
    OPT_DNS = "dns_history"
    OPT_TRAFFIC = "traffic"
    OPT_BLOCK = "block_internet"
    OPT_BACK = "back"

    def __init__(self, device_id: int):
        super().__init__()
        self.device_id = device_id
        self.ip = ""
        self.mac = ""

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Загрузка...", id="device_info")
        yield Static("", id="bytes_today")
        yield OptionList(id="menu")
        yield Footer()

    async def on_mount(self) -> None:
        async with self.app.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT ip, mac, vendor, os_type, is_online, last_seen "
                    "FROM devices WHERE id = %s",
                    (self.device_id,),
                )
                row = await cursor.fetchone()

        if row is None:
            self.notify("Устройство не найдено", severity="error")
            self.app.pop_screen()
            return

        self.ip, self.mac, vendor, os_type, is_online, last_seen = row
        status = "🟢 online" if is_online else f"⚪ offline (видели {_format_dt(last_seen)})"
        self.query_one("#device_info", Static).update(
            f"{self.ip}  ({self.mac})\n{os_type or '?'} / {vendor or '?'}\n{status}"
        )

        await self._refresh_bytes_today()
        await self._rebuild_menu()

    async def _refresh_bytes_today(self) -> None:
        async with self.app.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(_SQL_BYTES_TODAY, (self.device_id,))
                bytes_in, bytes_out = await cursor.fetchone()

        self.query_one("#bytes_today", Static).update(
            f"Сегодня (весь день, по всем сессиям): "
            f"↓ {_format_bytes(bytes_in)}   ↑ {_format_bytes(bytes_out)}"
        )

    async def _rebuild_menu(self) -> None:
        blocked, enabled = await self.app.fetch_status()

        monitoring_label = (
            "🟢 DNS-мониторинг: ВКЛ — Enter, чтобы выключить"
            if self.ip in enabled else
            "🔴 DNS-мониторинг: ВЫКЛ — Enter, чтобы включить"
        )
        block_label = (
            "🔴 Интернет: ЗАБЛОКИРОВАН — Enter, чтобы разблокировать"
            if self.ip in blocked else
            "🌐 Интернет: разрешён — Enter, чтобы заблокировать"
        )


        menu = self.query_one(OptionList)
        menu.clear_options()
        menu.add_option(Option(monitoring_label, id=self.OPT_TOGGLE))
        menu.add_option(Option("История сессий", id=self.OPT_SESSIONS))
        menu.add_option(Option("DNS-история", id=self.OPT_DNS))
        menu.add_option(Option("Трафик по дням", id=self.OPT_TRAFFIC))
        menu.add_option(Option(block_label, id=self.OPT_BLOCK))
        menu.add_option(Option("← Назад", id=self.OPT_BACK))

    async def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        option_id = event.option_id

        if option_id == self.OPT_TOGGLE:
            _, enabled = await self.app.fetch_status()
            action = "pause_monitoring" if self.ip in enabled else "resume_monitoring"
            ok = await self.app.send_command(action, self.ip)
            if ok:
                await self._rebuild_menu()
            else:
                self.notify("Не удалось изменить DNS-мониторинг", severity="error")

        elif option_id == self.OPT_BLOCK:
            blocked, _ = await self.app.fetch_status()
            action = "unblock" if self.ip in blocked else "block"
            ok = await self.app.send_command(action, self.ip)
            if ok:
                await self._rebuild_menu()
            else:
                self.notify("Не удалось изменить блокировку интернета", severity="error")

        elif option_id == self.OPT_SESSIONS:
            self.app.push_screen(SessionHistoryScreen(self.device_id))
        elif option_id == self.OPT_DNS:
            self.app.push_screen(DnsHistoryScreen(self.device_id))
        elif option_id == self.OPT_TRAFFIC:
            self.app.push_screen(TrafficHistoryScreen(self.device_id))
        elif option_id == self.OPT_BACK:
            self.app.pop_screen()


class SessionHistoryScreen(BackScreen):
    def __init__(self, device_id: int):
        super().__init__()
        self.device_id = device_id

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("История сессий  (Esc — назад)")
        yield DataTable(id="sessions_table")
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Начало", "Конец", "Длительность")

        async with self.app.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(_SQL_SESSIONS, (self.device_id,))
                rows = await cursor.fetchall()

        if not rows:
            table.add_row("—", "—", "сессий пока нет")
            return

        for started, ended, duration in rows:
            table.add_row(
                _format_dt(started),
                _format_dt(ended) if ended else "ещё онлайн",
                _format_duration(duration),
            )


class DnsHistoryScreen(BackScreen):
    def __init__(self, device_id: int):
        super().__init__()
        self.device_id = device_id

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("История DNS  (Esc — назад)")
        yield DataTable(id="dns_table")
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Время", "Домен")

        async with self.app.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    "SELECT timestamp, domain FROM dns_logs "
                    "WHERE device_id = %s ORDER BY timestamp DESC LIMIT 200",
                    (self.device_id,),
                )
                rows = await cursor.fetchall()

        if not rows:
            table.add_row("—", "записей пока нет")
            return

        for ts, domain in rows:
            table.add_row(_format_dt(ts), domain)



class TrafficHistoryScreen(BackScreen):
    def __init__(self, device_id: int):
        super().__init__()
        self.device_id = device_id

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Трафик по дням  (Esc — назад)")
        yield DataTable(id="traffic_table")
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Дата", "Входящий", "Исходящий")

        async with self.app.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(_SQL_BYTES_BY_DAY, (self.device_id,))
                rows = await cursor.fetchall()

        if not rows:
            table.add_row("—", "—", "данных пока нет")
            return

        for day, bytes_in, bytes_out in rows:
            table.add_row(str(day), _format_bytes(bytes_in), _format_bytes(bytes_out))



class BlockedListScreen(BackScreen):
    BINDINGS = BackScreen.BINDINGS + [
        Binding("u", "unblock_selected", "Разблокировать"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Заблокированные устройства  (U — разблокировать, Esc — назад)")
        yield DataTable(id="blocked_table")
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("IP", "MAC", "Вендор")
        await self.refresh_table()

    async def refresh_table(self) -> None:
        blocked = await self.app.fetch_blocked()
        table = self.query_one(DataTable)
        table.clear()

        if not blocked:
            return

        placeholders = ",".join(["%s"] * len(blocked))
        async with self.app.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(
                    f"SELECT ip, mac, vendor FROM devices WHERE ip IN ({placeholders})",
                    tuple(blocked),
                )
                rows = await cursor.fetchall()

        for ip, mac, vendor in rows:
            table.add_row(ip, mac, vendor or "?", key=ip)

    async def action_unblock_selected(self) -> None:
        table = self.query_one(DataTable)
        ip = _current_row_key(table)
        if ip is None:
            return
        if await self.app.send_command("unblock", ip):
            self.notify(f"{ip}: разблокирован")
            await self.refresh_table()



class NetWatchTUI(App):
    TITLE = "NetWatch"

    async def on_mount(self) -> None:
        self.pool = await aiomysql.create_pool(**DB_CONFIG)
        self.push_screen(MainScreen())

    async def on_unmount(self) -> None:
        if hasattr(self, "pool"):
            self.pool.close()
            await self.pool.wait_closed()

    async def fetch_status(self) -> tuple[set[str], set[str]]:
        """Возвращает (blocked_ips, monitoring_paused_ips)."""
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(
                    f"{API_URL}/api/status", timeout=aiohttp.ClientTimeout(total=2)
                ) as resp:
                    data = await resp.json()
                    return (
                        set(data.get("blocked", [])),
                        set(data.get("monitoring_enabled", [])),
                    )
        except Exception:
            self.notify("Демон недоступен (control_api)", severity="warning")
            return set(), set()

    async def fetch_blocked(self) -> set[str]:
        blocked, _ = await self.fetch_status()
        return blocked

    async def send_command(self, action: str, ip: str) -> bool:
        try:
            async with aiohttp.ClientSession() as s:
                resp = await s.post(
                    f"{API_URL}/api/command",
                    json={"action": action, "ip": ip},
                    timeout=aiohttp.ClientTimeout(total=2),
                )
                return resp.status == 200
        except Exception:
            self.notify("Не удалось связаться с демоном", severity="error")
            return False


if __name__ == "__main__":
    NetWatchTUI().run()