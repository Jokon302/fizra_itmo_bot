import asyncio
import html
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

from itmo_client import WEEKDAY_NAMES, WEEKDAY_SHORT, ItmoAuthError, ItmoSportClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("botfizra")

DATA_DIR = Path(os.getenv("DATA_DIR", "."))
DATA_DIR.mkdir(parents=True, exist_ok=True)
USERS_FILE = DATA_DIR / "users.json"
LEGACY_STATE_FILE = DATA_DIR / "bot_state.json"
LEGACY_TOKENS_FILE = DATA_DIR / "session_tokens.json"

INACTIVE_TIMEOUT_SECONDS = 21 * 86400  # 3 weeks (21 days)
ADMIN_USER_ID = int(os.getenv("ADMIN_USER_ID", "0"))

# Anti-spam & DDoS protection limits
LEADERBOARD_CACHE_TTL = 900.0       # 15 minutes cache for the whole leaderboard
USER_SCORE_CACHE_TTL = 3600.0      # 1 hour cache per user score (shield other users' accounts from repeated API calls)
USER_ACTION_MIN_INTERVAL = 3.0     # 3 seconds cooldown between manual API calls per user
CHAT_BOARD_MIN_INTERVAL = 8.0      # 8 seconds cooldown on /board per chat to avoid group spam

POPULAR_SPORTS = [
    "Бадминтон",
    "Волейбол",
    "Фитнес",
    "Плавание",
    "Настольный теннис",
    "Баскетбол",
    "Мини-футбол",
    "Йога",
    "Гребной спорт",
    "Шахматы",
    "Теннис",
    "Скалолазание",
]

ALL_TIME_SLOTS = ["08:10", "09:50", "11:30", "13:30", "15:30", "17:10", "19:00", "21:00"]

BUILDINGS_MAP = {
    273: "Ломоносова, 9",
    5: "Вяземский, 5-7",
    0: "Другие объекты",
}


def default_user_profile(user_id: int, name: str = "", username: str = "") -> dict[str, Any]:
    return {
        "user_id": user_id,
        "name": name,
        "username": username,
        "sports": ["Бадминтон"],
        "weekdays": [1, 4],
        "times": ["15:30", "17:10"],
        "buildings": [],  # empty = all buildings
        "auto_sign_up": False,
        "monitoring_active": True,
        "awaiting_login": False,
        "awaiting_custom_sport": False,
        "last_active_ts": time.time(),
        "notified_lesson_ids": [],
        "auth": {
            "login": None,
            "password": None,
            "access_token": None,
            "refresh_token": None,
            "expires_at": 0.0,
        },
        "cached_score": None,
        "cached_score_ts": 0.0,
    }


def load_db() -> dict[str, Any]:
    db: dict[str, Any] = {"users": {}, "meta": {"check_interval_minutes": 60}}
    if USERS_FILE.exists():
        try:
            db = json.loads(USERS_FILE.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(f"Failed to read {USERS_FILE}: {e}")

    # Migrate legacy single-user state if needed
    if not db.get("users") and LEGACY_STATE_FILE.exists():
        try:
            old_state = json.loads(LEGACY_STATE_FILE.read_text(encoding="utf-8"))
            cid = old_state.get("chat_id")
            if cid:
                prof = default_user_profile(int(cid), name="Владелец")
                kw = old_state.get("sport_keyword", "бадминтон")
                prof["sports"] = [kw.capitalize()] if kw else ["Бадминтон"]
                prof["weekdays"] = old_state.get("weekdays", [1, 4])
                prof["times"] = old_state.get("times", ["15:30", "17:10"])
                prof["auto_sign_up"] = bool(old_state.get("auto_sign_up", False))
                prof["notified_lesson_ids"] = old_state.get("notified_lesson_ids", [])
                if LEGACY_TOKENS_FILE.exists():
                    tdata = json.loads(LEGACY_TOKENS_FILE.read_text(encoding="utf-8"))
                    prof["auth"].update(tdata)
                db["users"][str(cid)] = prof
                db["meta"]["check_interval_minutes"] = int(old_state.get("check_interval_minutes", 60))
                save_db(db)
                logger.info(f"Migrated legacy user {cid} into multi-user database.")
        except Exception as e:
            logger.warning(f"Migration failed: {e}")

    return db


def save_db(db: dict[str, Any]) -> None:
    try:
        USERS_FILE.write_text(json.dumps(db, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        logger.warning(f"Failed to write {USERS_FILE}: {e}")


class TelegramBot:
    def __init__(self, token: str, db: dict[str, Any]):
        self.token = token
        self.api_url = f"https://api.telegram.org/bot{token}"
        self.db = db
        self.offset = 0
        self.bot_username = ""
        self._clients: dict[str, ItmoSportClient] = {}
        self._user_cooldowns: dict[tuple[int, str], float] = {}
        self._chat_board_cooldowns: dict[int, float] = {}
        self._cached_leaderboard: list[tuple[int, str]] = []
        self._leaderboard_updated_at: float = 0.0
        self._leaderboard_lock = asyncio.Lock()

    def check_user_rate_limit(self, user_id: int, action: str = "general", min_interval: float = USER_ACTION_MIN_INTERVAL) -> tuple[bool, float]:
        """
        Anti-spam / DDoS check for a specific user action.
        Returns (is_allowed, remaining_seconds).
        """
        now = time.time()
        key = (user_id, action)
        last_time = self._user_cooldowns.get(key, 0.0)
        elapsed = now - last_time
        if elapsed < min_interval:
            return False, round(min_interval - elapsed, 1)
        self._user_cooldowns[key] = now
        return True, 0.0

    def check_chat_board_rate_limit(self, chat_id: int, min_interval: float = CHAT_BOARD_MIN_INTERVAL) -> tuple[bool, float]:
        """
        Prevents spamming /board in chats.
        Returns (is_allowed, remaining_seconds).
        """
        now = time.time()
        last_time = self._chat_board_cooldowns.get(chat_id, 0.0)
        elapsed = now - last_time
        if elapsed < min_interval:
            return False, round(min_interval - elapsed, 1)
        self._chat_board_cooldowns[chat_id] = now
        return True, 0.0

    def get_user(self, user_id: int, tg_user: dict[str, Any] | None = None, touch: bool = True) -> dict[str, Any]:
        uid = str(user_id)
        users = self.db.setdefault("users", {})
        if uid not in users:
            first_name = (tg_user or {}).get("first_name") or ""
            last_name = (tg_user or {}).get("last_name") or ""
            full_name = f"{first_name} {last_name}".strip()
            username = (tg_user or {}).get("username") or ""
            users[uid] = default_user_profile(user_id, name=full_name, username=username)
            save_db(self.db)
        else:
            if tg_user:
                first_name = tg_user.get("first_name") or ""
                last_name = tg_user.get("last_name") or ""
                full_name = f"{first_name} {last_name}".strip()
                if full_name:
                    users[uid]["name"] = full_name
                if tg_user.get("username"):
                    users[uid]["username"] = tg_user["username"]
            if touch:
                users[uid]["last_active_ts"] = time.time()
                if not users[uid].get("monitoring_active", True) and users[uid].get("_paused_by_inactivity"):
                    users[uid]["monitoring_active"] = True
                    users[uid]["_paused_by_inactivity"] = False
                save_db(self.db)
        return users[uid]

    def get_client_for_user(self, user_id: int) -> ItmoSportClient:
        uid = str(user_id)
        prof = self.get_user(user_id, touch=False)
        auth = prof.setdefault("auth", {})

        def _on_tokens_updated(new_auth: dict[str, Any]) -> None:
            if uid in self.db.get("users", {}):
                self.db["users"][uid]["auth"] = new_auth
                save_db(self.db)

        if uid not in self._clients:
            self._clients[uid] = ItmoSportClient(
                login=auth.get("login"),
                password=auth.get("password"),
                access_token=auth.get("access_token"),
                refresh_token=auth.get("refresh_token"),
                expires_at=float(auth.get("expires_at") or 0.0),
                on_tokens_updated=_on_tokens_updated,
            )
        return self._clients[uid]

    def get_any_authenticated_client(self) -> ItmoSportClient | None:
        """Returns any authenticated client (e.g. for reading public schedule in group chats)."""
        for uid, prof in self.db.get("users", {}).items():
            auth = prof.get("auth") or {}
            if auth.get("access_token") or (auth.get("login") and auth.get("password")):
                return self.get_client_for_user(int(uid))
        return None

    def is_user_authenticated(self, prof: dict[str, Any]) -> bool:
        auth = prof.get("auth") or {}
        return bool(auth.get("access_token") or (auth.get("login") and auth.get("password")))

    async def tg_call(self, method: str, payload: dict[str, Any] | None = None, timeout: float = 35.0) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(f"{self.api_url}/{method}", json=payload or {})
            return resp.json()

    async def send_message(
        self,
        chat_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
        reply_to_message_id: int | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if reply_markup:
            payload["reply_markup"] = reply_markup
        if reply_to_message_id:
            payload["reply_to_message_id"] = reply_to_message_id
        return await self.tg_call("sendMessage", payload)

    async def edit_message(
        self,
        chat_id: int,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        if reply_markup:
            payload["reply_markup"] = reply_markup
        return await self.tg_call("editMessageText", payload)

    # ─── Keyboards ───────────────────────────────────────────────────────────

    def reply_keyboard(self) -> dict[str, Any]:
        return {
            "keyboard": [
                [{"text": "🔍 Свободные слоты"}, {"text": "📋 Все слоты"}],
                [{"text": "🏆 Мои баллы"}, {"text": "📅 Мои записи"}],
                [{"text": "⚙️ Настройки поиска"}, {"text": "👤 Профиль"}],
            ],
            "resize_keyboard": True,
            "is_persistent": True,
        }

    def settings_inline_keyboard(self, prof: dict[str, Any]) -> dict[str, Any]:
        auto_lbl = "🟢 ВКЛ" if prof.get("auto_sign_up") else "⚪ ВЫКЛ"
        mon_lbl = "🟢 Активен" if prof.get("monitoring_active", True) else "⏸ На паузе"
        return {
            "inline_keyboard": [
                [{"text": "🏅 Выбрать секции (виды спорта)", "callback_data": "cfg_sports"}],
                [{"text": "📆 Выбрать дни недели", "callback_data": "cfg_days"}],
                [{"text": "🕒 Выбрать время занятий", "callback_data": "cfg_times"}],
                [{"text": "🏢 Выбрать корпус", "callback_data": "cfg_buildings"}],
                [
                    {"text": f"🤖 Автозапись: {auto_lbl}", "callback_data": "toggle_auto_cfg"},
                    {"text": f"📡 Мониторинг: {mon_lbl}", "callback_data": "toggle_mon_cfg"},
                ],
                [{"text": "✅ Готово", "callback_data": "menu_main"}],
            ]
        }

    def sports_inline_keyboard(self, prof: dict[str, Any]) -> dict[str, Any]:
        selected = prof.get("sports") or []
        rows = []
        row = []
        for sp in POPULAR_SPORTS:
            mark = "✅ " if any(s.lower() == sp.lower() for s in selected) else ""
            row.append({"text": f"{mark}{sp}", "callback_data": f"sp_tog:{sp}"})
            if len(row) == 2:
                rows.append(row)
                row = []
        if row:
            rows.append(row)

        all_mark = "✅ " if not selected else ""
        rows.append([{"text": f"{all_mark}🌟 Все секции (без фильтра)", "callback_data": "sp_all"}])
        rows.append([{"text": "✏️ Ввести другую секцию вручную", "callback_data": "sp_custom"}])
        rows.append([{"text": "⬅️ Назад к настройкам", "callback_data": "menu_settings"}])
        return {"inline_keyboard": rows}

    def days_inline_keyboard(self, prof: dict[str, Any]) -> dict[str, Any]:
        selected = prof.get("weekdays") or []
        row1 = []
        row2 = []
        for d in range(1, 8):
            mark = "✅ " if d in selected else "⬜ "
            btn = {"text": f"{mark}{WEEKDAY_SHORT[d]}", "callback_data": f"day_tog:{d}"}
            if d <= 4:
                row1.append(btn)
            else:
                row2.append(btn)
        all_mark = "✅ " if not selected else ""
        return {
            "inline_keyboard": [
                row1,
                row2,
                [{"text": f"{all_mark}📅 Любой день недели", "callback_data": "day_all"}],
                [{"text": "⬅️ Назад к настройкам", "callback_data": "menu_settings"}],
            ]
        }

    def times_inline_keyboard(self, prof: dict[str, Any]) -> dict[str, Any]:
        selected = prof.get("times") or []
        rows = []
        row = []
        for t in ALL_TIME_SLOTS:
            mark = "✅ " if t in selected else "⬜ "
            row.append({"text": f"{mark}{t}", "callback_data": f"time_tog:{t}"})
            if len(row) == 2:
                rows.append(row)
                row = []
        if row:
            rows.append(row)
        all_mark = "✅ " if not selected else ""
        rows.append([{"text": f"{all_mark}🕒 Любое время", "callback_data": "time_all"}])
        rows.append([{"text": "⬅️ Назад к настройкам", "callback_data": "menu_settings"}])
        return {"inline_keyboard": rows}

    def buildings_inline_keyboard(self, prof: dict[str, Any]) -> dict[str, Any]:
        selected = prof.get("buildings") or []
        rows = []
        for bid, bname in BUILDINGS_MAP.items():
            mark = "✅ " if bid in selected else "⬜ "
            rows.append([{"text": f"{mark}{bname}", "callback_data": f"bld_tog:{bid}"}])
        all_mark = "✅ " if not selected else ""
        rows.append([{"text": f"{all_mark}🏢 Все корпуса", "callback_data": "bld_all"}])
        rows.append([{"text": "⬅️ Назад к настройкам", "callback_data": "menu_settings"}])
        return {"inline_keyboard": rows}

    def profile_inline_keyboard(self, prof: dict[str, Any]) -> dict[str, Any]:
        auth_btn_text = "🔑 Сменить аккаунт ИСУ" if self.is_user_authenticated(prof) else "🔑 Войти в аккаунт ИСУ"
        return {
            "inline_keyboard": [
                [{"text": auth_btn_text, "callback_data": "prof_login"}],
                [{"text": "🗑 Удалить себя из бота", "callback_data": "prof_delete_ask"}],
                [{"text": "✅ Закрыть", "callback_data": "menu_main"}],
            ]
        }

    def group_inline_keyboard(self) -> dict[str, Any]:
        return {
            "inline_keyboard": [
                [
                    {"text": "🏸 Слоты: Бадминтон", "callback_data": "grp_slots:Бадминтон"},
                    {"text": "🏐 Слоты: Волейбол", "callback_data": "grp_slots:Волейбол"},
                ],
                [
                    {"text": "💪 Слоты: Фитнес", "callback_data": "grp_slots:Фитнес"},
                    {"text": "🏊 Слоты: Плавание", "callback_data": "grp_slots:Плавание"},
                ],
                [
                    {"text": "🏆 Мои баллы", "callback_data": "my_score"},
                    {"text": "📅 Мои записи", "callback_data": "my_lessons"},
                ],
                [
                    {"text": "📊 Топ баллов чата", "callback_data": "grp_leaderboard"},
                ],
            ]
        }

    # ─── Formatters ──────────────────────────────────────────────────────────

    def format_user_dashboard(self, prof: dict[str, Any]) -> str:
        sports_str = ", ".join(prof.get("sports") or []) or "Все секции"
        days = prof.get("weekdays") or []
        days_str = ", ".join(WEEKDAY_NAMES.get(d, str(d)) for d in sorted(days)) if days else "Любой день"
        times = prof.get("times") or []
        times_str = ", ".join(times) if times else "Любое время"
        blds = prof.get("buildings") or []
        blds_str = ", ".join(BUILDINGS_MAP.get(b, str(b)) for b in blds) if blds else "Все корпуса"

        auth_ok = self.is_user_authenticated(prof)
        login_id = (prof.get("auth") or {}).get("login")
        auth_str = f"✅ Подключена ({login_id})" if (auth_ok and login_id) else (
            "✅ Подключена (по токену)" if auth_ok else "❌ Не подключена (нажми «Профиль» → «Войти»)"
        )
        mon_str = "🟢 Активен (каждый час)" if prof.get("monitoring_active", True) else "⏸ На паузе"
        auto_str = "🟢 Включена (бот запишет сам)" if prof.get("auto_sign_up") else "⚪ Выключена (уведомление + кнопка)"

        return (
            "🏸 <b>Бот мониторинга и записи на физру ИТМО</b>\n\n"
            f"👤 <b>Пользователь:</b> {html.escape(prof.get('name') or str(prof['user_id']))}\n"
            f"🔐 <b>Авторизация ИСУ:</b> {auth_str}\n"
            f"📡 <b>Ежечасный поиск:</b> {mon_str}\n"
            f"🤖 <b>Автозапись:</b> {auto_str}\n\n"
            "🎯 <b>Твой фильтр поиска (на 3 недели вперёд):</b>\n"
            f"• <b>Секции:</b> {html.escape(sports_str)}\n"
            f"• <b>Дни:</b> {days_str}\n"
            f"• <b>Время:</b> {times_str}\n"
            f"• <b>Корпус:</b> {blds_str}\n\n"
            "<i>💡 При неактивности более 3 недель автоматический поиск ставится на паузу с уведомлением.</i>"
        )

    def format_slot_card(self, slot: dict[str, Any]) -> str:
        avail = slot["available"]
        limit = slot["limit"]
        status_icon = "🟢 <b>ЕСТЬ МЕСТА</b>" if avail > 0 else "🔴 Мест нет"

        reasons = slot.get("unavailable_reasons") or []
        collision = slot.get("has_collision") or any(
            any(kw in str(r).lower() for kw in (
                "колли", "пересеч", "совпад", "collision", "conflict",
                "другое занятие", "другой урок", "уже записан", "occupied",
            ))
            for r in reasons
        )

        if slot["can_sign_in"]:
            sign_str = "✅ Доступно для записи"
        elif collision:
            sign_str = "⚠️ Коллизия расписания (пересечение с другим занятием)"
        elif reasons:
            sign_str = "⚠️ " + "; ".join(html.escape(str(r)) for r in reasons)
        else:
            sign_str = "⚠️ Запись недоступна"

        return (
            f"{status_icon} — <b>{html.escape(slot['section_name'])}</b>\n"
            f"📅 <b>{slot['date']} ({slot['weekday_name']})</b> | 🕒 <b>{slot['time_start']}–{slot['time_end']}</b>\n"
            f"📍 {html.escape(slot['room_name'])}\n"
            f"👤 {html.escape(slot['teacher_fio'])}\n"
            f"👥 Свободно: <b>{avail} из {limit}</b> | {sign_str}"
        )

    def format_score_card(self, prof: dict[str, Any], data: dict[str, Any]) -> str:
        sem = data.get("semester") or {}
        score_obj = data.get("score") or {}
        sums = score_obj.get("sum") or {}
        att_pts = int(sums.get("attendances", 0) or 0)
        other_pts = int(sums.get("other", 0) or 0)
        total_pts = att_pts + other_pts
        target = 100
        filled = min(10, int(round(total_pts / 10)))
        bar = "🟩" * filled + "⬜" * (10 - filled)
        rem_pts = max(0, target - total_pts)
        rem_lessons = (rem_pts + 4) // 5

        free_signs = data.get("free_signs")
        attendances = score_obj.get("attendances") or []

        lines = [
            f"🏆 <b>Баллы за физкультуру — {html.escape(prof.get('name') or 'Студент')}</b>",
            f"📚 Семестр: <b>{sem.get('study_year', '2026/2027')} (семестр {sem.get('semester', 1)})</b>\n",
            f"{bar} <b>{total_pts} / {target} баллов</b>",
            f"• За посещения: <b>{att_pts}</b> балл.",
            f"• Доп. баллы / соревнования: <b>{other_pts}</b> балл.",
        ]
        if rem_pts > 0:
            lines.append(f"• До зачёта осталось: <b>{rem_pts} балл.</b> (~{rem_lessons} зан. по 5 баллов)")
        else:
            lines.append("🎉 <b>Норма баллов на зачёт выполнена!</b>")

        if free_signs is not None:
            lines.append(f"🎟 Осталось свободных записей в семестре: <b>{free_signs}</b>")

        if attendances:
            lines.append("\n📋 <b>Последние начисления:</b>")
            for item in attendances[:8]:
                dt = str(item.get("date", ""))[:10]
                pts = item.get("score", 0)
                if item.get("is_competition"):
                    title = item.get("competition_name") or "Соревнование"
                    lines.append(f"• {dt}: 🏅 {html.escape(title)} (<b>+{pts}</b>)")
                else:
                    title = item.get("name") or "Занятие"
                    lines.append(f"• {dt}: 👟 {html.escape(title)} (<b>+{pts}</b>)")

        return "\n".join(lines)

    # ─── Actions ─────────────────────────────────────────────────────────────

    async def send_score(self, chat_id: int, user_id: int, tg_user: dict[str, Any] | None = None) -> None:
        prof = self.get_user(user_id, tg_user)
        if not self.is_user_authenticated(prof):
            await self.send_message(
                chat_id,
                "🔑 Сначала войди в свой аккаунт ИСУ в личных сообщениях бота (кнопка «👤 Профиль» → «🔑 Войти в аккаунт ИСУ» или команда <code>/login ИСУ ПАРОЛЬ</code> в ЛС).",
            )
            return
        client = self.get_client_for_user(user_id)
        try:
            data = await client.get_score_and_attempts()
            sums = (data.get("score") or {}).get("sum") or {}
            prof["cached_score"] = int(sums.get("attendances", 0) or 0) + int(sums.get("other", 0) or 0)
            prof["cached_score_ts"] = time.time()
            save_db(self.db)
            await self.send_message(chat_id, self.format_score_card(prof, data))
        except Exception as e:
            await self.send_message(chat_id, f"⚠️ Не удалось получить баллы: <code>{html.escape(str(e))}</code>")

    async def send_chosen_lessons(self, chat_id: int, user_id: int, tg_user: dict[str, Any] | None = None) -> None:
        prof = self.get_user(user_id, tg_user)
        if not self.is_user_authenticated(prof):
            await self.send_message(
                chat_id,
                "🔑 Сначала авторизуйся в ЛС бота через <code>/login ИСУ ПАРОЛЬ</code>.",
            )
            return
        client = self.get_client_for_user(user_id)
        try:
            upcoming = await client.get_chosen_lessons()
            if not upcoming:
                await self.send_message(
                    chat_id,
                    f"📅 <b>{html.escape(prof.get('name') or 'Студент')}:</b> у тебя сейчас нет активных записей на будущие занятия.",
                )
                return

            lines = [f"📅 <b>Будущие записи — {html.escape(prof.get('name') or 'Студент')} ({len(upcoming)} шт.):</b>\n"]
            buttons = []
            for les in upcoming:
                lines.append(
                    f"📌 <b>{html.escape(les['section_name'])}</b>\n"
                    f"🗓 <b>{les['date']} ({les['weekday_name']})</b> | 🕒 <b>{les['time_start']}–{les['time_end']}</b>\n"
                    f"📍 {html.escape(les['room_name'])}\n"
                    f"👤 {html.escape(les['teacher_fio'])}\n"
                )
                if chat_id == user_id:
                    buttons.append(
                        [
                            {
                                "text": f"❌ Отписаться: {les['date']} {les['time_start']} ({les['section_name']})",
                                "callback_data": f"unsub:{les['id']}",
                            }
                        ]
                    )
            await self.send_message(chat_id, "\n".join(lines), reply_markup={"inline_keyboard": buttons} if buttons else None)
        except Exception as e:
            await self.send_message(chat_id, f"⚠️ Ошибка при загрузке записей: <code>{html.escape(str(e))}</code>")

    async def run_user_scan(
        self,
        chat_id: int,
        user_id: int,
        show_all: bool = False,
        manual: bool = False,
        override_sport: str | None = None,
    ) -> None:
        prof = self.get_user(user_id, touch=manual)

        # Only use the user's own authenticated client — never fall back to another user's tokens
        if not self.is_user_authenticated(prof):
            if manual:
                await self.send_message(
                    chat_id,
                    "🔑 <b>Для поиска слотов нужно войти в свой аккаунт ИСУ!</b>\n\n"
                    "Нажми кнопку <b>«👤 Профиль» → «🔑 Войти в аккаунт ИСУ»</b> или напиши:\n"
                    "<code>/login ТВОЙ_ИСУ ТВОЙ_ПАРОЛЬ</code>",
                    reply_markup=self.profile_inline_keyboard(prof) if chat_id == user_id else None,
                )
            return

        client = self.get_client_for_user(user_id)

        sports = [override_sport] if override_sport else (prof.get("sports") or [])
        weekdays = [] if override_sport else (prof.get("weekdays") or [])
        times = [] if override_sport else (prof.get("times") or [])
        buildings = [] if override_sport else (prof.get("buildings") or [])

        try:
            slots = await client.find_matching_slots(
                sport_keywords=sports,
                target_weekdays=weekdays,
                target_times=times,
                target_building_ids=buildings if buildings else None,
                weeks_ahead=3,
            )
        except ItmoAuthError as e:
            if manual:
                await self.send_message(
                    chat_id,
                    f"🔑 <b>Требуется вход в ИСУ:</b> {html.escape(str(e))}\nНапиши в ЛС бота: <code>/login ИСУ ПАРОЛЬ</code>",
                )
            return
        except Exception as e:
            logger.exception("Error scanning slots")
            if manual:
                await self.send_message(chat_id, f"⚠️ Ошибка запроса к my.itmo.ru: <code>{html.escape(str(e))}</code>")
            return

        if show_all:
            if not slots:
                await self.send_message(
                    chat_id,
                    "📭 На ближайшие 3 недели не найдено занятий по выбранному фильтру.",
                )
                return

            lines = [f"📋 <b>Все слоты по фильтру на 3 недели ({len(slots)} шт.):</b>\n"]
            buttons = []
            for s in slots[:18]:
                lines.append(self.format_slot_card(s))
                lines.append("")
                if s["available"] > 0 and s["can_sign_in"]:
                    buttons.append(
                        [
                            {
                                "text": f"✍️ Записаться: {s['date']} ({WEEKDAY_SHORT.get(s['weekday'], '')}) {s['time_start']} — {s['section_name']}",
                                "callback_data": f"sign:{s['id']}",
                            }
                        ]
                    )
            if len(slots) > 18:
                lines.append(f"<i>...и ещё {len(slots) - 18} слотов (сузь фильтр в «⚙️ Настройки поиска»).</i>")
            await self.send_message(chat_id, "\n".join(lines), reply_markup={"inline_keyboard": buttons} if buttons else None)
            return

        # Default mode: ONLY available for sign-in AND available > 0
        # In group override mode, show any slot with available > 0
        free_slots = [
            s for s in slots
            if s["available"] > 0 and (s["can_sign_in"] or bool(override_sport))
        ]

        if not free_slots:
            if manual:
                total_found = len(slots)
                sp_label = override_sport or (", ".join(sports) if sports else "Все секции")
                await self.send_message(
                    chat_id,
                    f"🔍 <b>Проверка на 3 недели вперёд ({datetime.now().strftime('%H:%M:%S')})</b>\n"
                    f"Фильтр: <b>{html.escape(sp_label)}</b>\n"
                    f"Всего подходящих слотов в расписании: <b>{total_found}</b>.\n"
                    "Доступных для записи слотов со свободными местами сейчас <b>нет (0)</b>.\n\n"
                    "Я сканирую расписание каждый час и сразу пришлю уведомление, как только появится место!",
                    reply_markup=self.group_inline_keyboard() if chat_id != user_id else None,
                )
            return

        if manual:
            lines = [f"🟢 <b>Найдены доступные слоты со свободными местами ({len(free_slots)} шт.):</b>\n"]
            buttons = []
            for s in free_slots[:15]:
                lines.append(self.format_slot_card(s))
                lines.append("")
                buttons.append(
                    [
                        {
                            "text": f"✍️ Записаться: {s['date']} ({WEEKDAY_SHORT.get(s['weekday'], '')}) {s['time_start']} — {s['section_name']}",
                            "callback_data": f"sign:{s['id']}",
                        }
                    ]
                )
            await self.send_message(chat_id, "\n".join(lines), reply_markup={"inline_keyboard": buttons} if buttons else None)
            return

        # Background scheduled notification for a specific user
        notified_ids: list[int] = prof.get("notified_lesson_ids") or []
        for s in free_slots:
            lid = s["id"]
            if lid in notified_ids:
                continue

            notified_ids.append(lid)
            prof["notified_lesson_ids"] = notified_ids[-250:]
            save_db(self.db)

            if prof.get("auto_sign_up") and s["can_sign_in"]:
                try:
                    res = await client.sign_up_lesson(lid)
                    if res.get("error_code") == 0:
                        await self.send_message(
                            chat_id,
                            "🎉 <b>АВТОЗАПИСЬ ВЫПОЛНЕНА УСПЕШНО!</b>\n\n" + self.format_slot_card(s),
                        )
                        continue
                except Exception as e:
                    logger.warning(f"Auto sign-up failed for user {user_id}, lesson {lid}: {e}")

            kb = {
                "inline_keyboard": [
                    [
                        {
                            "text": f"✍️ Записаться: {s['date']} в {s['time_start']} ({s['section_name']})",
                            "callback_data": f"sign:{lid}",
                        }
                    ],
                ]
            }
            await self.send_message(
                chat_id,
                "🔥 <b>ПОЯВИЛСЯ СВОБОДНЫЙ СЛОТ!</b>\n\n" + self.format_slot_card(s),
                reply_markup=kb,
            )

    # ─── Update Handling ─────────────────────────────────────────────────────

    async def handle_callback(self, cq: dict[str, Any]) -> None:
        cq_id = cq["id"]
        data = cq.get("data", "")
        from_user = cq.get("from") or {}
        user_id = from_user.get("id")
        msg = cq.get("message") or {}
        chat_id = (msg.get("chat") or {}).get("id")
        msg_id = msg.get("message_id")
        if not user_id or not chat_id:
            return

        prof = self.get_user(user_id, from_user, touch=True)

        if data == "menu_main":
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id})
            await self.edit_message(chat_id, msg_id, self.format_user_dashboard(prof))

        elif data == "menu_settings":
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id})
            await self.edit_message(
                chat_id,
                msg_id,
                "⚙️ <b>Настройки фильтра поиска</b>\nВыбери, какой параметр хочешь изменить:\n\n" + self.format_user_dashboard(prof),
                reply_markup=self.settings_inline_keyboard(prof),
            )

        elif data == "cfg_sports":
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id})
            cur = ", ".join(prof.get("sports") or []) or "Все секции"
            await self.edit_message(
                chat_id,
                msg_id,
                f"🏅 <b>Выбор секций (видов спорта)</b>\nСейчас выбрано: <b>{html.escape(cur)}</b>\n\nНажимай на кнопки ниже, чтобы включить/выключить секцию (можно выбрать несколько):",
                reply_markup=self.sports_inline_keyboard(prof),
            )

        elif data.startswith("sp_tog:"):
            sp = data.split(":", 1)[1]
            cur_list: list[str] = prof.get("sports") or []
            existing = [x for x in cur_list if x.lower() == sp.lower()]
            if existing:
                for x in existing:
                    cur_list.remove(x)
            else:
                cur_list.append(sp)
            prof["sports"] = cur_list
            save_db(self.db)
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id, "text": f"Секции: {', '.join(cur_list) or 'Все'}"})
            cur_str = ", ".join(cur_list) or "Все секции"
            await self.edit_message(
                chat_id,
                msg_id,
                f"🏅 <b>Выбор секций (видов спорта)</b>\nСейчас выбрано: <b>{html.escape(cur_str)}</b>\n\nНажимай на кнопки ниже, чтобы включить/выключить секцию:",
                reply_markup=self.sports_inline_keyboard(prof),
            )

        elif data == "sp_all":
            prof["sports"] = []
            save_db(self.db)
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id, "text": "Выбраны все секции!"})
            await self.edit_message(
                chat_id,
                msg_id,
                "🏅 <b>Выбор секций (видов спорта)</b>\nСейчас выбрано: <b>Все секции</b>",
                reply_markup=self.sports_inline_keyboard(prof),
            )

        elif data == "sp_custom":
            prof["awaiting_custom_sport"] = True
            save_db(self.db)
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id})
            await self.send_message(
                chat_id,
                "✏️ Напиши название секции (или нескольких через запятую), например:\n<code>Бадминтон, Сквош</code>",
            )

        elif data == "cfg_days":
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id})
            await self.edit_message(
                chat_id,
                msg_id,
                "📆 <b>Выбери дни недели для мониторинга:</b>\n(можно отметить несколько дней или «Любой день»)",
                reply_markup=self.days_inline_keyboard(prof),
            )

        elif data.startswith("day_tog:"):
            d = int(data.split(":", 1)[1])
            cur_days: list[int] = prof.get("weekdays") or []
            if d in cur_days:
                cur_days.remove(d)
            else:
                cur_days.append(d)
                cur_days.sort()
            prof["weekdays"] = cur_days
            save_db(self.db)
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id})
            await self.edit_message(
                chat_id,
                msg_id,
                "📆 <b>Выбери дни недели для мониторинга:</b>",
                reply_markup=self.days_inline_keyboard(prof),
            )

        elif data == "day_all":
            prof["weekdays"] = []
            save_db(self.db)
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id, "text": "Выбраны все дни недели"})
            await self.edit_message(
                chat_id,
                msg_id,
                "📆 <b>Выбери дни недели для мониторинга:</b>",
                reply_markup=self.days_inline_keyboard(prof),
            )

        elif data == "cfg_times":
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id})
            await self.edit_message(
                chat_id,
                msg_id,
                "🕒 <b>Выбери нужное время начала занятий:</b>\n(можно выбрать несколько слотов или «Любое время»)",
                reply_markup=self.times_inline_keyboard(prof),
            )

        elif data.startswith("time_tog:"):
            t = data.split(":", 1)[1]
            cur_times: list[str] = prof.get("times") or []
            if t in cur_times:
                cur_times.remove(t)
            else:
                cur_times.append(t)
                cur_times.sort()
            prof["times"] = cur_times
            save_db(self.db)
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id})
            await self.edit_message(
                chat_id,
                msg_id,
                "🕒 <b>Выбери нужное время начала занятий:</b>",
                reply_markup=self.times_inline_keyboard(prof),
            )

        elif data == "time_all":
            prof["times"] = []
            save_db(self.db)
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id, "text": "Выбрано любое время"})
            await self.edit_message(
                chat_id,
                msg_id,
                "🕒 <b>Выбери нужное время начала занятий:</b>",
                reply_markup=self.times_inline_keyboard(prof),
            )

        elif data == "cfg_buildings":
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id})
            await self.edit_message(
                chat_id,
                msg_id,
                "🏢 <b>Выбери корпус ИТМО:</b>",
                reply_markup=self.buildings_inline_keyboard(prof),
            )

        elif data.startswith("bld_tog:"):
            b = int(data.split(":", 1)[1])
            cur_blds: list[int] = prof.get("buildings") or []
            if b in cur_blds:
                cur_blds.remove(b)
            else:
                cur_blds.append(b)
            prof["buildings"] = cur_blds
            save_db(self.db)
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id})
            await self.edit_message(
                chat_id,
                msg_id,
                "🏢 <b>Выбери корпус ИТМО:</b>",
                reply_markup=self.buildings_inline_keyboard(prof),
            )

        elif data == "bld_all":
            prof["buildings"] = []
            save_db(self.db)
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id, "text": "Выбраны все корпуса"})
            await self.edit_message(
                chat_id,
                msg_id,
                "🏢 <b>Выбери корпус ИТМО:</b>",
                reply_markup=self.buildings_inline_keyboard(prof),
            )

        elif data in ("toggle_auto", "toggle_auto_cfg"):
            prof["auto_sign_up"] = not prof.get("auto_sign_up", False)
            save_db(self.db)
            st = "ВКЛЮЧЕНА" if prof["auto_sign_up"] else "ВЫКЛЮЧЕНА"
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id, "text": f"Автозапись {st}"})
            kb = self.settings_inline_keyboard(prof) if data == "toggle_auto_cfg" else None
            await self.edit_message(chat_id, msg_id, self.format_user_dashboard(prof), reply_markup=kb)

        elif data in ("toggle_mon", "toggle_mon_cfg"):
            prof["monitoring_active"] = not prof.get("monitoring_active", True)
            prof["_paused_by_inactivity"] = False
            save_db(self.db)
            st = "ВКЛЮЧЕН" if prof["monitoring_active"] else "НА ПАУЗЕ"
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id, "text": f"Ежечасный поиск {st}"})
            kb = self.settings_inline_keyboard(prof) if data == "toggle_mon_cfg" else None
            await self.edit_message(chat_id, msg_id, self.format_user_dashboard(prof), reply_markup=kb)

        elif data == "menu_profile":
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id})
            await self.edit_message(
                chat_id,
                msg_id,
                "👤 <b>Управление профилем и аккаунтом ИСУ</b>\n\n" + self.format_user_dashboard(prof),
                reply_markup=self.profile_inline_keyboard(prof),
            )

        elif data == "prof_login":
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id})
            if chat_id != user_id:
                await self.send_message(chat_id, "🔒 В целях безопасности вводить логин и пароль можно только в личных сообщениях бота!")
                return
            prof["awaiting_login"] = True
            save_db(self.db)
            await self.send_message(
                chat_id,
                "🔑 <b>Вход в аккаунт my.itmo.ru</b>\n\n"
                "Отправь одним сообщением свой <b>логин (ИСУ) и пароль через пробел</b>, например:\n"
                "<code>312345 MySecretPass</code>\n\n"
                "<i>🔒 Бот мгновенно удалит твоё сообщение с паролем из чата и сохранит защищённую сессию.</i>",
            )

        elif data == "prof_delete_ask":
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id})
            kb = {
                "inline_keyboard": [
                    [{"text": "⚠️ Да, полностью удалить меня из бота", "callback_data": "prof_delete_confirm"}],
                    [{"text": "⬅️ Отмена", "callback_data": "menu_profile"}],
                ]
            }
            await self.edit_message(
                chat_id,
                msg_id,
                "🗑 <b>Удаление профиля из бота</b>\n\n"
                "Ты уверен? Твои токены авторизации, настройки фильтров и ежечасный мониторинг будут полностью удалены.",
                reply_markup=kb,
            )

        elif data == "prof_delete_confirm":
            uid = str(user_id)
            self.db.get("users", {}).pop(uid, None)
            self._clients.pop(uid, None)
            save_db(self.db)
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id, "text": "Твои данные удалены"})
            await self.edit_message(
                chat_id,
                msg_id,
                "✅ <b>Твой профиль, токены и подписка на поиск полностью удалены из бота.</b>\n"
                "Если захочешь вернуться — просто напиши <code>/start</code>!",
            )

        elif data in ("scan_free", "scan_all") or data.startswith("grp_slots:"):
            allowed, remain = self.check_user_rate_limit(user_id, "scan", USER_ACTION_MIN_INTERVAL)
            if not allowed:
                await self.tg_call(
                    "answerCallbackQuery",
                    {"callback_query_id": cq_id, "text": f"⏳ Подожди {remain} с перед следующим поиском...", "show_alert": False},
                )
                return
            if data == "scan_free":
                await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id, "text": "Ищу доступные слоты на 3 недели..."})
                await self.run_user_scan(chat_id, user_id, show_all=False, manual=True)
            elif data == "scan_all":
                await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id, "text": "Загружаю все слоты на 3 недели..."})
                await self.run_user_scan(chat_id, user_id, show_all=True, manual=True)
            else:
                sp_name = data.split(":", 1)[1]
                await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id, "text": f"Ищу свободные слоты: {sp_name}..."})
                await self.run_user_scan(chat_id, user_id, show_all=False, manual=True, override_sport=sp_name)

        elif data == "grp_leaderboard":
            allowed, remain = self.check_chat_board_rate_limit(chat_id, min_interval=5.0)
            if not allowed:
                await self.tg_call(
                    "answerCallbackQuery",
                    {"callback_query_id": cq_id, "text": f"⏳ Подожди {remain} с перед обновлением топа", "show_alert": False},
                )
                return
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id, "text": "Загружаю топ баллов..."})
            await self.send_leaderboard(chat_id)

        elif data == "my_score":
            allowed, remain = self.check_user_rate_limit(user_id, "score", USER_ACTION_MIN_INTERVAL)
            if not allowed:
                await self.tg_call(
                    "answerCallbackQuery",
                    {"callback_query_id": cq_id, "text": f"⏳ Подожди {remain} с перед запросом баллов...", "show_alert": False},
                )
                return
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id, "text": "Загружаю твои баллы..."})
            await self.send_score(chat_id, user_id, from_user)

        elif data == "my_lessons":
            allowed, remain = self.check_user_rate_limit(user_id, "my", USER_ACTION_MIN_INTERVAL)
            if not allowed:
                await self.tg_call(
                    "answerCallbackQuery",
                    {"callback_query_id": cq_id, "text": f"⏳ Подожди {remain} с перед запросом записей...", "show_alert": False},
                )
                return
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id, "text": "Загружаю твои записи..."})
            await self.send_chosen_lessons(chat_id, user_id, from_user)

        elif data.startswith("sign:"):
            allowed, remain = self.check_user_rate_limit(user_id, "sign", min_interval=2.0)
            if not allowed:
                await self.tg_call(
                    "answerCallbackQuery",
                    {"callback_query_id": cq_id, "text": f"⏳ Подожди {remain} с...", "show_alert": False},
                )
                return
            lesson_id = int(data.split(":", 1)[1])
            if not self.is_user_authenticated(prof):
                await self.tg_call(
                    "answerCallbackQuery",
                    {
                        "callback_query_id": cq_id,
                        "text": "Сначала войди в аккаунт ИСУ в личке бота (/login)!",
                        "show_alert": True,
                    },
                )
                return
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id, "text": "Отправляю запрос на запись..."})
            client = self.get_client_for_user(user_id)
            try:
                res = await client.sign_up_lesson(lesson_id)
                if res.get("error_code") == 0:
                    await self.send_message(
                        chat_id,
                        f"✅ <b>{html.escape(prof.get('name') or 'Студент')}, ты успешно записан на занятие (ID {lesson_id})!</b>",
                    )
                else:
                    await self.send_message(
                        chat_id,
                        f"⚠️ Ответ ИСУ для {html.escape(prof.get('name') or '')}: <code>{html.escape(str(res.get('error_message') or res))}</code>",
                    )
            except Exception as e:
                await self.send_message(chat_id, f"❌ Не удалось записаться: <code>{html.escape(str(e))}</code>")

        elif data.startswith("unsub:"):
            allowed, remain = self.check_user_rate_limit(user_id, "unsub", min_interval=2.0)
            if not allowed:
                await self.tg_call(
                    "answerCallbackQuery",
                    {"callback_query_id": cq_id, "text": f"⏳ Подожди {remain} с...", "show_alert": False},
                )
                return
            lesson_id = int(data.split(":", 1)[1])
            await self.tg_call("answerCallbackQuery", {"callback_query_id": cq_id, "text": "Отписываю от занятия..."})
            client = self.get_client_for_user(user_id)
            try:
                ok = await client.unsubscribe_lesson(lesson_id)
                if ok:
                    await self.send_message(chat_id, f"🗑 <b>Ты успешно отписался от занятия (ID {lesson_id}).</b>")
                    await self.send_chosen_lessons(chat_id, user_id, from_user)
                else:
                    await self.send_message(chat_id, "⚠️ Не удалось отписаться от занятия.")
            except Exception as e:
                await self.send_message(chat_id, f"❌ Ошибка при отписке: <code>{html.escape(str(e))}</code>")

    async def get_or_refresh_leaderboard(self) -> tuple[list[tuple[int, str]], float]:
        """
        Anti-DDoS & Account Shield for leaderboard:
        - Returns (board_list, last_updated_ts).
        - Serves from global cache if updated within LEADERBOARD_CACHE_TTL (15 min).
        - When refreshing, uses per-user cached score if updated within USER_SCORE_CACHE_TTL (1 hour).
        - Never bursts requests to ITMO: uses asyncio.Lock and 0.3s spacing between user API calls.
        - Other users' accounts are NEVER repeatedly contacted when someone requests /board.
        """
        now = time.time()
        if self._cached_leaderboard and (now - self._leaderboard_updated_at < LEADERBOARD_CACHE_TTL):
            return self._cached_leaderboard, self._leaderboard_updated_at

        async with self._leaderboard_lock:
            now = time.time()
            if self._cached_leaderboard and (now - self._leaderboard_updated_at < LEADERBOARD_CACHE_TTL):
                return self._cached_leaderboard, self._leaderboard_updated_at

            board: list[tuple[int, str]] = []
            changed = False
            users = list((self.db.get("users") or {}).items())

            for uid, prof in users:
                if not self.is_user_authenticated(prof):
                    continue

                pts = prof.get("cached_score")
                pts_ts = float(prof.get("cached_score_ts") or 0.0)

                # Only fetch from ITMO if there is no cached score or it is older than USER_SCORE_CACHE_TTL (1h)
                need_fetch = (pts is None) or ((now - pts_ts) > USER_SCORE_CACHE_TTL)
                if need_fetch:
                    try:
                        client = self.get_client_for_user(int(uid))
                        data = await client.get_score_and_attempts()
                        sums = (data.get("score") or {}).get("sum") or {}
                        pts = int(sums.get("attendances", 0) or 0) + int(sums.get("other", 0) or 0)
                        prof["cached_score"] = pts
                        prof["cached_score_ts"] = now
                        changed = True
                        await asyncio.sleep(0.3)
                    except Exception as e:
                        logger.warning(f"Could not refresh score for user {uid} during leaderboard build: {e}")
                        pts = prof.get("cached_score")

                if pts is not None:
                    board.append((pts, prof.get("name") or f"User {uid}"))

            if changed:
                save_db(self.db)

            board.sort(key=lambda x: x[0], reverse=True)
            self._cached_leaderboard = board
            self._leaderboard_updated_at = now
            return self._cached_leaderboard, self._leaderboard_updated_at

    async def send_leaderboard(self, chat_id: int) -> None:
        board, updated_at = await self.get_or_refresh_leaderboard()
        if not board:
            await self.send_message(chat_id, "📊 Пока никто из участников не авторизовался в боте для подсчёта баллов.")
            return

        medals = ["🥇", "🥈", "🥉"]
        lines = ["📊 <b>Топ баллов за физкультуру ИТМО:</b>\n"]
        for idx, (pts, name) in enumerate(board[:15]):
            prefix = medals[idx] if idx < 3 else f"<b>{idx + 1}.</b>"
            status = "✅ Зачёт" if pts >= 100 else f"осталось {100 - pts}"
            lines.append(f"{prefix} <b>{html.escape(name)}</b> — <b>{pts}</b> балл. ({status})")

        age_sec = int(time.time() - updated_at)
        if age_sec < 60:
            freshness = "только что"
        elif age_sec < 3600:
            freshness = f"{age_sec // 60} мин. назад"
        else:
            freshness = f"{age_sec // 3600} ч. назад"

        lines.append(f"\n🛡️ <i>Данные обновлены: {freshness} (кэш защищает аккаунты от спама)</i>")
        await self.send_message(chat_id, "\n".join(lines), reply_markup=self.group_inline_keyboard())

    async def send_admin_users(self, chat_id: int) -> None:
        users = self.db.get("users") or {}
        if not users:
            await self.send_message(chat_id, "👥 В базе бота пока нет пользователей.")
            return

        now = time.time()
        lines = [f"👑 <b>Админ-панель: пользователи бота ({len(users)} чел.)</b>\n"]
        for idx, (uid, prof) in enumerate(users.items(), 1):
            name = html.escape(prof.get("name") or f"User {uid}")
            uname = f" (@{html.escape(prof['username'])})" if prof.get("username") else ""
            auth_ok = self.is_user_authenticated(prof)
            isu_id = (prof.get("auth") or {}).get("login") or ("токен" if auth_ok else "нет")
            auth_badge = f"✅ ИСУ: <code>{html.escape(str(isu_id))}</code>" if auth_ok else "❌ Не авторизован"

            mon_badge = "🟢 Поиск ВКЛ" if prof.get("monitoring_active", True) else "⏸ На паузе"
            auto_badge = "🤖 Автозапись ВКЛ" if prof.get("auto_sign_up") else "⚪ Автозапись ВЫКЛ"

            sports_str = ", ".join(prof.get("sports") or []) or "Все секции"
            days = prof.get("weekdays") or []
            days_str = ", ".join(WEEKDAY_SHORT.get(d, str(d)) for d in sorted(days)) if days else "Любой"
            times_str = ", ".join(prof.get("times") or []) or "Любое"

            last_ts = float(prof.get("last_active_ts") or now)
            days_ago = max(0, int((now - last_ts) // 86400))
            hours_ago = max(0, int((now - last_ts) // 3600))
            active_str = f"{hours_ago} ч. назад" if days_ago == 0 else f"{days_ago} дн. назад"
            pts = prof.get("cached_score")
            pts_str = f"{pts} балл." if pts is not None else "—"

            lines.append(
                f"<b>{idx}. {name}</b>{uname} [<code>{uid}</code>]\n"
                f"   • {auth_badge} | 🏆 Баллы: <b>{pts_str}</b>\n"
                f"   • {mon_badge} | {auto_badge}\n"
                f"   • 🎯 Фильтр: <b>{html.escape(sports_str)}</b> ({days_str} | {times_str})\n"
                f"   • 🕒 Активность: {active_str}\n"
            )

        await self.send_message(chat_id, "\n".join(lines))

    async def perform_login(self, chat_id: int, user_id: int, login_val: str, password_val: str, from_user: dict[str, Any]) -> None:
        prof = self.get_user(user_id, from_user, touch=True)
        prof["awaiting_login"] = False
        client = self.get_client_for_user(user_id)
        await self.send_message(chat_id, "🔄 Выполняю вход в ITMO ID (id.itmo.ru)...")
        try:
            await client.login_with_credentials(login_val, password_val)
            save_db(self.db)
            await self.send_message(
                chat_id,
                "✅ <b>Авторизация в my.itmo.ru прошла успешно!</b>\n\n" + self.format_user_dashboard(prof),
                reply_markup=self.reply_keyboard(),
            )
            await self.run_user_scan(chat_id, user_id, show_all=False, manual=True)
        except Exception as e:
            await self.send_message(
                chat_id,
                f"❌ <b>Ошибка входа:</b> <code>{html.escape(str(e))}</code>\nПопробуй ещё раз через кнопку «🔑 Войти» или <code>/login ИСУ ПАРОЛЬ</code>.",
            )

    async def handle_message(self, msg: dict[str, Any]) -> None:
        chat = msg.get("chat") or {}
        chat_id = chat.get("id")
        chat_type = chat.get("type", "private")
        from_user = msg.get("from") or {}
        user_id = from_user.get("id")
        text = (msg.get("text") or "").strip()
        if not chat_id or not user_id or not text:
            return

        is_group = chat_type in ("group", "supergroup")
        prof = self.get_user(user_id, from_user, touch=True)

        # Normalize slash commands in groups (e.g. /check@MyBot -> /check)
        cmd = text.split()[0].lower() if text.startswith("/") else ""
        if "@" in cmd:
            cmd = cmd.split("@", 1)[0]
        arg_str = text.split(maxsplit=1)[1].strip() if len(text.split(maxsplit=1)) > 1 else ""

        # Security: if someone sends /login in a group chat, delete it immediately!
        if is_group and cmd == "/login":
            try:
                await self.tg_call("deleteMessage", {"chat_id": chat_id, "message_id": msg["message_id"]})
            except Exception:
                pass
            await self.send_message(
                chat_id,
                "🔒 <b>Никогда не отправляй пароль в общую группу!</b>\nПерейди ко мне в личные сообщения и авторизуйся там.",
            )
            return

        # Handle interactive states in private chat
        if not is_group and not text.startswith("/"):
            if prof.get("awaiting_login") and len(text.split()) == 2:
                try:
                    await self.tg_call("deleteMessage", {"chat_id": chat_id, "message_id": msg["message_id"]})
                except Exception:
                    pass
                l_val, p_val = text.split(maxsplit=1)
                await self.perform_login(chat_id, user_id, l_val, p_val, from_user)
                return

            if prof.get("awaiting_custom_sport"):
                prof["awaiting_custom_sport"] = False
                custom_list = [s.strip().capitalize() for s in text.split(",") if s.strip()]
                prof["sports"] = custom_list
                save_db(self.db)
                await self.send_message(
                    chat_id,
                    f"✅ Секции для поиска обновлены: <b>{html.escape(', '.join(custom_list) or 'Все секции')}</b>",
                    reply_markup=self.reply_keyboard(),
                )
                return

        # Bottom ReplyKeyboard button presses in private chat
        if text in ("🔍 Свободные слоты", "📋 Все слоты") or cmd in ("/check", "/all", "/slots", "/free"):
            allowed, remain = self.check_user_rate_limit(user_id, "scan", USER_ACTION_MIN_INTERVAL)
            if not allowed:
                await self.send_message(
                    chat_id,
                    f"⏳ <b>Слишком частые запросы!</b> Пожалуйста, подожди {remain} с. перед следующим поиском слотов.",
                )
                return

            if text == "🔍 Свободные слоты" or cmd in ("/check", "/slots", "/free"):
                ovr = arg_str if cmd in ("/check", "/slots", "/free") and arg_str else None
                await self.run_user_scan(chat_id, user_id, show_all=False, manual=True, override_sport=ovr)
                return

            if text == "📋 Все слоты" or cmd == "/all":
                ovr = arg_str if cmd == "/all" and arg_str else None
                await self.run_user_scan(chat_id, user_id, show_all=True, manual=True, override_sport=ovr)
                return

        if text == "🏆 Мои баллы" or cmd in ("/score", "/points"):
            allowed, remain = self.check_user_rate_limit(user_id, "score", USER_ACTION_MIN_INTERVAL)
            if not allowed:
                await self.send_message(chat_id, f"⏳ Подожди {remain} с. перед повторным запросом баллов.")
                return
            await self.send_score(chat_id, user_id, from_user)
            return

        if text == "📅 Мои записи" or cmd == "/my":
            allowed, remain = self.check_user_rate_limit(user_id, "my", USER_ACTION_MIN_INTERVAL)
            if not allowed:
                await self.send_message(chat_id, f"⏳ Подожди {remain} с. перед повторным запросом записей.")
                return
            await self.send_chosen_lessons(chat_id, user_id, from_user)
            return

        if text == "⚙️ Настройки поиска" or cmd == "/settings":
            await self.send_message(
                chat_id,
                "⚙️ <b>Настройки фильтра поиска</b>\n\n" + self.format_user_dashboard(prof),
                reply_markup=self.settings_inline_keyboard(prof),
            )
            return

        if text == "👤 Профиль" or cmd == "/profile":
            await self.send_message(
                chat_id,
                "👤 <b>Управление профилем</b>\n\n" + self.format_user_dashboard(prof),
                reply_markup=self.profile_inline_keyboard(prof),
            )
            return

        if cmd in ("/start", "/help"):
            if is_group:
                await self.send_message(
                    chat_id,
                    "🏸 <b>Привет! Я бот мониторинга и записи на физкультуру ИТМО (my.itmo.ru).</b>\n\n"
                    "<b>Команды в групповом чате:</b>\n"
                    "• <code>/slots [секция]</code> — найти свободные места на 3 недели вперёд (например, <code>/slots бадминтон</code> или <code>/slots волейбол</code>)\n"
                    "• <code>/score</code> — показать твои баллы за физру и прогресс до зачёта\n"
                    "• <code>/my</code> — показать твои будущие записи на занятия\n"
                    "• <code>/board</code> — топ баллов за физру среди участников чата\n\n"
                    "<i>💡 Чтобы записываться в 1 клик и настроить личный ежечасный мониторинг — напиши мне <code>/start</code> в личные сообщения!</i>",
                    reply_markup=self.group_inline_keyboard(),
                )
            else:
                await self.send_message(
                    chat_id,
                    self.format_user_dashboard(prof),
                    reply_markup=self.reply_keyboard(),
                )
            return

        if cmd == "/board":
            allowed, remain = self.check_chat_board_rate_limit(chat_id, CHAT_BOARD_MIN_INTERVAL)
            if not allowed:
                if is_group:
                    return
                await self.send_message(chat_id, f"⏳ Топ баллов уже выведен выше. Подожди {remain} с.")
                return
            await self.send_leaderboard(chat_id)
            return

        if cmd in ("/users", "/admin"):
            if user_id != ADMIN_USER_ID:
                await self.send_message(chat_id, "⛔ Эта команда доступна только создателю бота.")
                return
            await self.send_admin_users(chat_id)
            return

        if cmd == "/sport":
            if not arg_str:
                await self.send_message(chat_id, "Укажи название секции, например: <code>/sport Волейбол</code>")
                return
            prof["sports"] = [s.strip().capitalize() for s in arg_str.split(",") if s.strip()]
            save_db(self.db)
            await self.send_message(
                chat_id,
                f"✅ Секции обновлены: <b>{html.escape(', '.join(prof['sports']))}</b>",
                reply_markup=self.reply_keyboard(),
            )
            return

        if cmd == "/delete_me":
            kb = {
                "inline_keyboard": [
                    [{"text": "⚠️ Да, полностью удалить меня из бота", "callback_data": "prof_delete_confirm"}],
                ]
            }
            await self.send_message(chat_id, "Подтверди удаление своих данных из бота:", reply_markup=kb)
            return

        if cmd == "/login":
            try:
                await self.tg_call("deleteMessage", {"chat_id": chat_id, "message_id": msg["message_id"]})
            except Exception:
                pass
            parts = text.split(maxsplit=2)
            if len(parts) < 3:
                prof["awaiting_login"] = True
                save_db(self.db)
                await self.send_message(
                    chat_id,
                    "Отправь следующим сообщением <b>логин_ИСУ и пароль через пробел</b> (или <code>/login ИСУ ПАРОЛЬ</code>):",
                )
                return
            await self.perform_login(chat_id, user_id, parts[1], parts[2], from_user)
            return

        if cmd == "/token":
            if not arg_str:
                await self.send_message(chat_id, "Использование: <code>/token ТВОЙ_BEARER_ТОКЕН</code>")
                return
            client = self.get_client_for_user(user_id)
            client.set_manual_token(arg_str)
            await self.send_message(chat_id, "✅ Токен сохранен! Проверяю доступные слоты на 3 недели вперёд...")
            await self.run_user_scan(chat_id, user_id, show_all=False, manual=True)
            return

        if cmd == "/interval":
            if not arg_str.isdigit() or int(arg_str) < 1:
                await self.send_message(chat_id, "Укажи интервал в минутах (от 1), например: <code>/interval 60</code>")
                return
            self.db.setdefault("meta", {})["check_interval_minutes"] = int(arg_str)
            save_db(self.db)
            await self.send_message(chat_id, f"⏱ Интервал фонового сканирования: каждые <b>{arg_str} мин.</b>")
            return

    # ─── Background Loops ────────────────────────────────────────────────────

    async def check_inactivity_and_scan(self) -> None:
        now = time.time()
        users = list((self.db.get("users") or {}).items())
        for uid, prof in users:
            user_id = int(uid)
            if not prof.get("monitoring_active", True):
                continue

            last_active = float(prof.get("last_active_ts") or now)
            if now - last_active > INACTIVE_TIMEOUT_SECONDS:
                prof["monitoring_active"] = False
                prof["_paused_by_inactivity"] = True
                save_db(self.db)
                kb = {
                    "inline_keyboard": [
                        [{"text": "▶️ Возобновить поиск слотов", "callback_data": "toggle_mon"}],
                        [{"text": "🗑 Удалить меня из бота", "callback_data": "prof_delete_confirm"}],
                    ]
                }
                try:
                    await self.send_message(
                        user_id,
                        "💤 <b>Автоматический поиск поставлен на паузу</b>\n\n"
                        "Ты не взаимодействовал с ботом больше <b>3 недель</b>, поэтому мы временно исключили тебя из ежечасного сканирования слотов.\n\n"
                        "Нажми кнопку ниже в любой момент, чтобы снова включить мониторинг!",
                        reply_markup=kb,
                    )
                except Exception as e:
                    logger.warning(f"Failed to send inactivity notice to {user_id}: {e}")
                continue

            if self.is_user_authenticated(prof):
                logger.info(f"Scheduled scan for user {user_id}...")
                await self.run_user_scan(user_id, user_id, show_all=False, manual=False)
                await asyncio.sleep(2)

    async def scheduler_loop(self) -> None:
        logger.info("Background multi-user slot scanner started.")
        while True:
            interval_min = int((self.db.get("meta") or {}).get("check_interval_minutes", 60))
            interval_sec = max(60, interval_min * 60)
            try:
                await self.check_inactivity_and_scan()
            except Exception as e:
                logger.warning(f"Error in scheduler loop: {e}")
            await asyncio.sleep(interval_sec)

    async def polling_loop(self) -> None:
        me = await self.tg_call("getMe")
        if me.get("ok"):
            self.bot_username = (me.get("result") or {}).get("username", "")
            logger.info(f"Telegram bot @{self.bot_username} polling started.")
        else:
            logger.info("Telegram bot polling started.")

        # Register bot commands menu in Telegram UI
        await self.tg_call(
            "setMyCommands",
            {
                "commands": [
                    {"command": "start", "description": "Главное меню и панель управления"},
                    {"command": "check", "description": "Проверить доступные свободные слоты"},
                    {"command": "all", "description": "Показать все слоты по фильтру (3 недели)"},
                    {"command": "score", "description": "Мои баллы за физру и прогресс до зачёта"},
                    {"command": "my", "description": "Мои будущие записи и отписка"},
                    {"command": "settings", "description": "Настроить секции, дни, время и автозапись"},
                    {"command": "board", "description": "Топ баллов за физру среди пользователей"},
                    {"command": "profile", "description": "Профиль ИСУ и удаление своих данных"},
                ]
            },
        )

        while True:
            try:
                res = await self.tg_call(
                    "getUpdates",
                    {"offset": self.offset, "timeout": 25},
                    timeout=35.0,
                )
                if res.get("ok"):
                    for upd in res.get("result", []):
                        self.offset = upd["update_id"] + 1
                        if "callback_query" in upd:
                            await self.handle_callback(upd["callback_query"])
                        elif "message" in upd:
                            await self.handle_message(upd["message"])
                else:
                    logger.warning(f"Telegram getUpdates error: {res}")
                    await asyncio.sleep(5)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Polling network error: {e}")
                await asyncio.sleep(5)


async def main() -> None:
    load_dotenv()
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not bot_token or bot_token == "your_bot_token_here":
        print("ОШИБКА: Укажи TELEGRAM_BOT_TOKEN в файле .env!")
        return

    db = load_db()
    bot = TelegramBot(bot_token, db)

    # Notify existing users about the v3 update once
    meta = db.setdefault("meta", {})
    if not meta.get("notified_update_v3"):
        meta["notified_update_v3"] = True
        save_db(db)
        for uid, prof in (db.get("users") or {}).items():
            try:
                cid = int(uid)
                await bot.send_message(
                    cid,
                    bot.format_user_dashboard(prof),
                    reply_markup=bot.reply_keyboard(),
                )
            except Exception as e:
                logger.warning(f"Could not send v3 update notice to {uid}: {e}")

    await asyncio.gather(
        bot.polling_loop(),
        bot.scheduler_loop(),
    )


if __name__ == "__main__":
    asyncio.run(main())
