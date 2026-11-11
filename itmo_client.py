import base64
import hashlib
import html
import json
import logging
import os
import re
import secrets
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

logger = logging.getLogger("itmo_client")

BASE_URL = "https://my.itmo.ru"
AUTH_URL = "https://id.itmo.ru/auth/realms/itmo/protocol/openid-connect/auth"
TOKEN_URL = "https://id.itmo.ru/auth/realms/itmo/protocol/openid-connect/token"
CLIENT_ID = "student-personal-cabinet"
REDIRECT_URI = "https://my.itmo.ru/login/callback"

WEEKDAY_NAMES = {
    1: "Понедельник",
    2: "Вторник",
    3: "Среда",
    4: "Четверг",
    5: "Пятница",
    6: "Суббота",
    7: "Воскресенье",
}

WEEKDAY_SHORT = {
    1: "Пн",
    2: "Вт",
    3: "Ср",
    4: "Чт",
    5: "Пт",
    6: "Сб",
    7: "Вс",
}


class ItmoAuthError(Exception):
    pass


class ItmoSportClient:
    def __init__(
        self,
        login: str | None = None,
        password: str | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        expires_at: float = 0.0,
        on_tokens_updated: Any = None,
    ):
        self.login = login
        self.password = password
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_at = float(expires_at or 0.0)
        self.on_tokens_updated = on_tokens_updated

    def _notify_tokens(self) -> None:
        if callable(self.on_tokens_updated):
            self.on_tokens_updated(
                {
                    "login": self.login,
                    "password": None,          # Never persist the password after first login
                    "access_token": self.access_token,
                    "refresh_token": self.refresh_token,
                    "expires_at": self.expires_at,
                }
            )

    def set_manual_token(self, token: str) -> None:
        clean = token.strip()
        if clean.lower().startswith("bearer "):
            clean = clean[7:].strip()
        self.access_token = clean
        self.expires_at = time.time() + 3600
        self._notify_tokens()

    async def login_with_credentials(self, login: str | None = None, password: str | None = None) -> str:
        if login:
            self.login = login
        if password:
            self.password = password
        if not self.login or not self.password:
            raise ItmoAuthError("Не указаны логин/пароль ИСУ и нет активного токена.")

        verifier = secrets.token_urlsafe(32)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            .decode("ascii")
            .rstrip("=")
        )
        state = secrets.token_urlsafe(12)

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            )
        }

        async with httpx.AsyncClient(follow_redirects=True, headers=headers, timeout=25.0) as client:
            r = await client.get(
                AUTH_URL,
                params={
                    "protocol": "oauth2",
                    "response_type": "code",
                    "access_type": "",
                    "client_id": CLIENT_ID,
                    "redirect_uri": REDIRECT_URI,
                    "scope": "openid profile",
                    "state": state,
                    "code_challenge_method": "S256",
                    "code_challenge": challenge,
                },
            )
            r.raise_for_status()

            m = re.search(r'"loginAction":\s*"([^"]+)"', r.text) or re.search(
                r'action="([^"]+)"', r.text
            )
            if not m:
                raise ItmoAuthError("Не удалось найти URL формы входа на id.itmo.ru.")
            login_action_url = html.unescape(m.group(1))

            resp = await client.post(
                login_action_url,
                data={"username": self.login, "password": self.password, "rememberMe": "on"},
                follow_redirects=False,
            )

            hops = 0
            location = resp.headers.get("location", "")
            while resp.status_code in (301, 302, 303, 307, 308) and location and hops < 8:
                if location.startswith(REDIRECT_URI) or "code=" in location:
                    break
                resp = await client.get(location, follow_redirects=False)
                location = resp.headers.get("location", "")
                hops += 1

            if not location or "code=" not in location:
                err_match = re.search(r'"messageSummary":\s*"([^"]+)"', resp.text)
                err_msg = err_match.group(1) if err_match else "Неверный логин/пароль или требуется подтверждение."
                raise ItmoAuthError(f"Ошибка входа в ITMO ID: {err_msg}")

            parsed = urlparse(location)
            code = parse_qs(parsed.query).get("code", [None])[0]
            if not code:
                raise ItmoAuthError("Не удалось получить OAuth code от id.itmo.ru.")

            token_resp = await client.post(
                TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "client_id": CLIENT_ID,
                    "redirect_uri": REDIRECT_URI,
                    "code": code,
                    "code_verifier": verifier,
                },
            )
            if token_resp.status_code != 200:
                raise ItmoAuthError(f"Ошибка обмена кода на токен: {token_resp.text}")

            tdata = token_resp.json()
            self.access_token = tdata["access_token"]
            self.refresh_token = tdata.get("refresh_token")
            self.expires_at = time.time() + float(tdata.get("expires_in", 1800)) - 60
            # Discard the password from memory — only tokens are needed from now on
            self.password = None
            self._notify_tokens()
            logger.info("Successfully authenticated with ITMO ID via OAuth2 PKCE.")
            return self.access_token

    async def refresh_access_token(self) -> str:
        if not self.refresh_token:
            return await self.login_with_credentials()

        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(
                TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "client_id": CLIENT_ID,
                    "refresh_token": self.refresh_token,
                },
            )
            if resp.status_code == 200:
                tdata = resp.json()
                self.access_token = tdata["access_token"]
                if tdata.get("refresh_token"):
                    self.refresh_token = tdata["refresh_token"]
                self.expires_at = time.time() + float(tdata.get("expires_in", 1800)) - 60
                self._notify_tokens()
                return self.access_token

        return await self.login_with_credentials()

    async def ensure_token(self) -> str:
        if self.access_token and time.time() < self.expires_at:
            return self.access_token
        if self.refresh_token or (self.login and self.password):
            return await self.refresh_access_token()
        if self.access_token:
            return self.access_token
        raise ItmoAuthError(
            "Нет авторизации в my.itmo.ru. Используй /login <ИСУ> <пароль> в ЛС бота."
        )

    async def _request(self, method: str, path: str, **kwargs) -> dict[str, Any]:
        token = await self.ensure_token()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        headers["Accept"] = "application/json"
        headers["Accept-Language"] = "ru"

        async with httpx.AsyncClient(base_url=BASE_URL, timeout=25.0) as client:
            resp = await client.request(method, path, headers=headers, **kwargs)
            if resp.status_code == 401:
                if self.refresh_token or (self.login and self.password):
                    token = await self.refresh_access_token()
                    headers["Authorization"] = f"Bearer {token}"
                    resp = await client.request(method, path, headers=headers, **kwargs)
                else:
                    raise ItmoAuthError("Токен my.itmo.ru истек (401). Авторизуйся заново через /login <ИСУ> <пароль>.")
            resp.raise_for_status()
            return resp.json()

    async def get_filters(self) -> dict[str, Any]:
        data = await self._request("GET", "/api/sport/sign/schedule/filters")
        return data.get("result") or {}

    async def get_time_slots(self) -> list[dict[str, Any]]:
        data = await self._request("GET", "/api/sport/time_slots")
        return data.get("result") or []

    async def get_limits(self) -> dict[str, Any]:
        data = await self._request("GET", "/api/sport/sign/schedule/limits")
        return data.get("result") or {}

    async def get_current_semester(self) -> dict[str, Any]:
        data = await self._request("GET", "/api/sport/semesters/current")
        return data.get("result") or {}

    async def get_score_and_attempts(self) -> dict[str, Any]:
        sem = await self.get_current_semester()
        sem_id = sem.get("id", 41)
        score_resp = await self._request("GET", "/api/sport/personal/score", params={"semester_id": sem_id})
        attempts_resp = await self._request("GET", "/api/sport/personal/sign_attempts")
        debt_resp = await self._request("GET", "/api/sport/personal/debt")
        return {
            "semester": sem,
            "score": score_resp.get("result") or {},
            "free_signs": attempts_resp.get("result"),
            "debt": debt_resp.get("result") or {},
        }

    async def get_chosen_lessons(self) -> list[dict[str, Any]]:
        data = await self._request("GET", "/api/sport/sign/chosen")
        sections = data.get("result") or []
        now = datetime.now().astimezone()
        upcoming: list[dict[str, Any]] = []
        for sec in sections:
            sec_name = sec.get("section_name", "Секция")
            for grp in sec.get("lesson_groups") or []:
                for les in grp.get("lessons") or []:
                    raw_end = str(les.get("date_end") or les.get("date_start") or "")
                    raw_start = str(les.get("date_start") or "")
                    try:
                        dt_end = datetime.fromisoformat(raw_end)
                        if dt_end < now:
                            continue
                        dt_start = datetime.fromisoformat(raw_start)
                        iso_w = dt_start.isoweekday()
                    except Exception:
                        iso_w = 1
                    upcoming.append(
                        {
                            "id": les.get("id"),
                            "section_name": sec_name,
                            "date": raw_start[:10],
                            "weekday_name": WEEKDAY_NAMES.get(iso_w, ""),
                            "time_start": les.get("time_start") or raw_start[11:16],
                            "time_end": les.get("time_end") or raw_end[11:16],
                            "room_name": les.get("room_name") or "Не указан",
                            "teacher_fio": les.get("teacher_fio") or "Не указан",
                        }
                    )
        upcoming.sort(key=lambda x: (x["date"], x["time_start"]))
        return upcoming

    async def get_schedule(
        self,
        date_start: str,
        date_end: str,
        sport_type_ids: list[int] | None = None,
        building_id: int | None = None,
    ) -> list[dict[str, Any]]:
        params: list[tuple[str, Any]] = [
            ("date_start", date_start),
            ("date_end", date_end),
        ]
        if sport_type_ids:
            for sid in sport_type_ids:
                params.append(("sport_type_id", sid))
        if building_id is not None:
            params.append(("building_id", building_id))

        data = await self._request("GET", "/api/sport/sign/schedule", params=params)
        return data.get("result") or []

    async def sign_up_lesson(self, lesson_id: int) -> dict[str, Any]:
        return await self._request("POST", "/api/sport/sign/schedule/lessons", json=[lesson_id])

    async def unsubscribe_lesson(self, lesson_id: int) -> bool:
        token = await self.ensure_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Accept-Language": "ru",
        }
        async with httpx.AsyncClient(base_url=BASE_URL, timeout=25.0) as client:
            resp = await client.request(
                "DELETE",
                "/api/sport/sign/schedule/lessons",
                headers=headers,
                json=[lesson_id],
            )
            return resp.status_code == 200

    async def find_matching_slots(
        self,
        sport_keywords: list[str] | None = None,
        target_weekdays: list[int] | tuple[int, ...] = (1, 4),
        target_times: list[str] | tuple[str, ...] = ("15:30", "17:10"),
        target_building_ids: list[int] | None = None,
        weeks_ahead: int = 3,
    ) -> list[dict[str, Any]]:
        """
        Finds all schedule lessons matching sport_keywords (empty = all sports),
        target ISO weekdays (empty = all days), target start times (empty = all times),
        enriched with real-time available seats for 3 weeks ahead.
        """
        filters = await self.get_filters()
        limits = await self.get_limits()
        time_slots_list = await self.get_time_slots()
        time_slot_map = {
            ts["id"]: (ts.get("time_start", ""), ts.get("time_end", ""))
            for ts in time_slots_list
            if "id" in ts
        }

        sport_types = filters.get("sport_type_id") or []
        matching_sport_ids: list[int] = []
        kw_lower = [k.lower().strip() for k in (sport_keywords or []) if k.strip()]

        if kw_lower:
            for st in sport_types:
                val = str(st.get("value", "")).lower()
                if any(k in val for k in kw_lower):
                    matching_sport_ids.append(st["id"])

        buildings = filters.get("building_id") or []
        if target_building_ids:
            building_ids = target_building_ids
        else:
            building_ids = [b["id"] for b in buildings if "id" in b and b["id"] != -1]
            if not building_ids:
                building_ids = [273, 5, 0]

        today = date.today()
        monday = today - timedelta(days=today.weekday())
        date_start = monday.isoformat()
        date_end = (monday + timedelta(days=7 * weeks_ahead)).isoformat()

        seen_lesson_ids: set[int] = set()
        matched_lessons: list[dict[str, Any]] = []

        for b_id in building_ids:
            try:
                days_data = await self.get_schedule(
                    date_start=date_start,
                    date_end=date_end,
                    sport_type_ids=matching_sport_ids if matching_sport_ids else None,
                    building_id=b_id,
                )
            except Exception as e:
                logger.warning(f"Failed fetching schedule for building {b_id}: {e}")
                continue

            for day_entry in days_data:
                day_str = str(day_entry.get("date", ""))[:10]
                lessons = day_entry.get("lessons") or []
                for lesson in lessons:
                    lid = lesson.get("id")
                    if lid in seen_lesson_ids:
                        continue

                    sec_name = str(lesson.get("section_name", ""))
                    if kw_lower and not matching_sport_ids:
                        if not any(k in sec_name.lower() for k in kw_lower):
                            continue

                    raw_dt = str(lesson.get("date") or lesson.get("date_start") or day_str)
                    raw_end = str(lesson.get("date_end") or "")
                    lesson_date_str = raw_dt[:10]
                    try:
                        dt_obj = datetime.fromisoformat(raw_dt)
                        iso_weekday = dt_obj.isoweekday()
                        time_from_dt = dt_obj.strftime("%H:%M")
                        if dt_obj.tzinfo and dt_obj < datetime.now(dt_obj.tzinfo):
                            continue
                    except Exception:
                        try:
                            d_obj = date.fromisoformat(lesson_date_str)
                            iso_weekday = d_obj.isoweekday()
                        except Exception:
                            continue
                        time_from_dt = ""

                    if lesson_date_str < today.isoformat():
                        continue

                    try:
                        time_end_from_dt = datetime.fromisoformat(raw_end).strftime("%H:%M") if raw_end else ""
                    except Exception:
                        time_end_from_dt = raw_end[11:16] if len(raw_end) >= 16 else ""

                    ts_id = lesson.get("time_slot_id")
                    grid_slot_start = str(
                        lesson.get("time_slot_start")
                        or (time_slot_map.get(ts_id, ("", ""))[0] if ts_id else "")
                    )[:5]
                    slot_start = (time_from_dt or grid_slot_start)[:5]
                    slot_end = (
                        time_end_from_dt
                        or str(lesson.get("time_slot_end") or "")[:5]
                        or (time_slot_map.get(ts_id, ("", ""))[1] if ts_id else "")[:5]
                    )

                    if target_weekdays and iso_weekday not in target_weekdays:
                        continue
                    if target_times and (slot_start not in target_times and grid_slot_start not in target_times):
                        continue

                    seen_lesson_ids.add(lid)

                    lg_id = str(lesson.get("lesson_group_id", ""))
                    lid_str = str(lid)
                    group_limits = limits.get(lg_id) or limits.get(lesson.get("lesson_group_id")) or {}
                    lesson_limit_info = (
                        group_limits.get(lid_str)
                        or group_limits.get(lid)
                        or {}
                    )
                    raw_avail = lesson_limit_info.get("available", lesson.get("available", 0))
                    raw_limit = lesson_limit_info.get("limit", lesson.get("limit", 0))
                    available = max(0, int(raw_avail or 0))
                    limit_total = max(0, int(raw_limit or 0))

                    can_sign_obj = lesson.get("can_sign_in") or {}
                    can_sign = bool(can_sign_obj.get("can_sign_in", False))
                    reasons = can_sign_obj.get("unavailable_reasons") or []
                    # Detect schedule collision (пересечение с другим занятием)
                    collision = bool(can_sign_obj.get("has_collision") or any(
                        any(kw in str(r).lower() for kw in (
                            "колли", "пересеч", "совпад", "collision", "conflict",
                            "другое занятие", "другой урок", "уже записан", "occupied",
                        ))
                        for r in reasons
                    ))

                    matched_lessons.append(
                        {
                            "id": lid,
                            "lesson_group_id": lesson.get("lesson_group_id"),
                            "section_name": sec_name,
                            "date": lesson_date_str,
                            "weekday": iso_weekday,
                            "weekday_name": WEEKDAY_NAMES.get(iso_weekday, str(iso_weekday)),
                            "time_start": slot_start,
                            "time_end": slot_end,
                            "room_name": lesson.get("room_name") or "Не указан",
                            "teacher_fio": lesson.get("teacher_fio") or "Не указан",
                            "available": available,
                            "limit": limit_total,
                            "can_sign_in": can_sign,
                            "has_collision": collision,
                            "unavailable_reasons": reasons,
                        }
                    )

        matched_lessons.sort(key=lambda x: (x["date"], x["time_start"], x["id"]))
        return matched_lessons
