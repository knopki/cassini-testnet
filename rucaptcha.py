#!/usr/bin/env python3

import aiohttp
import asyncio
import dataclasses
from datetime import datetime, timedelta
from typing import Optional, Union
from dataclasses import dataclass


@dataclass
class RuCaptchaV2JobRequest:
    method: str
    json: int
    key: str
    googlekey: str
    pageurl: str


@dataclass
class RuCaptchaV2OkResponse:
    status = 1
    request: str


@dataclass
class RuCaptchaV2ErrorResponse:
    status = 0
    request: str
    error_text: Optional[str] = None


@dataclass
class RuCaptchaV2ResultRequest:
    key: str
    action: str
    id: str
    json: int


RuCaptchaV2Result = Union[RuCaptchaV2OkResponse, RuCaptchaV2ErrorResponse]


class RuCaptchaV2:
    in_url = "http://rucaptcha.com/in.php"
    res_url = "http://rucaptcha.com/res.php"
    key: str
    site_key: str
    url: str

    def __init__(self, key: str, site_key: str, url: str) -> None:
        self.key = key
        self.site_key = site_key
        self.url = url
        self.session = None

    async def _init_session(self) -> None:
        if self.session is None:
            self.session = aiohttp.ClientSession(raise_for_status=True)

    async def close(self) -> None:
        if self.session:
            await self.session.close()

    async def _create_job(self) -> RuCaptchaV2Result:
        await self._init_session()
        data = RuCaptchaV2JobRequest(
            key=self.key,
            googlekey=self.site_key,
            pageurl=self.url,
            method="userrecaptcha",
            json=1,
        )
        async with self.session.post(
            self.in_url, json=dataclasses.asdict(data)
        ) as response:
            resp_data = await response.json(content_type=None)
            if resp_data.get("status") == 1:
                return RuCaptchaV2OkResponse(request=resp_data.get("request"))
            else:
                return RuCaptchaV2ErrorResponse(
                    request=resp_data.get("request"),
                    error_text=resp_data.get("error_text"),
                )

    async def create_job(self, timeout=120) -> RuCaptchaV2Result:
        stop = datetime.now() + timedelta(seconds=timeout)
        while True:
            resp = await self._create_job()
            if resp.status == 1:
                return resp
            if datetime.now() > stop:
                return resp
            if resp.request == "ERROR_NO_SLOT_AVAILABLE":
                await asyncio.sleep(5)
                continue
            if resp.request == "ERROR_ZERO_BALANCE":
                await asyncio.sleep(60)
                continue
            if resp.request == "MAX_USER_TURN":
                await asyncio.sleep(10)
                continue
            return resp

    async def _get_result(self, id: str) -> RuCaptchaV2Result:
        await self._init_session()
        params = RuCaptchaV2ResultRequest(key=self.key, id=id, action="get", json=1)
        async with self.session.get(
            self.res_url, params=dataclasses.asdict(params)
        ) as response:
            resp_data = await response.json(content_type=None)
            if resp_data.get("status") == 1:
                return RuCaptchaV2OkResponse(request=resp_data.get("request"))
            else:
                return RuCaptchaV2ErrorResponse(
                    request=resp_data.get("request"),
                    error_text=resp_data.get("error_text"),
                )

    async def get_result(self, id: str, timeout=120) -> RuCaptchaV2Result:
        interval = 5
        stop = datetime.now() + timedelta(seconds=timeout)
        while True:
            resp = await self._get_result(id)
            if resp.status == 1:
                return resp
            if resp.request != "CAPCHA_NOT_READY" or datetime.now() > stop:
                return resp
            await asyncio.sleep(interval)

    async def solve(self, timeout=120) -> RuCaptchaV2Result:
        resp = await self.create_job(timeout=timeout)
        if resp.status != 1:
            return resp
        await asyncio.sleep(15)
        return await self.get_result(resp.request, timeout=timeout)

    async def send_report(self, id: str, is_valid=True):
        await self._init_session()
        params = RuCaptchaV2ResultRequest(
            key=self.key,
            id=id,
            action="reportgood" if is_valid else "reportbad",
            json=1,
        )
        async with self.session.get(
            self.res_url, params=dataclasses.asdict(params)
        ) as response:
            await response.json(content_type=None)
