#!/usr/bin/env python3

import asyncio
import logging
import os
import aiohttp
from datetime import datetime, timedelta
from web3 import Web3
from web3.types import TxParams
from web3tools import Web3Client
from rucaptcha import RuCaptchaV2

SEED = os.environ["SEED"]
RPC_ADDR = "https://cassini.crypto.org:8545/"
FAUCET_API_URL = os.environ["FAUCET_API_URL"]
FAUCET_SITE_URL = os.environ["FAUCET_SITE_URL"]
FAUCET_SITE_KEY = os.environ["FAUCET_SITE_KEY"]
RUCAPTCHA_API_KEY = os.environ["RUCAPTCHA_API_KEY"]

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
    level=logging.INFO,
    datefmt="%d %H:%M:%S",
)
log = logging.getLogger(__name__)


async def account_generator(w3c: Web3Client, acct_q: asyncio.Queue):
    log = logging.getLogger("account_generator")
    log.debug("Started")
    n = 0
    ts = int(datetime.now().timestamp())
    while True:
        account = w3c.from_mnemonic(n=n, acct_n=ts)
        await acct_q.put(account)
        log.info(f"New account {ts}/{n} - {account.address}")
        n += 1


async def captcha_requester(name: str, rc: RuCaptchaV2, q: asyncio.Queue):
    log = logging.getLogger(name)
    log.debug("Started")
    while True:
        try:
            in_resp = await rc.create_job()
            if in_resp.status == 0:
                log.error(f"Captcha solve error: {in_resp.request}")
                continue
            await asyncio.sleep(15)
            res_resp = await rc.get_result(in_resp.request)
            log.info(f"Captcha {in_resp.request} solved!")
            await q.put((in_resp.request, res_resp.request))
        except Exception as e:
            log.error(e)


async def faucet_poster(
    name: str,
    captcha_q: asyncio.Queue,
    good_c_q: asyncio.Queue,
    bad_c_q: asyncio.Queue,
    acct_q: asyncio.Queue,
    donors_q: asyncio.Queue,
):
    log = logging.getLogger(name)
    log.debug("Started")
    headers = {
        "authority": "cronos.crypto.org",
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded;charset=UTF-8",
        "origin": "https://cronos.crypto.org",
        "referer": FAUCET_SITE_URL,
    }
    async with aiohttp.ClientSession() as session:
        while True:
            account = await acct_q.get()
            captcha_id, captcha_code = await captcha_q.get()
            data = {"address": account.address, "response": captcha_code}
            try:
                async with session.post(
                    FAUCET_API_URL, headers=headers, data=data
                ) as resp:
                    if resp.status == 400:
                        log.warning(
                            f"Captcha is good but to early for address {account.address}"
                        )
                        await good_c_q.put(captcha_id)
                    elif resp.status == 401:
                        log.warning(
                            f"Bad captcha {captcha_id} for address {account.address}"
                        )
                        await bad_c_q.put(captcha_id)
                    elif resp.status == 504:
                        log.warning(
                            f"Faucet gateway timeout for address {account.address}"
                        )
                        # await donors_q.put(account) # may be OK?
                        await asyncio.sleep(60)  # back pressure
                    elif resp.status < 300:
                        log.info(f"Successfully submited for address {account.address}")
                        await good_c_q.put(captcha_id)
                        await donors_q.put(account)
                    else:
                        raise RuntimeError(
                            f"Faucet response with unknown status {resp.status}"
                        )
            except Exception as e:
                log.error(e)
            acct_q.task_done()
            captcha_q.task_done()


async def good_captcha_report(name, rc: RuCaptchaV2, q: asyncio.Queue):
    log = logging.getLogger(name)
    log.debug("Started")
    while True:
        captcha_id = await q.get()
        try:
            await rc.send_report(captcha_id, is_valid=True)
            log.info(f"Good captcha {captcha_id} reported")
        except Exception as e:
            log.error(e)
        q.task_done()


async def bad_captcha_report(name, rc: RuCaptchaV2, q: asyncio.Queue):
    log = logging.getLogger(name)
    log.debug("Started")
    while True:
        captcha_id = await q.get()
        try:
            await rc.send_report(captcha_id, is_valid=False)
            log.info(f"Bad captcha {captcha_id} reported")
        except Exception as e:
            log.error(e)
        q.task_done()


async def balance_accumulator(
    name: str, w3c: Web3Client, addr: str, q: asyncio.Queue, timeout=600
):
    log = logging.getLogger(name)
    log.debug("Started")
    min_balance = Web3.toWei(0.3, "ether")
    stop = datetime.now() + timedelta(seconds=timeout)
    while True:
        acct = await q.get()
        try:
            balance = 0
            while balance <= min_balance:
                if datetime.now() > stop:
                    log.warning(
                        f"Address {acct.address} was timed out with small balance"
                    )
                    break
                balance = await w3c.get_balance(acct.address)
                log.debug(f"Balance of {acct.address} is {balance}")
                if balance <= min_balance:
                    await asyncio.sleep(30)
            if balance <= min_balance:
                q.task_done()
                continue

            value = balance - min_balance
            log.info(
                f"Sending {Web3.fromWei(value, 'ether')} from {acct.address} to {addr}"
            )
            tx = TxParams(
                {
                    "to": addr,
                    "value": value,
                    "nonce": await w3c.get_nonce(acct.address),
                    "gas": 21000,
                    "gasPrice": Web3.toWei(5000, "gwei"),
                }
            )
            signed_tx = w3c.sign_transaction(tx, acct.privateKey)
            await w3c.send_raw_transaction(signed_tx.rawTransaction)
        except Exception as e:
            log.error(e)
        q.task_done()


async def main():
    w3c = Web3Client(http_addr=RPC_ADDR, seed=SEED)
    rc = RuCaptchaV2(
        key=RUCAPTCHA_API_KEY, site_key=FAUCET_SITE_KEY, url=FAUCET_SITE_URL
    )
    target_addr = w3c.from_mnemonic(n=0).address

    work_fact = 10
    acct_q = asyncio.Queue(maxsize=work_fact)
    captcha_q = asyncio.Queue(maxsize=work_fact)
    good_captcha_q = asyncio.Queue()
    bad_captcha_q = asyncio.Queue()
    donors_q = asyncio.Queue(maxsize=work_fact)

    asyncio.create_task(account_generator(w3c, acct_q)),
    for i in range(2):
        asyncio.create_task(
            good_captcha_report(f"good_captcha_reporter-{i}", rc, good_captcha_q)
        )
        asyncio.create_task(
            bad_captcha_report(f"bad_captcha_reporter-{i}", rc, bad_captcha_q)
        )
    for i in range(work_fact):
        asyncio.create_task(captcha_requester(f"captcha_requester-{i}", rc, captcha_q))
        asyncio.create_task(
            faucet_poster(
                f"faucet_poster-{i}",
                captcha_q,
                good_captcha_q,
                bad_captcha_q,
                acct_q,
                donors_q,
            )
        )
    for i in range(work_fact * 5):
        asyncio.create_task(
            balance_accumulator(f"balance_accumulator-{i}", w3c, target_addr, donors_q)
        )

    try:
        await asyncio.sleep(float("inf"))
    finally:
        await rc.close()
        await w3c.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
