#!/usr/bin/env python3

import asyncio
import json
import logging
import os
import math
import eth_utils
import aiohttp
import subprocess
import random
from aiohttp import (
    ClientOSError,
    ClientSSLError,
    ClientConnectionError,
    ClientConnectorSSLError,
)
from datetime import datetime, timedelta
from aiohttp_rpc.errors import JsonRpcError
from web3 import Web3
from web3.types import TxParams
from web3tools import Web3Client, JsonRpcErrorList
from prometheus_client.parser import text_string_to_metric_families

# debug web3 requests
# from http.client import HTTPConnection
# HTTPConnection.debuglevel = 1

# debug aiohttp requests
# import aiohttp
# async def on_request_chunk_sent(session, trace_config_ctx, params):
#     print("Starting request")
#     print(params)
# trace_config = aiohttp.TraceConfig()
# trace_config.on_request_chunk_sent.append(on_request_chunk_sent)

net_errors = (
    ClientOSError,
    ClientSSLError,
    ClientConnectionError,
    ClientConnectorSSLError,
    asyncio.TimeoutError,
)

# fix aiohttp_rpc bug
JsonRpcError.message = ">_<"

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
    level=logging.INFO,
    datefmt="%d %H:%M:%S",
)
log = logging.getLogger(__name__)

SEED = os.environ["SEED"]
ACCN = int(os.environ.get("N", 0))
PUBLIC_RPC = os.environ.get("PUBLIC_RPC", False)

RPC_ADDRS = [
    "http://localhost:8545/",
    "https://cassini.crypto.org:8545/",
    # "http://138.197.110.129:8545/", # syncing
    # "http://144.91.78.195:8545/", # connection error
    "http://164.68.102.64:8545/",
    "http://164.68.114.113:8545/",
    "http://164.68.117.58:8545/",
    "http://18.141.166.179:8545/",
    "http://188.165.217.174:8545/",
    "http://194.163.182.24:8545/",
    "http://46.21.255.58:8545/",
    "http://49.12.224.41:8545/",
    "http://95.217.17.145:8545/",
]
random.shuffle(RPC_ADDRS)


def get_contract(w3c: Web3Client):
    penis_addr = "0x3Dda4dB649A204409E00e68358413ab10ef13cC7"
    with open("contracts/PenisCoin_abi.json") as abi_file:
        penis_abi = json.load(abi_file)
    return w3c.w3.eth.contract(address=penis_addr, abi=penis_abi), penis_addr


async def get_metrics(w3c: Web3Client):
    data = {
        "tendermint_mempool_failed_txs_total": 0,
        "tendermint_mempool_size": 0,
    }
    parts = w3c.http_addr.split(":")
    url = ":".join([parts[0], parts[1], "26657/unconfirmed_txs"])
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            json = await resp.json()
            data["tendermint_mempool_size"] = int(
                json.get("result", {}).get("total", 0)
            )

    # async with aiohttp.ClientSession() as session:
    #     async with session.post("http://localhost:26660/") as resp:
    #         metrics = await resp.text()
    #         for family in text_string_to_metric_families(metrics):
    #             for sample in family.samples:
    #                 if sample.name in data.keys():
    #                     data[sample.name] = sample.value
    return data


async def balance_printer(w3c: Web3Client, addr):
    log = logging.getLogger(asyncio.current_task().get_name())
    log.debug("Started")
    while True:
        try:
            balance = await w3c.balanced().get_balance(addr)
            log.info("Balance is {} ethers".format(Web3.fromWei(balance, "ether")))
        except Exception as e:
            log.error(e)
        await asyncio.sleep(60)


async def address_provider(w3c: Web3Client, q: asyncio.Queue):
    log = logging.getLogger(asyncio.current_task().get_name())
    log.debug("Started")
    url_base = "https://raw.githubusercontent.com/crypto-org-chain/cassini/main"

    async def do_line(b: bytes):
        addr = b.decode("utf-8").strip()
        if w3c.w3.isChecksumAddress(addr):
            await q.put(addr)

    while True:
        try:
            async with aiohttp.ClientSession(raise_for_status=True) as session:
                async with session.get(f"{url_base}/builderList.csv") as response:
                    log.info("Feeding addresses from builders list")
                    async for line in response.content:
                        await do_line(line)
                async with session.get(f"{url_base}/testerList.csv") as response:
                    log.info("Feeding addresses from testers list")
                    async for line in response.content:
                        await do_line(line)
        except Exception as e:
            log.error(e)


async def block_provider(w3c: Web3Client, queue, interval=0.3):
    log = logging.getLogger(asyncio.current_task().get_name())
    log.debug("Started")
    block_number = 0
    last_block_time = datetime.now()
    min_block_period = timedelta(seconds=5.5)
    w3cb = w3c.balanced()
    old_http = w3cb.balanced()
    while True:
        await asyncio.sleep(interval)
        w3cb = w3cb.balanced()
        if old_http != w3cb.http_addr:
            log.info(f"RPC endpoint changed: {w3cb.http_addr}")
            old_http = w3cb.http_addr
        try:
            new_block = await w3cb.get_block_by_number(qty="pending")
            new_number = eth_utils.to_int(hexstr=new_block["number"])
            last_block_time = datetime.fromtimestamp(
                eth_utils.to_int(hexstr=new_block["timestamp"])
            )
            if block_number - new_number > 3:
                log.warning(
                    f"Current block {new_number} less then {block_number} - bad node"
                )
                w3cb.errors += 10
                block_number = new_number
                continue
            if block_number >= new_number:
                continue
            log.info(f"New block number {new_number} at {last_block_time.isoformat()}")
            block_number = new_number
            if not queue.full():
                await queue.put(block_number)
            await asyncio.sleep(
                (min_block_period / 2).total_seconds()
            )  # less then block time
        except net_errors as e:
            log.error(e)
            w3cb.errors += 1
            log.error([f"{x.http_addr} {x.errors}" for x in w3cb.clients])
            await asyncio.sleep(1)
        except Exception as e:
            log.error(e)


async def txs_sender(
    w3c: Web3Client,
    account,
    tx_hash_q: asyncio.Queue,
):
    log = logging.getLogger(asyncio.current_task().get_name())
    log.debug("Started")

    err_counter = 0
    target_pending_receipts = 100
    batch_size = 10
    max_batch_size = 50

    async def get_nonce(w3c):
        pending_nonce = await w3c.get_nonce(account.address, state="pending")
        latest_nonce = await w3c.get_nonce(account.address, state="latest")
        nonce = max(pending_nonce, latest_nonce)
        return nonce, pending_nonce, latest_nonce

    penis_contract, penis_addr = get_contract(w3c)
    # method = penis_contract.functions.transfer(account.address,Web3.toWei(1, "ether"))
    method = penis_contract.functions.approve(account.address, Web3.toWei(1, "ether"))
    # gas_price = await w3c.get_gas_price()
    proto_tx = TxParams(
        {
            "chainId": eth_utils.to_hex(339),
            "from": account.address,
            "to": penis_addr,
            "data": method._encode_transaction_data(),
            "gasPrice": eth_utils.to_hex(Web3.toWei(5100, "gwei")),
            "gas": eth_utils.to_hex(Web3.toWei(100000, "gwei")),
            "value": eth_utils.to_hex(0),
        }
    )
    proto_tx["gas"] = eth_utils.to_hex(await w3c.estimate_gas(proto_tx))

    nonce = None
    old_http = w3c.http_addr
    w3cb = w3c.balanced()
    while True:
        try:
            # take new client
            w3cb = w3c.balanced()
            if old_http != w3cb.http_addr:
                log.info(f"RPC endpoint changed: {w3cb.http_addr}")
                old_http = w3cb.http_addr

            pending_receipts = tx_hash_q.qsize()
            if pending_receipts > target_pending_receipts:
                await asyncio.sleep(1)
                continue

            if nonce is None:
                nonce, _, _ = await get_nonce(w3c)
                log.info(f"New nonce is {nonce}")

            signed_txs = []
            log.info(f"Sending batch of {batch_size} txs")
            for _ in range(batch_size):
                tx = proto_tx.copy()
                # method = penis_contract.functions.transfer(target_addr, Web3.toWei(0.1, "ether"))
                # tx["data"] = method._encode_transaction_data()
                tx["nonce"] = eth_utils.to_hex(nonce)
                nonce += 1
                signed_tx = w3cb.sign_transaction(tx, account.privateKey)
                signed_txs.append(signed_tx)
            tx_hashes = await w3cb.send_raw_transactions(
                [x.rawTransaction for x in signed_txs]
            )
            log.info(
                f"Sent batch of {len(tx_hashes)} txs with nonce {nonce}-{nonce+len(tx_hashes)}"
            )
            for tx_hash in tx_hashes:
                await tx_hash_q.put(tx_hash)

            err_counter = 0
            w3cb.errors -= 0.1
            batch_size += 1
            target_pending_receipts += 10
            await asyncio.sleep(0.3)

        except net_errors as e:
            w3cb.errors += 1
            log.error([f"{x.http_addr} {x.errors}" for x in w3cb.clients])
            log.error(e)
            target_pending_receipts -= 1
            await asyncio.sleep(1)

        except (JsonRpcErrorList, JsonRpcError) as e:
            log.error(f"Transaction sending error: {e}")
            w3cb.errors += 1
            batch_size -= 1
            target_pending_receipts -= 1
            log.error([f"{x.http_addr} {x.errors}" for x in w3cb.clients])
            err_counter += 1
            await asyncio.sleep(1)
            nonce = None

        except Exception as e:
            print(type(e))
            print(e)
            log.error(e)

        finally:
            batch_size = max(batch_size, 1)
            batch_size = min(batch_size, max_batch_size)
            target_pending_receipts = max(target_pending_receipts, 10)
            target_pending_receipts = min(target_pending_receipts, tx_hash_q.maxsize)


async def receipt_eater(w3c: Web3Client, tx_q: asyncio.Queue, interval=1):
    log = logging.getLogger(asyncio.current_task().get_name())
    log.debug("Started")
    old_http = w3c.http_addr
    while True:
        tx_hash = await tx_q.get()
        log.debug(f"Processing {tx_hash}")

        # take new client
        w3cb = w3c.balanced()
        if old_http != w3cb.http_addr:
            log.info(f"RPC endpoint changed: {w3cb.http_addr}")
            old_http = w3cb.http_addr

        try:
            await w3cb.wait_for_transaction_receipt(
                tx_hash, interval=interval, timeout=30
            )
        except net_errors as e:
            w3cb.errors += 1
            log.error(e)
            await asyncio.sleep(1)
        except Exception as e:
            print(type(e))
            print(e)
            log.error(e)
        finally:
            tx_q.task_done()


async def receipt_queue_size_printer(q: asyncio.Queue, interval=10):
    log = logging.getLogger(asyncio.current_task().get_name())
    log.debug("Started")
    while True:
        log.info(f"Pending receipts: {q.qsize()}")
        await asyncio.sleep(interval)


async def main():
    w3c = Web3Client.init_balanced(endpoints=RPC_ADDRS, seed=SEED)
    account = w3c.from_mnemonic(n=ACCN)
    print(account.address)

    # address_q = asyncio.Queue(maxsize=100)
    block_number_q = asyncio.Queue(maxsize=1)
    tx_hash_q = asyncio.Queue(maxsize=1000)
    asyncio.create_task(balance_printer(w3c, account.address), name="balance_printer")
    # asyncio.create_task(address_provider(w3c, address_q))
    asyncio.create_task(
        block_provider(w3c, block_number_q, interval=1), name="block_provider"
    )
    asyncio.create_task(txs_sender(w3c, account, tx_hash_q), name="txs_sender")
    asyncio.create_task(receipt_queue_size_printer(tx_hash_q), name="receipts_queue")
    for i in range(20):
        asyncio.create_task(receipt_eater(w3c, tx_hash_q), name=f"receipt_eater-{i}")
    try:
        await asyncio.sleep(float("inf"))
    finally:
        await w3c.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
