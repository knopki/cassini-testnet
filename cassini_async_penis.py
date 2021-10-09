#!/usr/bin/env python3

import asyncio
import json
import logging
import os
import eth_utils
from aiohttp_rpc.errors import JsonRpcError
from web3 import Web3
from web3.types import TxParams
from web3tools import Web3Client

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


# fix aiohttp_rpc bug
JsonRpcError.message = ">_<"

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
    level=logging.INFO,
    datefmt="%d %H:%M:%S",
)
log = logging.getLogger(__name__)

SEED = os.environ["SEED"]

rpc_addr = "https://cassini.crypto.org:8545/"


async def balance_printer(w3c: Web3Client, addr):
    log = logging.getLogger("balance_printer")
    log.debug("Started")
    while True:
        balance = await w3c.get_balance(addr)
        log.info("Balance is {} ethers".format(Web3.fromWei(balance, "ether")))
        await asyncio.sleep(60)


async def cro_collector(
    w3c: Web3Client,
    addr,
    amount=100,
    min_balance=Web3.toWei(0.5, "ether"),
    interval=600,
):
    log = logging.getLogger("cro_collector")
    log.debug("Started")
    accounts = []
    for i in range(amount):
        account = w3c.from_mnemonic(i)
        log.debug(f"New donor {account.address}")
        accounts.append(account)
    while True:
        for acct in accounts:
            if acct.address == addr:
                continue
            try:
                balance = await w3c.get_balance(acct.address)
                log.debug(
                    f"Balance of {acct.address} is {Web3.fromWei(balance, 'ether')} ethers"
                )
                if balance < min_balance:
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
        await asyncio.sleep(interval)


async def block_provider(w3c: Web3Client, queue, interval=0.1):
    log = logging.getLogger("block_provider")
    log.debug("Started")
    block_number = 0
    while True:
        await asyncio.sleep(interval)
        try:
            new_block = await w3c.get_block_by_number()
            new_number = eth_utils.to_int(hexstr=new_block["number"])
            if block_number >= new_number:
                continue
            log.info(f"New block number {new_number}")
            block_number = new_number
            if not queue.full():
                await queue.put(block_number)
            await asyncio.sleep(4.5)  # less then block time
        except Exception as e:
            log.error(e)


async def txs_sender(
    w3c: Web3Client, account, block_q: asyncio.Queue, proto_tx: TxParams, batch_size=1
):
    log = logging.getLogger("txs_sender")
    log.debug("Started")
    while True:
        try:
            await block_q.get()
            block_q.task_done()
            nonce = await w3c.get_nonce(account.address, state="pending")
            ns = list(range(nonce, nonce + batch_size))
            signed_txs = []
            for n in ns:
                tx = proto_tx.copy()
                tx["nonce"] = eth_utils.to_hex(n)
                signed_tx = w3c.sign_transaction(tx, account.privateKey)
                signed_txs.append(signed_tx)

            tx_hashes = await w3c.send_raw_transactions(
                [x.rawTransaction for x in signed_txs]
            )
            for idx, tx_hash in enumerate(tx_hashes):
                log.info(f"Sent tx#{nonce+idx}#{tx_hash}")
        except Exception as e:
            log.error(e)


async def main():
    w3c = Web3Client(http_addr=rpc_addr, seed=SEED)
    account = w3c.from_mnemonic(0)
    penis_addr = "0x3Dda4dB649A204409E00e68358413ab10ef13cC7"
    with open("contracts/PenisCoin_abi.json") as abi_file:
        penis_abi = json.load(abi_file)
    penis_contract = w3c.w3.eth.contract(address=penis_addr, abi=penis_abi)
    method = penis_contract.functions.transfer(account.address, 1)
    proto_tx = TxParams(
        {
            "from": account.address,
            "to": penis_addr,
            "data": method._encode_transaction_data(),
            "gasPrice": eth_utils.to_hex(Web3.toWei(5000, "gwei")),
        }
    )
    gas = await w3c.estimate_gas(proto_tx)
    proto_tx["gas"] = eth_utils.to_hex(gas)

    block_number_q = asyncio.Queue(maxsize=1)
    tasks = [
        asyncio.create_task(balance_printer(w3c, account.address)),
        asyncio.create_task(cro_collector(w3c, account.address)),
        asyncio.create_task(block_provider(w3c, block_number_q)),
        asyncio.create_task(
            txs_sender(w3c, account, block_number_q, proto_tx, batch_size=5)
        ),
    ]

    while True:
        await asyncio.sleep(1)


asyncio.run(main())
