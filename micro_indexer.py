#!/usr/bin/env python3

import json
import os
import logging
from time import sleep
from web3 import Web3
from web3.types import TxParams
from web3.middleware import geth_poa_middleware
from web3.contract import ContractEvent


logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel("INFO")

SEED = os.environ["SEED"]
RPC_ADDR = "http://localhost:8545/"


w3 = Web3(Web3.HTTPProvider(RPC_ADDR))
# w3.eth.account.enable_unaudited_hdwallet_features()
# account = w3.eth.account.from_mnemonic(SEED, account_path="m/44'/60'/0'/0/0")

contracts = {
    "penis_coin": {
        "address": "0x3Dda4dB649A204409E00e68358413ab10ef13cC7",
        "abi_filename": "contracts/PenisCoin_abi.json",
        "method_name": "approve",
    },
    "A": {
        "address": "0x4c80b48B47e3D88f42C37E6cBc890148284C25d6",
        "abi_filename": "contracts/A_abi.json",
        "method_name": "a",
    },
    "B": {
        "address": "0xb0e337b5CA3789a21656b0B52D7bF86b9298fc36",
        "abi_filename": "contracts/B_abi.json",
        "method_name": "b",
    },
    "C": {
        "address": "0x2d7368714a108fbF7ec18582005e29DBAC93A54A",
        "abi_filename": "contracts/C_abi.json",
        "method_name": "c",
    },
    "Echo": {
        "address": "0xBa6C36b96d328d092e4207cc8c04E56B63C7ec52",
        "abi_filename": "contracts/Echo_abi.json",
        "method_name": "echo",
    },
}
for name in contracts.keys():
    with open(contracts[name]["abi_filename"]) as abi_file:
        abi = json.load(abi_file)
    address = contracts[name]["address"]
    contracts[name].update({"abi": abi, "contract": w3.eth.contract(address)})
    contracts[name]["contract"] = w3.eth.contract(address=address, abi=abi)

counters = {k: 0 for k in contracts.keys()}
# counters = {'penis_coin': 2695288, 'A': 545238, 'B': 554728, 'C': 45036, 'Echo': 1803418}

init_block_number = 0
# init_block_number = 207584
latest_block_number = w3.eth.get_block_number()


def process_block(i):
    log.info(f"Block {i}")
    block = w3.eth.get_block(i, full_transactions=True)
    txs = block["transactions"]
    for tx in txs:
        for contract_name, meta in contracts.items():
            if tx["to"] == meta["address"]:
                counters[contract_name] += 1
    print(counters)

for i in range(init_block_number, latest_block_number):
    process_block(i)

while True:
    new_block_number = w3.eth.get_block_number()
    if new_block_number == latest_block_number:
        sleep(1)
        continue
    latest_block_number = new_block_number
    process_block(latest_block_number)
