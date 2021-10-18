#!/usr/bin/env python3

import logging
import os
from time import sleep
from time import sleep
from web3 import Web3
from web3.exceptions import InvalidAddress
from eth_account import Account

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel("INFO")

SEED = os.environ["SEED"]

rpc_addr = "http://localhost:8545/"
rpc_addr = "https://cassini.crypto.org:8545/"
rpc_addr = "http://18.141.166.179:8545/"
rpc_addr = "http://138.197.110.129:8545/"
https_provider = Web3.HTTPProvider(rpc_addr)

w3 = Web3(https_provider)
w3.eth.account.enable_unaudited_hdwallet_features()


def print_balance(acct, balance, i=0):
    print(str(i).zfill(2), acct.address, w3.fromWei(balance, "ether"))


def get_acct(num=0, acct_num=0):
    return w3.eth.account.from_mnemonic(
        SEED, account_path="m/44'/60'/{}'/0/{}".format(acct_num, num)
    )


def send(donor, to_addr, value):
    log.info(
        "Sending {} from {} to {}".format(
            w3.fromWei(value, "ether"), donor.address, to_addr
        )
    )
    payload = {
        "to": to_addr,
        "value": value,
        "nonce": w3.eth.get_transaction_count(donor.address),
        "gas": 21000,
        "gasPrice": w3.toWei(5000, "gwei"),
    }
    signed_tx = w3.eth.account.sign_transaction(payload, donor.privateKey)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)


targets = [get_acct(num=x) for x in [0, 1, 2, 3, 4, 5, 6]]
min_balance = w3.toWei(0.3, "ether")


for i in range(0, 0):
    acct = get_acct(num=i, acct_num=1634372040)
    balance = w3.eth.get_balance(acct.address)
    print_balance(acct, balance, i)
    value = balance - min_balance
    if balance + value < min_balance:
        sleep(0.1)
        continue

    print("=" * 80)
    target = targets[0]
    tb_min = float("+Inf")
    for j, t in enumerate(targets):
        b = w3.eth.get_balance(t.address)
        print_balance(t, b, j)
        if b < tb_min:
            tb_min = b
            target = t
    print("=" * 80)

    send(acct, target.address, value)
