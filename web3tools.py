#!/usr/bin/env python3

import logging
import asyncio
import functools
import eth_utils
import aiohttp
import aiohttp_rpc
from datetime import datetime, timedelta
from operator import attrgetter
from typing import List, Optional
from aiohttp_rpc.protocol import JsonRpcRequest, JsonRpcBatchRequest
from hexbytes import HexBytes
from web3.auto import Web3
from web3.types import TxParams, TxReceipt, BlockData, SignedTx

log = logging.getLogger(__name__)


def run_in_executor(f):
    @functools.wraps(f)
    def inner(*args, **kwargs):
        loop = asyncio.get_running_loop()
        return loop.run_in_executor(None, functools.partial(f, *args, **kwargs))

    return inner


class JsonRpcErrorList(Exception):
    def __init__(self, errs):
        super().__init__(errs)
        self.errors = errs


class Web3Client:
    http_addr: str
    w3: Web3
    seed: str
    errors: float = 0
    clients: List["Web3Client"]
    timeout = aiohttp.ClientTimeout(total=10, sock_connect=10, sock_read=10, connect=10)

    def __init__(self, http_addr: str, seed=None) -> None:
        self.http_addr = http_addr
        if self.http_addr:
            self.w3 = Web3(Web3.HTTPProvider(self.http_addr))
            self.w3.eth.account.enable_unaudited_hdwallet_features()
        if seed:
            self.seed = seed
        self.session = None
        self.rpc = None
        self.clients = []

    async def _init_rpc(self) -> None:
        if self.session is None:
            self.session = aiohttp.ClientSession(
                raise_for_status=True, timeout=self.timeout
            )
        if self.rpc is None:
            self.rpc = aiohttp_rpc.JsonRpcClient(self.http_addr, session=self.session, timeout=self.timeout)
            self.rpc.session = self.session
            self.rpc._session_is_outer = True

    async def close(self) -> None:
        if self.rpc:
            await self.rpc.disconnect()
        if self.session and not self.session.closed:
            await self.session.close()
        pending_clients = [x for x in self.clients if x.session and not x.session.closed]
        for client in pending_clients:
            await client.close()

    @classmethod
    def init_balanced(cls, endpoints, seed=None):
        batch = []
        for endpoint in endpoints:
            client = Web3Client(http_addr=endpoint, seed=seed)
            client.clients = batch
            batch.append(client)
        return batch[0]

    def balanced(self):
        sorted_list = sorted(self.clients, key=attrgetter("errors"))
        new_client = sorted_list[0]
        return new_client

    def from_mnemonic(self, seed=None, account_path=None, acct_n=0, n=0):
        seed = seed or self.seed
        if not seed:
            raise ValueError("No seed")
        if account_path:
            return self.w3.eth.account.from_mnemonic(seed, account_path)
        else:
            return self.w3.eth.account.from_mnemonic(
                seed, account_path=f"m/44'/60'/{acct_n}'/0/{n}"
            )

    async def get_nonce(self, addr: str, state="latest") -> int:
        await self._init_rpc()
        result = await self.rpc.eth_getTransactionCount(addr, state)
        return eth_utils.to_int(hexstr=result)

    async def get_balance(self, addr: str, state="latest") -> int:
        await self._init_rpc()
        result = await self.rpc.eth_getBalance(addr, state)
        return eth_utils.to_int(hexstr=result)

    async def estimate_gas(self, params: TxParams) -> int:
        await self._init_rpc()
        result = await self.rpc.eth_estimateGas(params)
        return eth_utils.to_int(hexstr=result)

    async def get_gas_price(self) -> int:
        await self._init_rpc()
        result = await self.rpc.eth_gasPrice()
        return eth_utils.to_int(hexstr=result)

    def sign_transaction(self, tx: TxParams, key: str) -> SignedTx:
        return self.w3.eth.account.sign_transaction(tx, key)

    async def send_raw_transaction(self, params: bytes) -> HexBytes:
        await self._init_rpc()
        request = JsonRpcRequest(
            id=aiohttp_rpc.utils.get_random_id(),
            method_name="eth_sendRawTransaction",
            args=[params.hex()],
        )
        request.params = [request.params]
        response = await self.rpc.direct_call(request)
        if response.error is not None:
            raise response.error

        return eth_utils.to_hex(hexstr=response.result)

    async def send_raw_transactions(self, txs: List[bytes]) -> List[HexBytes]:
        await self._init_rpc()
        batch_request = JsonRpcBatchRequest(requests=[])
        for tx in txs:
            request = JsonRpcRequest(
                id=aiohttp_rpc.utils.get_random_id(),
                method_name="eth_sendRawTransaction",
                args=[tx.hex()],
            )
            request.params = [request.params]
            batch_request.requests.append(request)

        result = await self.rpc.direct_batch(batch_request)

        errors = [x.error for x in result.responses if x.error]
        if errors:
            raise JsonRpcErrorList(errors)

        return [eth_utils.to_hex(hexstr=x.result) for x in result.responses]

    async def get_transaction_receipt(self, tx_hash: str) -> TxReceipt:
        await self._init_rpc()
        request = JsonRpcRequest(
            id=aiohttp_rpc.utils.get_random_id(),
            method_name="eth_getTransactionReceipt",
            args=[tx_hash],
        )
        request.params = [request.params]
        response = await self.rpc.direct_call(request)
        if response.error is not None:
            raise response.error

        if not response.result:
            return None

        return TxReceipt(response.result)

    async def wait_for_transaction_receipt(
            self, tx_hash: str, interval=0.1, timeout=120
    ) -> Optional[TxReceipt]:
        result = None
        deadline = datetime.now() + timedelta(seconds=timeout)
        while not result:
            result = await self.get_transaction_receipt(tx_hash)
            if result:
                return result
            if datetime.now() + timedelta(seconds=interval) > deadline:
                return None
            await asyncio.sleep(interval)

    async def get_block_by_number(self, qty="latest", full=False) -> BlockData:
        await self._init_rpc()
        result = await self.rpc.eth_getBlockByNumber(qty, full)
        return BlockData(result)
