"""Round-trip a disposable tdc-vanity export through pinned Tidecoin Core wallets."""

import argparse
from contextlib import contextmanager
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile


CORE_REVISION = "ffed4e92e60ff2de30361648a71cba64531f9077"
CORE_VERSION = "v1.0.0rc3"
# src/kernel/chainparams.cpp at CORE_REVISION.
MAINNET_WIF = 125
MAINNET_P2SH = 65
REGTEST_WIF = 15
REGTEST_P2SH = 122
FALCON_SECRET_BYTES = 1281
FALCON_PUBLIC_BYTES = 897
COINBASE_MATURITY = 100
WALLET = "recovery"
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
STAGES = (
    "Local miner export and script bytes",
    "Core executable and version checks",
    "Mainnet address and wrapped script",
    "Regtest address, wrapped script and private import",
    "Regtest funding and coinbase maturity",
    "Regtest node restart and wallet reload",
    "Regtest wallet signing",
    "Regtest mempool and block acceptance",
)


class CheckFailed(Exception):
    pass


class MissingPrerequisite(CheckFailed):
    pass


def require(condition, message):
    if not condition:
        raise CheckFailed(message)


@contextmanager
def stage(results, name):
    results[name] = "FAIL"
    try:
        yield
    except MissingPrerequisite:
        results[name] = "BLOCKED"
        raise
    results[name] = "PASS"


def capture(argv, description, *, data="", timeout=30):
    # Core errors (including successful RPC replies with per-item errors) can
    # echo descriptors. Keep both child streams away from the terminal.
    try:
        reply = subprocess.run(
            argv, input=data, text=True, encoding="utf-8",
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise CheckFailed(f"{description} timed out") from None
    except OSError:
        raise CheckFailed(f"{description} could not be started") from None
    require(reply.returncode == 0, f"{description} failed (exit {reply.returncode})")
    return reply.stdout.strip()


def core_binary(command, kind, option):
    path = shutil.which(command)
    if path is None:
        raise MissingPrerequisite(f"Missing {kind} executable for {CORE_VERSION} ({option})")
    path = str(Path(path).resolve())
    lines = capture([path, "-version"], f"{kind} version check").splitlines()
    if not lines or lines[0] != f"Tidecoin {kind} version {CORE_VERSION}":
        raise MissingPrerequisite(f"{kind} must be from the pinned {CORE_VERSION} build ({option})")
    return path


class Node:
    def __init__(self, daemon, cli, datadir, chain):
        self.daemon = daemon
        self.cli = cli
        self.chain = chain
        self.options = ["-noconf", f"-datadir={datadir}", f"-chain={chain}"]
        self.process = None
        self.port = None
        datadir.mkdir(mode=0o700)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def start(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", 0))
                self.port = sock.getsockname()[1]
        except OSError:
            raise MissingPrerequisite("Cannot allocate a local IPv4 loopback RPC port") from None
        mode = ["-disablewallet=1"] if self.chain == "main" else ["-auxpowactivationheight=never"]
        self.process = subprocess.Popen(
            [
                self.daemon, *self.options, *mode,
                "-server=1", f"-rpcport={self.port}", "-rpcbind=127.0.0.1",
                "-rpcallowip=127.0.0.1", "-networkactive=0", "-listen=0",
                "-connect=0", "-dnsseed=0", "-fixedseeds=0",
                "-nodebuglogfile", "-printtoconsole=0",
            ],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        info = self.rpc("getblockchaininfo", wait=True)
        require(self.process.poll() is None, "Core exited during RPC startup")
        require(info["chain"] == self.chain, "Core selected the wrong chain")
        network = self.rpc("getnetworkinfo")
        require(network["networkactive"] is False and network["connections"] == 0,
                "Core P2P networking is active")

    def stop(self):
        self.rpc("stop", raw=True)
        try:
            status = self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            raise CheckFailed("Core did not shut down after stop") from None
        require(status == 0, "Core did not shut down cleanly")
        self.process = None

    def rpc(self, method, *args, wallet=None, raw=False, wait=False, timeout=30):
        cli = [
            self.cli, *self.options, "-rpcconnect=127.0.0.1", f"-rpcport={self.port}",
            f"-rpcclienttimeout={timeout}", "-stdin",
        ]
        if wait:
            cli.extend(("-rpcwait", "-rpcwaittimeout=20"))
        if wallet is not None:
            cli.append(f"-rpcwallet={wallet}")
        require(all("\n" not in arg and "\r" not in arg for arg in args),
                f"Core RPC {method} received a multiline argument")
        result = capture(
            [*cli, method], f"{self.chain} Core RPC {method}",
            data="".join(f"{arg}\n" for arg in args), timeout=timeout + 5,
        )
        return result if raw else json.loads(result, parse_float=Decimal)


def checksum(payload):
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def decode_base58check(value):
    number = 0
    for char in value:
        digit = BASE58.find(char)
        require(digit >= 0, "Export contains an invalid Base58 digit")
        number = number * 58 + digit
    leading_zeroes = len(value) - len(value.lstrip("1"))
    decoded = bytes(leading_zeroes) + number.to_bytes((number.bit_length() + 7) // 8, "big")
    payload, suffix = decoded[:-4], decoded[-4:]
    require(bool(payload) and checksum(payload) == suffix, "Export has an invalid WIF checksum")
    return payload


def encode_base58check(payload):
    encoded = payload + checksum(payload)
    number = int.from_bytes(encoded, "big")
    digits = []
    while number:
        number, digit = divmod(number, 58)
        digits.append(BASE58[digit])
    leading_zeroes = len(encoded) - len(encoded.lstrip(b"\x00"))
    return "1" * leading_zeroes + "".join(reversed(digits))


def hash160(value):
    try:
        return hashlib.new("ripemd160", hashlib.sha256(value).digest()).digest()
    except ValueError:
        raise MissingPrerequisite("Python hashlib needs RIPEMD-160 support") from None


def mine_export(miner, path):
    mined = capture(
        [str(miner.resolve()), "--workers=1", "--prefix=T", "--out", str(path)],
        "tdc-vanity", timeout=60,
    )
    address, _, wif = path.read_text(encoding="ascii").strip().partition(":")
    path.unlink()
    require(address == mined and address.startswith("T") and bool(wif),
            "Miner stdout and the legacy export disagree")
    payload = decode_base58check(wif)
    public_offset = 1 + FALCON_SECRET_BYTES + 1
    require(
        len(payload) == public_offset + FALCON_PUBLIC_BYTES
        and payload[:2] == bytes([MAINNET_WIF, 0x59])
        and payload[public_offset - 1:public_offset + 1] == b"\x01\x09",
        "Export does not contain the mainnet legacy Falcon-512 payload",
    )
    public_key = b"\x07" + payload[public_offset:]
    redeem_script = b"\x00\x14" + hash160(public_key)
    return address, wif, payload, public_key, redeem_script


def derive(node, descriptor):
    info = node.rpc("getdescriptorinfo", descriptor)
    require(info["hasprivatekeys"] and info["issolvable"] and not info["isrange"],
            "Core did not recognize a fixed, solvable private descriptor")
    addresses = node.rpc("deriveaddresses", info["descriptor"])
    require(len(addresses) == 1, "Core did not derive a single address")
    return addresses[0], info["checksum"]


def check_wrapped_script(node, address, redeem_script, output_script):
    wrapped = node.rpc("decodescript", redeem_script.hex())
    require(wrapped.get("p2sh") == address, "Core wrapped the redeem script to a different address")
    validated = node.rpc("validateaddress", address)
    require(validated.get("scriptPubKey") == output_script,
            "Core returned different scriptPubKey bytes")


def import_export(node, payload, script_hash, redeem_script, output_script):
    # Adapt only the WIF version and checksum. Preserve the full legacy payload,
    # including its embedded public key. Import the private input descriptor.
    wif = encode_base58check(bytes([REGTEST_WIF]) + payload[1:])
    private_descriptor = f"sh(wpkh({wif}))"
    address, input_checksum = derive(node, private_descriptor)
    require(address == encode_base58check(bytes([REGTEST_P2SH]) + script_hash),
            "Core derived a different regtest address for the same script hash")
    check_wrapped_script(node, address, redeem_script, output_script)

    node.rpc("createwallet", WALLET, "false", "true")
    request = json.dumps([{"desc": f"{private_descriptor}#{input_checksum}", "timestamp": "now"}])
    imported = node.rpc("importdescriptors", request, wallet=WALLET)
    require(len(imported) == 1 and imported[0]["success"] is True,
            "Wallet rejected the private descriptor import")
    info = node.rpc("getaddressinfo", address, wallet=WALLET)
    require(info["ismine"] and info["solvable"] and info.get("hex") == redeem_script.hex()
            and info["scriptPubKey"] == output_script,
            "Wallet did not recognize the imported wrapped script as its own")
    return address


def fund_script(node, address, output_script):
    count = COINBASE_MATURITY + 1
    blocks = node.rpc("generatetoaddress", str(count), address, timeout=180)
    require(len(blocks) == count, "Core did not mine enough blocks to mature the first coinbase")
    coinbase = node.rpc("getblock", blocks[0], "2")["tx"][0]
    outputs = [out for out in coinbase["vout"] if out["scriptPubKey"]["hex"] == output_script]
    require(len(outputs) == 1, "First coinbase did not pay the expected script exactly once")
    outpoint = {"txid": coinbase["txid"], "vout": outputs[0]["n"]}
    coin = node.rpc("gettxout", outpoint["txid"], str(outpoint["vout"]))
    require(coin is not None and coin["coinbase"] and coin["confirmations"] >= count
            and coin["scriptPubKey"]["hex"] == output_script,
            "Expected coinbase output is missing or immature")
    return outpoint, coin["value"]


def sign_spend(node, address, outpoint, value, public_key, redeem_script):
    # Spend just the first coinbase output back to the disposable test address.
    amount = value - Decimal("0.001")
    require(amount > 0, "Funded output cannot cover the test fee")
    unsigned = node.rpc(
        "createrawtransaction", json.dumps([outpoint]), json.dumps({address: str(amount)}),
        raw=True,
    )
    signed = node.rpc("signrawtransactionwithwallet", unsigned, wallet=WALLET)
    require(signed["complete"] is True, "Reloaded wallet could not complete the spend signature")
    decoded = node.rpc("decoderawtransaction", signed["hex"])
    inputs = decoded["vin"]
    require(len(inputs) == 1 and all(inputs[0][k] == v for k, v in outpoint.items()),
            "Signed transaction does not spend the funded output")
    require(inputs[0]["scriptSig"]["hex"] == (bytes([len(redeem_script)]) + redeem_script).hex(),
            "Signed transaction did not push the expected redeem script")
    witness = inputs[0]["txinwitness"]
    require(len(witness) == 2 and bool(witness[0]) and witness[1] == public_key.hex(),
            "Signed transaction did not witness with the exported Falcon public key")
    return signed["hex"], decoded["txid"]


def run(options, results):
    with tempfile.TemporaryDirectory(prefix="tdc-core-wallet-") as directory:
        root = Path(directory)
        with stage(results, STAGES[0]):
            address, wif, payload, public_key, redeem_script = mine_export(
                options.miner, root / "disposable.wif",
            )
            script_hash = hash160(redeem_script)
            require(address == encode_base58check(bytes([MAINNET_P2SH]) + script_hash),
                    "Legacy WIF public key does not reproduce the miner's mainnet address")
            output_script = (b"\xa9\x14" + script_hash + b"\x87").hex()

        with stage(results, STAGES[1]):
            daemon = core_binary(options.daemon, "daemon", "--daemon")
            cli = core_binary(options.cli, "RPC client", "--cli")

        with stage(results, STAGES[2]), Node(daemon, cli, root / "main", "main") as node:
            node.start()
            derived, _ = derive(node, f"sh(wpkh({wif}))")
            require(derived == address, "Core derived a different mainnet address")
            check_wrapped_script(node, address, redeem_script, output_script)
            node.stop()
        del wif

        with Node(daemon, cli, root / "regtest", "regtest") as node:
            with stage(results, STAGES[3]):
                node.start()
                address = import_export(node, payload, script_hash, redeem_script, output_script)
                del payload
            with stage(results, STAGES[4]):
                outpoint, value = fund_script(node, address, output_script)
            with stage(results, STAGES[5]):
                node.stop()
                node.start()
                loaded = node.rpc("loadwallet", WALLET)
                require(loaded["name"] == WALLET, "Core did not reopen the imported wallet")
                coins = node.rpc("listunspent", wallet=WALLET)
                require(any(coin["txid"] == outpoint["txid"] and coin["vout"] == outpoint["vout"]
                            and coin["scriptPubKey"] == output_script for coin in coins),
                        "Reloaded wallet did not recognize the mature funded output")
            with stage(results, STAGES[6]):
                signed_hex, txid = sign_spend(node, address, outpoint, value, public_key, redeem_script)
            with stage(results, STAGES[7]):
                require(node.rpc("sendrawtransaction", signed_hex, raw=True) == txid,
                        "Core did not accept the signed spend")
                node.rpc("getmempoolentry", txid)
                block = node.rpc("generatetoaddress", "1", address, timeout=180)
                require(len(block) == 1 and txid in node.rpc("getblock", block[0], "1")["tx"],
                        "Mined block did not confirm the signed spend")
                node.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--miner", required=True, type=Path)
    parser.add_argument("--daemon", default="tidecoind")
    parser.add_argument("--cli", default="tidecoin-cli")
    options = parser.parse_args()
    print(f"Core reference {CORE_VERSION} ({CORE_REVISION})", flush=True)
    results = dict.fromkeys(STAGES, "NOT RUN")
    try:
        run(options, results)
    except CheckFailed as error:
        # CheckFailed messages are defined by the harness and contain no RPC data.
        print(error)
        return 1
    except (Exception, KeyboardInterrupt) as error:
        # Never render exceptions that may carry private inputs or RPC replies.
        print(f"Wallet check stopped ({type(error).__name__})")
        return 130 if isinstance(error, KeyboardInterrupt) else 1
    finally:
        for name, result in results.items():
            print(f"{result:7} {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
