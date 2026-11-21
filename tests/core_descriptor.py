"""Check one disposable miner export against an already running local mainnet Core RPC."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--miner", required=True, type=Path)
    parser.add_argument("--cli", default="tidecoin-cli")
    parser.add_argument("--datadir", type=Path)
    options = parser.parse_args()
    cli = [options.cli, "-rpcconnect=127.0.0.1"]
    if options.datadir:
        cli.append(f"-datadir={options.datadir}")

    def rpc(command, argument=None):
        # Never pass a WIF in argv or include daemon errors containing inputs.
        reply = subprocess.run(
            [*cli, "-stdin", command], text=True, capture_output=True,
            input=argument + "\n" if argument is not None else "", timeout=30,
        )
        if reply.returncode:
            raise SystemExit(f"Local Core RPC {command} failed (exit {reply.returncode})")
        return json.loads(reply.stdout)

    if rpc("getblockchaininfo")["chain"] != "main":
        raise SystemExit("This test needs mainnet address parameters")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "disposable.wif"
        mined = subprocess.run(
            [str(options.miner.resolve()), "--workers=1", "--prefix=T", "--out", str(path)],
            check=True, capture_output=True, text=True, timeout=60,
        ).stdout.strip()
        address, key = path.read_text(encoding="ascii").strip().split(":")
        info = rpc("getdescriptorinfo", f"sh(wpkh({key}))")
        if not info["hasprivatekeys"] or not info["issolvable"]:
            raise SystemExit("Core did not recognize a solvable private descriptor")
        if rpc("deriveaddresses", info["descriptor"]) != [address] or address != mined:
            raise SystemExit("Core derived a different address")
    print("Core recognized the private descriptor and derived the mined address.")


if __name__ == "__main__":
    main()
