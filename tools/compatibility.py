"""List all imported entrypoints missing from the current LeanWin build."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    cli = Path(os.environ.get("LEANWIN_CLI", ROOT / "build/leanwin"))
    result = subprocess.run([str(cli), "inspect", str(args.file)], capture_output=True, text=True, timeout=10)
    if result.returncode:
        print(result.stderr, end="", file=sys.stderr)
        return result.returncode
    image = json.loads(result.stdout)
    capabilities = json.loads(subprocess.check_output([str(cli), "capabilities"], text=True, timeout=5))
    implemented = {(item["dll"].lower(), item["name"]) for item in capabilities["interfaces"]}
    # KERNELBASE is an existing runtime alias, not a new implementation.
    implemented |= {("kernelbase.dll", name) for dll, name in implemented if dll == "kernel32.dll"}
    missing, supported = [], []
    for group in image["imports"]:
        for symbol in group["symbols"]:
            entry = {"dll": group["dll"], "symbol": symbol, "delayed": group["delayed"]}
            (supported if (group["dll"].lower(), symbol) in implemented else missing).append(entry)
    report = {"file": args.file.name, "sha256": hashlib.sha256(args.file.read_bytes()).hexdigest(),
              "format": image["format"], "architecture": image["architecture"],
              "static_import_entries": len(supported) + len(missing),
              "supported_import_entries": len(supported), "missing_import_entries": len(missing),
              "supported_imports": supported, "missing_imports": missing,
              "execution_validated": False,
              "note": "Static entrypoint-name analysis only; parameter, instruction, loader and application compatibility are not established."}
    encoded = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    else:
        print(encoded, end="")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
