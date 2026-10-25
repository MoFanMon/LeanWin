"""Measure actual example execution; no Wine/CrossOver comparison is inferred."""
import json
import datetime
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples"))
from build import console, Program


def benchmark():
    executable = ROOT / "build" / "leanwin"
    result = {"generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "host_architecture": platform.machine(),
              "system": platform.platform(), "binary_bytes": executable.stat().st_size,
              "gui_module_bytes": (ROOT / "build" / "liblwgui.dylib").stat().st_size
                  if (ROOT / "build" / "liblwgui.dylib").exists() else None,
              "method": "20 fresh processes per architecture; includes launch, output capture and execution; warm filesystem cache; no baseline competitor", "samples": {}}
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        for bits in (32, 64):
            program, report, drive = directory / f"hello{bits}.exe", directory / "run.json", directory / "drive"
            program.write_bytes(console(bits).image())
            samples = []
            for _ in range(20):
                start = time.perf_counter_ns()
                run = subprocess.run([str(executable), "run", str(program), "--root", str(drive), "--report", str(report)], capture_output=True, timeout=5)
                wall_ms = (time.perf_counter_ns() - start) / 1_000_000
                if run.returncode != 37 or run.stdout != b"Hello from a Windows EXE on macOS!\r\n":
                    raise RuntimeError(f"example execution failed: {run.returncode}, {run.stderr!r}")
                samples.append({"process_wall_ms": wall_ms, **json.loads(report.read_text())})
            result["samples"][str(bits)] = {
                "process_wall_median_ms": statistics.median(x["process_wall_ms"] for x in samples),
                "runtime_median_ms": statistics.median(x["elapsed_ms"] for x in samples),
                "host_peak_rss_median_bytes": statistics.median(x["host_peak_rss_bytes"] for x in samples),
                "runs": samples}
        loop = Program([("KERNEL32.dll", "ExitProcess")])
        loop.prologue()
        loop.emit(b"\xb9\xa0\x86\x01\x00\x83\xe9\x01\x75\xfb")
        loop.call("ExitProcess")
        path = directory / "loop.exe"
        path.write_bytes(loop.image())
        run = subprocess.run([str(executable), "run", str(path), "--root", str(directory / "drive"), "--report", str(directory / "loop.json")], capture_output=True, timeout=5)
        if run.returncode:
            raise RuntimeError(run.stderr.decode())
        result["integer_loop"] = json.loads((directory / "loop.json").read_text())
    return result


if __name__ == "__main__":
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "reports" / "benchmark.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(benchmark(), indent=2) + "\n")
    print(output)
