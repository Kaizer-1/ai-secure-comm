"""Single-command dev launcher.

Starts both `app.py --role alice` and `app.py --role bob` as
subprocesses on this machine, opens a browser tab for each, and
pipes their stdout to this terminal with role prefixes.  Ctrl+C
shuts both down cleanly.

Demo mode (two laptops on a hotspot) does NOT use this file — each
laptop runs `python app.py --role <role>` directly.  See
`docs/demo_phase2.md`.
"""

from __future__ import annotations

import signal
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

import config


def _stream(proc: subprocess.Popen, label: str) -> None:
    """Forward subprocess stdout to ours, prefixed with [role]."""
    assert proc.stdout is not None
    for line in iter(proc.stdout.readline, ""):
        if not line:
            break
        sys.stdout.write(f"[{label}] {line}")
        sys.stdout.flush()


def main() -> int:
    here = Path(__file__).resolve().parent
    app_py = here / "app.py"
    if not app_py.exists():
        print(f"[launcher] could not find {app_py}", file=sys.stderr)
        return 1

    targets = [
        (config.ROLE_A, config.FLASK_PORT_ALICE),
        (config.ROLE_B, config.FLASK_PORT_BOB),
    ]

    procs: list[tuple[str, int, subprocess.Popen]] = []
    try:
        for role, port in targets:
            p = subprocess.Popen(
                [sys.executable, str(app_py), "--role", role,
                 "--port", str(port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            t = threading.Thread(
                target=_stream, args=(p, role),
                name=f"stream-{role}", daemon=True,
            )
            t.start()
            procs.append((role, port, p))

        # Wait briefly for both Flask servers to bind.  Two seconds is
        # plenty for a threading-mode dev server.
        time.sleep(2.0)

        # Open both UIs.  webbrowser.open returns immediately once the
        # OS has handed the URL off; on macOS it focuses the existing
        # browser if one is open.
        for role, port, _ in procs:
            url = f"http://127.0.0.1:{port}/"
            print(f"[launcher] opening {role} at {url}", flush=True)
            webbrowser.open(url, new=2)

        print(f"\n[launcher] both processes running. "
              f"Ctrl+C to stop.\n", flush=True)

        # Block until Ctrl+C or until either subprocess dies.
        while True:
            time.sleep(0.5)
            for role, _, p in procs:
                if p.poll() is not None:
                    print(
                        f"\n[launcher] {role} exited "
                        f"(code={p.returncode}); shutting down",
                        flush=True,
                    )
                    raise KeyboardInterrupt

    except KeyboardInterrupt:
        print("\n[launcher] stopping…", flush=True)
    finally:
        for role, _, p in procs:
            if p.poll() is None:
                try:
                    p.send_signal(signal.SIGTERM)
                except Exception:  # noqa: BLE001
                    pass
        # Grace period before SIGKILL.
        for role, _, p in procs:
            try:
                p.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                print(f"[launcher] {role} did not exit; killing",
                      flush=True)
                p.kill()
                p.wait()
        print("[launcher] done.", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
