"""Demo-day pre-flight check for the alice↔bob TCP channel.

The two roles cooperate — alice runs first and **waits** for bob to
arrive within 60 seconds, exchanges a tiny handshake, and only then
declares success.  An earlier version exited as soon as alice's bind
succeeded, which gave a false "all checks passed" the moment alice's
listening socket had already been released.

Usage (run on each laptop in this order):

    Terminal 1, alice's laptop:
        python network_check.py --role alice
        # → "✓ bound 127.0.0.1:9001"
        # → "· waiting up to 60 seconds for peer check to connect…"

    Terminal 2, bob's laptop, within 60 seconds:
        python network_check.py --role bob
        # → "✓ ping 127.0.0.1"
        # → "✓ TCP connect 127.0.0.1:9001"
        # → "✓ peer connected and handshake successful"
        # → "all checks passed."

    Back in terminal 1, alice's check now also reports success
    and exits 0.

The handshake string is the literal ASCII line ``NETCHECK_OK\\n``;
both sides send it and both expect to receive it.

Exit code 0 on full success, 1 on any failure.
"""

from __future__ import annotations

import argparse
import platform
import socket
import subprocess
import sys

import config


GREEN = "\033[32m"
RED = "\033[31m"
DIM = "\033[2m"
RESET = "\033[0m"

_HANDSHAKE = b"NETCHECK_OK\n"
_HANDSHAKE_TRIMMED = _HANDSHAKE.strip()
_INITIATOR_WAIT_S = 60.0
_RESPONDER_CONNECT_TIMEOUT_S = 5.0
_HANDSHAKE_TIMEOUT_S = 5.0


def _ok(msg: str) -> None:
    print(f"  {GREEN}✓{RESET} {msg}")


def _fail(msg: str) -> None:
    print(f"  {RED}✗{RESET} {msg}")


def _info(msg: str) -> None:
    print(f"  {DIM}·{RESET} {msg}")


def ping(host: str, timeout_s: float = 2.0) -> bool:
    """One ICMP echo; returns True on response."""
    flag = "-n" if platform.system() == "Windows" else "-c"
    timeout_flag = "-w" if platform.system() == "Windows" else "-W"
    timeout_arg = str(int(timeout_s))
    try:
        r = subprocess.run(
            ["ping", flag, "1", timeout_flag, timeout_arg, host],
            capture_output=True, text=True, timeout=timeout_s + 1,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _exchange_handshake(sock: socket.socket, role_label: str,
                        send_first: bool) -> bool:
    """Send and receive the handshake line.  Returns True on success.

    `send_first=True` for the initiator (alice's listener side) so the
    responder's `recv` finds bytes immediately.  `send_first=False` for
    the responder; it waits for the initiator's hello, then echoes it
    back so the initiator's blocking `recv` unblocks.
    """
    sock.settimeout(_HANDSHAKE_TIMEOUT_S)
    try:
        if send_first:
            sock.sendall(_HANDSHAKE)
            data = _recv_line(sock, max_bytes=64)
        else:
            data = _recv_line(sock, max_bytes=64)
            sock.sendall(_HANDSHAKE)
    except socket.timeout:
        _fail(f"handshake timed out (other side is the {role_label})")
        return False
    except OSError as exc:
        _fail(f"handshake socket error: {exc}")
        return False

    if data.strip() != _HANDSHAKE_TRIMMED:
        _fail(f"unexpected handshake bytes: {data!r}")
        return False
    return True


def _recv_line(sock: socket.socket, max_bytes: int = 64) -> bytes:
    """Read until newline or `max_bytes`, whichever comes first."""
    buf = bytearray()
    while len(buf) < max_bytes:
        chunk = sock.recv(min(16, max_bytes - len(buf)))
        if not chunk:
            break
        buf.extend(chunk)
        if b"\n" in chunk:
            break
    return bytes(buf)


# ---------------------------------------------------------------------------
# Per-role checks
# ---------------------------------------------------------------------------


def run_initiator_check() -> bool:
    """Bind, wait up to 60 s for the peer, exchange handshake, exit."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        try:
            server.bind((config.BIND_HOST, config.PEER_TCP_PORT))
            server.listen(1)
        except OSError as exc:
            _fail(f"bind {config.BIND_HOST}:{config.PEER_TCP_PORT} failed — {exc}")
            return False
        _ok(f"bound {config.BIND_HOST}:{config.PEER_TCP_PORT}")
        _info(f"waiting up to {int(_INITIATOR_WAIT_S)} seconds for peer "
              f"check to connect…")

        server.settimeout(_INITIATOR_WAIT_S)
        try:
            peer_sock, peer_addr = server.accept()
        except socket.timeout:
            _fail(
                f"no peer connected within {int(_INITIATOR_WAIT_S)}s — "
                f"make sure 'python network_check.py --role "
                f"{config.ROLE_B}' is run on the peer machine "
                f"within the timeout"
            )
            return False
        _info(f"peer connected from {peer_addr[0]}:{peer_addr[1]}")

        try:
            if not _exchange_handshake(peer_sock, role_label="responder",
                                       send_first=True):
                return False
        finally:
            try:
                peer_sock.close()
            except OSError:
                pass

        _ok("peer connected and handshake successful")
        return True
    finally:
        try:
            server.close()
        except OSError:
            pass


def run_responder_check() -> bool:
    """Ping, dial alice's listener, exchange handshake, exit."""
    if ping(config.PEER_HOST):
        _ok(f"ping {config.PEER_HOST}")
    else:
        _fail(f"ping {config.PEER_HOST} failed (Wi-Fi up? same network?)")
        return False

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(_RESPONDER_CONNECT_TIMEOUT_S)
    try:
        try:
            s.connect((config.PEER_HOST, config.PEER_TCP_PORT))
        except OSError as exc:
            _fail(
                f"TCP connect {config.PEER_HOST}:{config.PEER_TCP_PORT} "
                f"failed — {exc}"
            )
            _info(
                f"make sure 'python network_check.py --role "
                f"{config.ROLE_A}' is currently running on the peer "
                f"machine"
            )
            return False
        _ok(f"TCP connect {config.PEER_HOST}:{config.PEER_TCP_PORT}")

        if not _exchange_handshake(s, role_label="initiator",
                                   send_first=False):
            return False

        _ok("peer connected and handshake successful")
        return True
    finally:
        try:
            s.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Pre-flight check for the alice↔bob TCP channel.  Run "
            f"`--role {config.ROLE_A}` first; it will wait up to 60 "
            f"seconds for `--role {config.ROLE_B}` on the peer "
            "machine to arrive."
        ),
    )
    parser.add_argument(
        "--role", required=True, choices=[config.ROLE_A, config.ROLE_B],
    )
    args = parser.parse_args(argv)
    role = args.role
    is_initiator = (role == config.INITIATOR_ROLE)

    print(f"network_check  role={role}  initiator={is_initiator}")
    _info(f"BIND_HOST={config.BIND_HOST}")
    _info(f"PEER_HOST={config.PEER_HOST}")
    _info(f"PEER_TCP_PORT={config.PEER_TCP_PORT}")
    print()

    ok = run_initiator_check() if is_initiator else run_responder_check()

    print()
    if ok:
        print(f"{GREEN}all checks passed.{RESET}")
        return 0
    print(f"{RED}one or more checks failed.{RESET}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
