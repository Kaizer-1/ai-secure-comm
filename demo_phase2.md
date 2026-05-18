# Phase 2 Demo Walkthrough

This is the manual smoke test for the end of Phase 2.  Treat it as
both a demo script and a checklist — Phase 2 is "done" when every
step here passes on a fresh machine.

## Prerequisites

```bash
cd ai_secure_comm
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover tests          # 74 tests should pass
```

If the test suite is green, the cryptographic core, the TCP transport,
the chunked file transfer, and the PeerLink glue are all working.  The
walkthrough below exercises the *web UI* on top of those.

---

## Dev mode (single laptop, two browser tabs)

Run a single command:

```bash
python launcher_dev.py
```

This starts `app.py --role alice` and `app.py --role bob` as
subprocesses, waits ~2s for both Flask servers to bind, and opens
two browser tabs:

- alice → <http://127.0.0.1:5001/>
- bob   → <http://127.0.0.1:5002/>

### Step 1 — page renders (≤2s after launch)

Each tab shows:

- Role header in the role's color (alice = cyan, bob = amber).
- Connection status: gray dot, label "idle" briefly, then yellow
  ("syncing…") once the SocketIO connection forms.
- A two-column layout: chat on the left, **Wire View** on the right.
- A drop zone above the chat input ("Drop a file to send securely").
- The message input is **disabled** until sync completes.

### Step 2 — TPM sync (≤2s)

Both tabs auto-trigger sync when their SocketIO connects.  You should
see:

- A horizontal progress bar appear under the header, pulsing
  cyan, with text like `round 30 / 10000`.
- Status dot turns yellow.

When sync converges (typically 100–400 rounds):

- Progress bar disappears.
- Status dot turns **green** and reads "synchronised".
- A `key:` indicator appears in the top-right showing the first 16
  hex chars of the derived AES key.
- A system bubble appears in the chat log: `key derived after N
  rounds (X ms)`.
- The message input becomes enabled.

**Both tabs MUST display the same 16-char key fingerprint.**  If the
fingerprints differ, sync silently failed — stop and investigate.

### Step 3 — chat (≤1s round-trip per message)

In alice's tab: type `hello bob` → press Enter / click Send.

- alice's tab: a cyan bubble appears on the right with "you — HH:MM:SS"
  and the plaintext.  A wire-view entry appears with a `→` arrow,
  timestamp, byte count (~50–60 bytes), and the ciphertext as hex.
- bob's tab: an amber bubble appears on the left from "alice".  A
  wire-view entry appears with a `←` arrow and the same ciphertext.

Send a few messages in both directions.  All bubbles auto-scroll;
wire view stays bounded by `WIRE_VIEW_BUFFER` (50 entries by default).

### Step 4 — wire view toggle

Click the **show** checkbox in the wire-view header — wire entries
should stop being added (existing ones stay).  Re-tick the box;
new entries resume.  This proves the wire-view feed and the chat
feed are independent.

### Step 5 — file transfer via drag-and-drop

Drag a small image (a few hundred KB) onto either tab's drop zone.

- The drop zone briefly highlights cyan during the drag.
- A small status line appears under the drop zone: `uploading
  filename.png (NNN bytes)…`, then `sending filename.png…`.
- The sender's chat log shows a system bubble: `↑ sent: filename.png
  (NNN bytes, M chunks)`.
- The receiver's chat log shows two bubbles:
  1. `📎 incoming file: filename.png (NNN bytes, M chunks)` (system)
  2. `📥 file received ✓ — filename.png` (clickable download link)

Click the download link in the receiver's tab.  The browser downloads
`filename.png`; opening it shows the same image you dragged in.

The `✓` indicates the SHA-256 verified.  An `✗` means the assembled
plaintext did not match the sender's announced digest — that's a real
bug, not a demo nuance, so investigate.

### Step 6 — graceful shutdown

Hit Ctrl+C in the launcher terminal.

- Both tabs' status dots flip to red ("disconnected").
- Both subprocess logs show shutdown.
- Launcher prints `[launcher] done.` and exits cleanly.

---

## Demo mode (two laptops on a hotspot)

Once dev mode works, the demo-mode change set is **just `config.py`
edits**:

| Knob | Server laptop (alice, the initiator) | Client laptop (bob) |
| --- | --- | --- |
| `BIND_HOST` | `"0.0.0.0"` | `"127.0.0.1"` (irrelevant — bob doesn't bind) |
| `PEER_HOST` | `"127.0.0.1"` (irrelevant — alice doesn't dial) | `"<alice's hotspot IP>"` |
| `INITIATOR_ROLE` | `"alice"` | `"alice"` (same on both) |

Then on each laptop:

```bash
# Pre-flight check — run it ONCE per laptop before launching the app.
python network_check.py --role alice    # on alice's laptop
python network_check.py --role bob      # on bob's laptop (after alice is bound)

# If both report "all checks passed", launch the role-specific app:
python app.py --role alice               # on alice's laptop
python app.py --role bob                 # on bob's laptop
```

Open `http://127.0.0.1:5001/` in each laptop's browser.  Steps 1–6
above behave identically.

---

## Known boundaries (do NOT debug as Phase 2 bugs)

- **Attack simulators** (MITM / replay buttons) — Phase 3.
- **AI threat dashboard** — Phase 4.
- **Throughput / latency charts, RSA comparison, polish** — Phase 5.
- **Multiple simultaneous file transfers** — out of scope; one at a time.
- **Mobile-responsive UI** — out of scope; desktop browsers only.
- **Persistent message history** — in-memory only; refresh wipes it.
- **TLS on the alice↔bob socket** — out of scope; we're demonstrating
  the TPM+AES layer, not stacking TLS on top.

If any step above fails on a fresh checkout, that *is* a Phase 2 bug —
log it and fix it before declaring Phase 2 complete.
