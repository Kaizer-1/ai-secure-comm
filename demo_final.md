# Demo Guide — AI-Enhanced Secure Communication System

> **Supersedes** `demo_phase2.md` and `demo_phase3.md`.  
> Target runtime: **10–12 minutes**.  Last updated: 2026-05-16.

---

## 1. Pre-Demo Setup

### Hardware / network
- **Dev mode (single laptop):** One machine, two browser tabs.  No network config needed.
- **Demo mode (two laptops):** Both on the same Wi-Fi or ad-hoc network.  Alice binds; Bob dials.

### Software check
```bash
cd ai_secure_comm
.venv/bin/python network_check.py   # confirms ports 9001, 5000, 5001 are free
```

If any port is in use, kill the occupying process with `lsof -i :<port>` → `kill <pid>`.

### IDS model
The trained model lives at `ai/trained_model.pkl` (448 KB).  If it is missing:
```bash
.venv/bin/python -m ai.ids_train --output ai/trained_model.pkl
```

### Confirm the test suite is green (optional but reassuring)
```bash
.venv/bin/python -m unittest discover -s tests -q
# Expected: 158 tests, 1 skipped, 0 failures
```

---

## 2. Dev Mode Quick Start (single laptop)

```bash
cd ai_secure_comm
.venv/bin/python launcher_dev.py
```

`launcher_dev.py` starts two Python processes (alice on port 5000, bob on 5001) and opens both browser tabs automatically.  Wait ~5 seconds for TPM sync to complete — the UI shows a live round counter while it works.

**What to expect:**
- Both tabs show the role label (Alice / Bob) in the header.
- A progress bar counts synchronisation rounds.
- After sync: key fingerprint appears; the message input unlocks.
- You can type in either tab and the other receives the message instantly.

---

## 3. Demo Mode (Two Laptops)

### Step 1 — Edit `config.py` on Bob's laptop
```python
PEER_HOST = "192.168.x.y"   # Alice's IP address
```
Leave everything else at defaults.

### Step 2 — Start Alice first
```bash
# Alice's machine
cd ai_secure_comm && .venv/bin/python app.py --role alice
```
Alice binds TCP port 9001 and waits for Bob.

### Step 3 — Start Bob
```bash
# Bob's machine
cd ai_secure_comm && .venv/bin/python app.py --role bob
```
Bob dials Alice's IP on port 9001.  TPM sync begins immediately.

### Step 4 — Open browsers
- Alice's laptop → `http://localhost:5000`
- Bob's laptop → `http://localhost:5001`

Both UIs connect via WebSocket to their local Flask server; the two Flask servers communicate peer-to-peer over TCP.

---

## 4. Full Demo Script (10–12 minutes)

Use this section as a prompt-sheet during the viva.  Timings are approximate.

---

### §1 Cold Start + Key Synchronisation  *(~2 min)*

**What to do:**  
Run `launcher_dev.py` (or start both servers manually).  Let the tabs auto-open.  Point at the progress indicator.

**What to say:**  
> "Both processes just started.  What you're watching now is the Tree Parity Machine synchronisation.  Alice and bob each have a 3-layer neural network with random weights.  They exchange output bits — not the weights themselves — and after every matching output they both update their weights using the Hebbian rule.  The more rounds they run the more their weight vectors converge, and eventually they reach identical weights.  Nobody watching the wire ever sees the weights."

> "You can see the round counter climbing.  Typical sync takes 200–400 rounds, which is around 2–3 seconds here.  The exact number is non-deterministic — it depends on initial random weights."

**What to show:**  
Once sync completes, point at the key fingerprint.

> "This hex string is a SHA-256 hash of Alice's weight vector.  Bob's hash is identical — we just derived the same 256-bit AES key from two sets of weights that never left their respective machines.  That's the quantum-resistant property: an eavesdropper who captured every exchange bit still cannot reconstruct the weights."

---

### §2 Normal Encrypted Chat  *(~1 min)*

**What to do:**  
Type a message from Alice's tab.  Watch Bob receive it.

**What to say:**  
> "Alice types 'Hello Bob.'  Before it goes on the wire it's encrypted with AES-256-GCM using the derived key.  The wire view at the bottom shows the raw ciphertext — notice it changes completely with every message even for the same plaintext, because each frame gets a fresh 12-byte nonce.  Bob's side decrypts transparently and the plaintext appears in the chat."

> "The green padlock means the auth tag verified — nobody tampered with this frame in transit."

---

### §3 File Transfer  *(~1 min)*

**What to do:**  
Click the paper-clip icon on Alice's tab and upload a small file (e.g., a photo or PDF).

**What to say:**  
> "Files use the same AES-256-GCM pipeline, just chunked.  The metadata — filename, size, SHA-256 hash — travels in a separate encrypted control frame first so Bob knows what to expect.  Each chunk is independently encrypted.  On arrival Bob reassembles and SHA-256-verifies the plaintext; if any chunk was tampered, the hash check fails and Bob rejects the whole file."

---

### §4 Demo Panel Reveal  *(~30 s)*

**What to do:**  
Press **Ctrl + Shift + D** (or Cmd + Shift + D on Mac) in Alice's tab.

**What to say:**  
> "There's a hidden attack-control panel — not visible in normal use, only for the demo.  It lets us inject two simulated attacks without needing a separate machine acting as a man-in-the-middle."

> "This panel is gated behind `config.DEMO_MODE = True`.  In a real deployment you'd set it to False and the SocketIO event handlers simply aren't registered — there's no endpoint a hostile client could probe."

---

### §5 MITM Attack — Launch  *(~2 min)*

**What to do:**  
Click **Launch MITM** in Alice's demo panel.  Then send 5–6 messages from Alice.

**What to say:**  
> "The MITM simulator is now registered on Alice's outbound transport.  It bit-flips roughly 30 % of outbound chat frames before they leave Alice's socket.  The bits that flip are inside the AES-GCM ciphertext, so when Bob tries to verify the auth tag it fails — Bob sees a red 'tampered ciphertext rejected' bubble for those messages."

> "Meanwhile, Bob's IDS is watching.  Notice the threat gauge in the top-right — it shows the Random Forest's current probability estimate for each attack class.  Right now it's mostly green: normal traffic."

> "Keep watching as I send a few more messages…"

*(Send 5–8 more messages.  The gauge will start shifting toward red.)*

> "The IDS uses a sliding window of the last 20 frames and evaluates every 5.  It needs 3 evaluations before it starts making alerts — that's the warming-up period — so detection intentionally lags a little.  This is by design: a single corrupted frame could be a legitimate bit error, not an attack.  We want statistical evidence before alerting."

---

### §6 MITM Detection Moment  *(~1 min — emphasise this)*

**What to do:**  
Continue sending messages until the amber banner appears on Bob's tab.

**What to say:**  
> "There it is — the amber 'MITM Detected' banner.  The Random Forest crossed the 70 % confidence threshold for the MITM class.  The gauge is now firmly red."

> "The key IDS feature here is `decrypt_failure_rate` — the fraction of frames in the current window that failed AES-GCM authentication.  With 30 % of Alice's frames being tampered, that rate climbs to around 0.25–0.35, which the model confidently classifies as an MITM pattern.  Normal traffic has a failure rate of exactly zero."

> "Notice the history chip in the bottom-right corner — it will log how long this alert lasted once we clear it."

---

### §7 Stop MITM — Watch Alert Clear  *(~30 s)*

**What to do:**  
Click **Stop All Attacks** in the demo panel.  Watch the banner fade.

**What to say:**  
> "When we stop the attack the demo panel immediately resets the IDS — it clears the observation window so the gauge returns to green instantly.  In a real adversarial scenario we wouldn't know the attacker stopped; the window would age out naturally over the next 20 frames of clean traffic.  For the demo we fast-path it so the audience can see the clear happen live."

> "The history chip now shows the MITM alert with its duration."

---

### §8 Replay Attack  *(~2 min)*

**What to do:**  
Click **Launch Replay** in Alice's demo panel.  Send 3–4 messages.

**What to say:**  
> "The Replay attack is structurally different from MITM.  Instead of corrupting frames, the attacker buffers valid encrypted frames and re-injects them unchanged every 3 seconds.  Because the replayed frames have valid auth tags — they're legitimate ciphertexts that were captured earlier — AES-GCM accepts them.  Bob decrypts them successfully and sees duplicate messages."

> "This is why kind-only AAD is a deliberate design choice.  If we'd included a sequence number in the AAD, replayed frames would fail authentication and the IDS couldn't see them at all — the replay attack would be invisible.  By keeping the AAD minimal, replayed frames reach the feature extractor where `duplicate_payload_count` can spike."

*(Wait for the rose/pink banner to appear.)*

> "And there's the Replay detection — rose banner, different colour from MITM so an operator can distinguish them at a glance.  The key feature is `duplicate_payload_count`: the number of frames in the window whose payload hash appears more than once."

---

### §9 Refresh Recovery  *(~30 s)*

**What to do:**  
While a banner is active, refresh Bob's browser tab (Cmd+R / Ctrl+R).

**What to say:**  
> "If a user refreshes mid-session the session state is replayed from the Flask server's in-memory cache.  The key fingerprint, IDS gauge, and any active threat banner are all replayed to the freshly connecting tab — the user sees the same state immediately, with no need to re-sync."

---

### §10 Stop & Clean Up

Click **Stop All Attacks** to clear the IDS state.  Confirm the banner fades and the gauge returns to green.

---

### §11 Metrics Dashboard  *(~1 min)*

**What to do:**  
Click the small **metrics** link in the top-right of the chat header (or navigate to `http://127.0.0.1:5001/metrics`).

**What to say:**  
> "This is the performance metrics dashboard — Phase 5A of the project.  It shows quantitative comparisons between the three key-exchange schemes we're using or could have used."

> "Section 1 is the key-exchange bar chart.  On this machine: TPM neural synchronisation takes about 41 milliseconds on average — comparable to RSA-2048's 68 ms and faster than RSA when you factor out the key-pair generation cost.  DH-2048 agreement is only 10 ms, but DH requires a one-time 39-second parameter generation step that RSA and TPM don't need."

> "Section 2 is AES-256-GCM throughput.  The x-axis is log scale.  For small messages — 64 bytes — throughput is limited by the per-call overhead of the AEAD primitive, about 28 MB/s.  For large messages the hardware AES-NI acceleration kicks in and we see over 7 GB/s.  All real chat messages are in the 64 B to 1 KB range, so the relevant figure is a few hundred MB/s — well above any network bottleneck."

> "Section 3 is IDS detection latency.  This accumulates during the demo session — if we just triggered an attack and saw the alert fire, the latency from button-click to first alert is recorded here.  The histogram shows the distribution of those detection times."

> "Section 4 shows the benchmark metadata — when these numbers were measured, Python version, platform — plus this session's message count and total bytes encrypted."

**Note on DH parameter generation:**  
On exam day, mention that the 39-second DH parameter-generation cost is a hardware/OS entropy issue on this machine; a hardware RNG or a cached parameter set brings this to under 1 second.  The *agreement* step (10 ms) is the operationally relevant cost.

---

---

## 5. Q&A Pointers

These are questions examiners typically ask, with one-line answers to help the presenter respond quickly.

| Question | Short answer |
|---|---|
| Why not use RSA or Diffie-Hellman? | TPM synchronises via neural weights, not algebraic hardness — it's a different mathematical family, and the project demonstrates a less-studied approach. |
| Is TPM quantum-resistant? | The security argument relies on the learning-with-errors structure of weight recovery, not integer factorisation — so yes, in principle, though TPM is not yet standardised. |
| Why AES-256-GCM and not ChaCha20? | AES has hardware acceleration on x86/ARM; GCM provides authenticated encryption in a single pass.  Both would work. |
| What does "kind-only AAD" mean? | The authenticated additional data is just the 1-byte frame type.  Intentionally omitting a nonce or sequence number lets the IDS see replayed frames; explained in DECISIONS.md. |
| Why Random Forest and not a neural network? | Random Forest trains in seconds on a laptop CPU, gives calibrated probabilities, and is interpretable — we can explain which features drove the decision.  A neural network would give better accuracy at the cost of all three. |
| Can the IDS produce false positives? | Yes — in practice, a flaky network with many retransmissions could raise `decrypt_failure_rate`.  The hysteresis thresholds (fire=0.70, clear=0.50) and the warming-up period reduce false positives. |
| What's in Phase 5? | 5A (done): performance metrics dashboard comparing TPM, RSA-2048, DH-2048 setup times and AES-GCM throughput.  5B: two-laptop hotspot dry-run.  5C: final report preparation. |
| How would you harden this for production? | Mutual TLS on the TCP link, a proper PKI for fingerprint verification, sequence numbers added to GCM AAD for production traffic, and the IDS model retrained on real-world traffic distributions. |

---

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| "not synced yet" error on send | Refresh the browser tab; the server replays sync state. |
| Sync never completes (>30 s) | Check firewall: port 9001 must be open between alice and bob.  Run `network_check.py`. |
| IDS gauge stuck at warming_up | Model file missing or corrupt.  Re-run `ids_train`. |
| MITM detection doesn't fire | Send more messages (need 15+ for 3 feature windows).  Check that `DEMO_MODE = True` in config. |
| `ResourceWarning` in test output | Known Python 3.13 GC quirk; documented in `docs/DECISIONS.md`.  All 158 tests still pass. |
