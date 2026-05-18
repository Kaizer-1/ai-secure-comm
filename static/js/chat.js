// chat.js — browser-side logic for the role-aware chat page.
//
// The Flask app emits SocketIO events; we update the DOM in response.
// No build step, no framework — keep it boringly readable.

(function () {
  const $ = (id) => document.getElementById(id);
  const ROLE = window.ROLE;
  const PEER_ROLE = window.PEER_ROLE;
  const WIRE_BUFFER = window.WIRE_VIEW_BUFFER || 50;

  // Canonical status definitions.  Every header-status update goes
  // through `setStatus(state)` so that all five visual states are
  // mapped from a single place — there is no risk of a caller
  // passing an inconsistent label/color combination, and there is
  // exactly one code path that the reconnect-replay flow shares with
  // first-time-sync.  Per-round counters and other fine-grained info
  // belong in the sync-progress bar, not the header.
  const STATUS_DEFS = {
    idle:       { color: "bg-slate-500",   label: "idle" },
    connecting: { color: "bg-amber-400",   label: "connecting…" },
    syncing:    { color: "bg-amber-400",   label: "synchronising…" },
    synced:     { color: "bg-emerald-400", label: "synchronised" },
    error:      { color: "bg-rose-500",    label: "error" },
  };

  function setStatus(state) {
    const def = STATUS_DEFS[state] || STATUS_DEFS.idle;
    $("status-dot").className = `w-3 h-3 rounded-full ${def.color}`;
    $("status-text").textContent = def.label;
  }

  function colorForRole(role) {
    return role === "alice" ? "cyan" : "amber";
  }

  function escapeHTML(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function formatTime(ts) {
    return new Date(ts * 1000).toLocaleTimeString();
  }

  // ---------- Chat log ----------
  function appendBubble(direction, text, ts, kind = "text") {
    const log = $("chat-log");
    const isOut = direction === "out";
    const ownColor = colorForRole(ROLE);
    const peerColor = colorForRole(PEER_ROLE);
    const bg = isOut ? `bg-${ownColor}-700` : `bg-${peerColor}-900`;
    const align = isOut ? "ml-auto" : "mr-auto";
    const sender = isOut ? "you" : PEER_ROLE;
    const div = document.createElement("div");
    div.className = `${align} ${bg} max-w-[85%] p-2 rounded text-sm break-words`;
    div.innerHTML = `
      <div class="text-[10px] opacity-70 mb-1">${escapeHTML(sender)} — ${escapeHTML(formatTime(ts))}</div>
      <div>${kind === "html" ? text : escapeHTML(text)}</div>
    `;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  }

  function appendSystemBubble(html) {
    const log = $("chat-log");
    const div = document.createElement("div");
    div.className = "mr-auto max-w-[85%] p-2 rounded text-xs bg-slate-800 text-slate-300 italic";
    div.innerHTML = html;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  }

  // ---------- Wire view ----------
  function appendWireEntry(direction, hex, ts, label, opts) {
    if (!$("wire-toggle").checked) return;
    opts = opts || {};
    const log = $("wire-log");
    const arrow = direction === "out" ? "→" : "←";
    const bytes = Math.floor(hex.length / 2);
    const trimmed = hex.length > 240 ? hex.slice(0, 240) + "…" : hex;

    // Variant styling.  Plain inbound/outbound get the role-coloured
    // left border; "rejected" entries (AES-GCM auth failed — Phase-3
    // MITM signal) get a red border + strikethrough hex so the demo
    // audience can see the ciphertext that was caught and discarded.
    let borderClass;
    let hexClass;
    let glyph = arrow;
    let labelText = label || "chat";
    if (opts.rejected) {
      borderClass = "border-rose-500";
      hexClass = "break-all text-rose-300/60 leading-tight line-through";
      glyph = `<span class="text-rose-400">✗</span>`;
      labelText = `${labelText} (rejected)`;
    } else {
      borderClass = direction === "out"
        ? "border-cyan-500"
        : "border-amber-500";
      hexClass = "break-all text-slate-300 leading-tight";
    }
    const div = document.createElement("div");
    div.className = `border-l-2 ${borderClass} pl-2 py-0.5`;
    div.innerHTML = `
      <div class="text-[10px] text-slate-500 mb-0.5">
        ${glyph} ${escapeHTML(labelText)} · ${escapeHTML(formatTime(ts))} · ${bytes} bytes
      </div>
      <div class="${hexClass}">${escapeHTML(trimmed)}</div>
    `;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
    while (log.children.length > WIRE_BUFFER) {
      log.removeChild(log.firstChild);
    }
  }

  // ---------- SocketIO wiring ----------
  const socket = io({ reconnection: true, reconnectionDelay: 500 });

  // On connect, the backend may emit a state-replay event (sync_complete
  // / sync_progress / sync_in_progress / error) so the new tab catches
  // up to whatever the existing PeerLink is doing.  If no such event
  // arrives within IDLE_GRACE_MS, we assume the backend is idle and
  // trigger start_sync ourselves — preserving the first-load UX.
  const IDLE_GRACE_MS = 2000;
  let initialStateTimer = null;

  function cancelInitialStateTimer() {
    if (initialStateTimer !== null) {
      clearTimeout(initialStateTimer);
      initialStateTimer = null;
    }
  }

  // The "connecting" header status is *deferred* by CONNECTING_DELAY_MS
  // rather than written immediately on `connect`.  Reason: SocketIO's
  // `reconnection: true` plus Engine.IO's polling→websocket upgrade
  // means the `connect` handler can fire *after* a replay
  // `sync_complete` has already painted "synchronised", which would
  // silently roll the status back to "connecting…" even though the
  // session is fine.  By deferring 500ms, any state-bearing event
  // (sync_complete in ~8ms over loopback) can cancel the deferred
  // write before the user ever sees it.  Pure first-load (idle
  // backend) still shows "connecting…" because no event arrives
  // within 500ms.
  const CONNECTING_DELAY_MS = 500;
  let connectingDelayTimer = null;

  // Once we've ever observed `sync_complete` in this page lifetime,
  // we KNOW we're synced — the AES key is derived, app mode is on,
  // chat traffic is flowing.  After that, no event-ordering glitch
  // (late connect handler, transport upgrade, etc.) is allowed to
  // roll the header status back to "connecting…".  This is the
  // correctness guarantee the previous (deferred-only) fix was
  // missing.
  let hasEverSynced = false;

  function cancelConnectingDelay() {
    if (connectingDelayTimer !== null) {
      clearTimeout(connectingDelayTimer);
      connectingDelayTimer = null;
    }
  }

  function scheduleConnectingStatus() {
    cancelConnectingDelay();
    connectingDelayTimer = setTimeout(() => {
      connectingDelayTimer = null;
      setStatus("connecting");
    }, CONNECTING_DELAY_MS);
  }

  socket.on("connect", () => {
    $("reconnect-banner").classList.add("hidden");
    // Once we've ever synced, this connect is either a transport
    // upgrade or a brief reconnect — DO NOT schedule a "connecting"
    // write.  The current "synchronised" indicator is correct.
    if (!hasEverSynced) {
      scheduleConnectingStatus();
    }
    cancelInitialStateTimer();
    initialStateTimer = setTimeout(() => {
      initialStateTimer = null;
      // No state event from the backend within the grace window —
      // treat as a first-load and ask for a fresh sync.
      socket.emit("start_sync");
    }, IDLE_GRACE_MS);
  });

  socket.on("disconnect", () => {
    // SocketIO client is configured with `reconnection: true`, so the
    // socket layer is already attempting to reconnect.  Show that as
    // "connecting…" rather than a hard error; the banner makes the
    // disconnect itself visible.  This is a real disconnect so we
    // skip the grace period — the user should see immediate feedback.
    cancelConnectingDelay();
    $("reconnect-banner").classList.remove("hidden");
    setStatus("connecting");
  });

  socket.on("hello", (data) => {
    // hello carries the role labels and a status hint.  We don't act
    // on it directly — the more specific event (sync_progress /
    // sync_complete / sync_in_progress / error) drives UI changes.
  });

  socket.on("sync_progress", (data) => {
    cancelConnectingDelay();
    cancelInitialStateTimer();
    setStatus("syncing");
    $("sync-progress").classList.remove("hidden");
    // Per-round detail goes in the progress bar's counter, not the
    // header — the header label is canonical per-state.
    $("sync-counter").textContent = `round ${data.round} / ${data.total}`;
    // Width: pct of rounds done, capped at 95% so the bar never looks
    // "complete" before sync_complete fires.
    const denom = Math.max(1, data.total);
    const pct = Math.min(95, Math.max(2, (data.round / denom) * 100));
    $("sync-bar").style.width = pct + "%";
  });

  socket.on("sync_in_progress", (data) => {
    // Backend says "we're syncing but I don't have a cached
    // sync_progress to show you yet".  Show indeterminate progress.
    cancelConnectingDelay();
    cancelInitialStateTimer();
    setStatus("syncing");
    $("sync-progress").classList.remove("hidden");
    $("sync-counter").textContent = "synchronising…";
    $("sync-bar").style.width = "5%";
  });

  function enableInput(keyHex) {
    // setStatus("synced") is the single source of truth for the
    // header indicator; both the first-time-sync and the reconnect-
    // replay paths land here, so there is exactly one code path for
    // "we're synchronised".
    setStatus("synced");
    $("sync-progress").classList.add("hidden");
    $("key-fp-wrap").classList.remove("hidden");
    $("key-fp").textContent = keyHex.slice(0, 16);
    $("chat-input").disabled = false;
    $("chat-send").disabled = false;
    $("choose-file-btn").disabled = false;
    $("chat-input").focus();
  }

  // ---------- File status helpers ----------
  function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
  }

  function showFileStatus(html) {
    const el = $("file-status");
    el.classList.remove("hidden");
    el.innerHTML = html;
  }

  function hideFileStatus(delayMs = 0) {
    if (delayMs > 0) {
      setTimeout(() => $("file-status").classList.add("hidden"), delayMs);
    } else {
      $("file-status").classList.add("hidden");
    }
  }

  socket.on("sync_complete", (data) => {
    // Cancel the deferred "connecting…" write FIRST.  If a connect
    // handler fired moments ago, its 500ms grace timer is still
    // pending; without this cancel the timer would later overwrite
    // our "synchronised" label.
    cancelConnectingDelay();
    cancelInitialStateTimer();
    // Latch: from now until the page is closed, the status indicator
    // is "synchronised" no matter what other events fire.  This is
    // the guarantee that fixes the bug where a late connect handler
    // (after a transport upgrade) was silently rolling the header
    // back to "connecting…".
    hasEverSynced = true;
    // Set the header status explicitly here AS WELL AS via enableInput.
    setStatus("synced");
    enableInput(data.key_fingerprint);
    // Phase 4C: reveal the IDS status bar at sync time so the audience
    // sees "WARMING UP · 0%" even before the first feature window fires.
    $("ids-status-bar").classList.remove("hidden");
    if (data.replay) {
      // The backend was already synced when this tab connected —
      // chat history is in-memory only, so explain why the log
      // looks empty even though the peer is still synced.
      appendSystemBubble(
        '<span class="text-slate-400">(reconnected — earlier messages not shown)</span>'
      );
    } else {
      appendSystemBubble(
        `key derived after <span class="text-emerald-400">${data.rounds}</span> rounds ` +
        (data.time_ms ? `(${data.time_ms} ms)` : "")
      );
    }
  });

  // App-phase events (chat / file) implicitly prove we're synced —
  // they could not have fired otherwise.  We reconcile the header to
  // "synchronised" here as a self-healing safety net: even if some
  // future event-ordering bug leaves the header stuck on "connecting…",
  // the very next message reverts it.  The user is no longer at the
  // mercy of getting handler ordering exactly right.
  function reconcileSyncedStatus() {
    if (hasEverSynced) {
      cancelConnectingDelay();
      setStatus("synced");
    }
  }

  // ---------- Phase-3: tampered-message bubble + duplicate detection ----------
  //
  // Tampered: AES-GCM rejected the inbound ciphertext.  Render a
  // distinct red/orange bordered bubble so the audience sees the
  // security layer catching MITM-tampered traffic — that's the demo
  // punchline and it must NOT look like an unspecified error.
  function appendTamperedBubble(payload) {
    const log = $("chat-log");
    const ts = payload.timestamp;
    const bytes = payload.ciphertext_size;
    const previewHex = payload.ciphertext_preview_hex || "";
    const div = document.createElement("div");
    div.className =
      "mr-auto max-w-[90%] p-2 rounded text-sm break-words " +
      "bg-rose-950 border border-rose-700 text-rose-100";
    div.innerHTML = `
      <div class="text-[10px] opacity-80 mb-1">
        ${escapeHTML(window.PEER_ROLE)} — ${escapeHTML(formatTime(ts))}
      </div>
      <div class="font-medium">
        <span class="text-rose-300">⚠ Tampered ciphertext rejected</span>
      </div>
      <div class="text-[11px] text-rose-200/80 mt-0.5">
        AES-GCM authentication failed · ${bytes} bytes
      </div>
      <div class="text-[10px] font-mono mt-1 break-all text-rose-300/70">
        ${escapeHTML(previewHex)}…
      </div>
    `;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  }

  // Duplicate detection: a replayed CHAT bundle is byte-for-byte
  // identical to its original (same ciphertext, same nonce, same
  // tag — Phase 3's kind-only AAD lets it decrypt cleanly).  We
  // remember every inbound ciphertext_hex we've seen and stamp
  // duplicates with a "↻ duplicate" footnote.  We do NOT suppress
  // duplicates — Phase 4's IDS will flag them as anomalies; the
  // chat just shows them so the audience can see what's happening.
  const RECENT_BUNDLES_LIMIT = (window.WIRE_VIEW_BUFFER || 50) * 2;
  const recentBundleSeenAt = new Map();   // hex → first-seen timestamp
  const recentBundleOrder = [];           // FIFO eviction order

  function recordAndCheckDuplicate(cipherHex, ts) {
    const prior = recentBundleSeenAt.get(cipherHex);
    if (prior !== undefined) {
      return prior;  // first-seen timestamp of the original
    }
    recentBundleSeenAt.set(cipherHex, ts);
    recentBundleOrder.push(cipherHex);
    while (recentBundleOrder.length > RECENT_BUNDLES_LIMIT) {
      const evict = recentBundleOrder.shift();
      recentBundleSeenAt.delete(evict);
    }
    return null;
  }

  socket.on("chat_received", (data) => {
    reconcileSyncedStatus();
    const dupTs = recordAndCheckDuplicate(data.ciphertext_hex, data.timestamp);
    if (dupTs !== null) {
      // Render the duplicate as a regular inbound bubble PLUS a
      // small footnote citing the original's timestamp.  Subtle on
      // purpose — the IDS, not the chat, is the thing that "flags".
      const log = $("chat-log");
      const peerColor = colorForRole(PEER_ROLE);
      const div = document.createElement("div");
      div.className =
        `mr-auto bg-${peerColor}-900 max-w-[85%] p-2 rounded text-sm break-words ` +
        `border-l-2 border-orange-400/70`;
      div.innerHTML = `
        <div class="text-[10px] opacity-70 mb-1">
          ${escapeHTML(PEER_ROLE)} — ${escapeHTML(formatTime(data.timestamp))}
        </div>
        <div>${escapeHTML(data.plaintext)}</div>
        <div class="text-[10px] mt-1 text-orange-300/80 italic">
          ↻ duplicate of earlier message at ${escapeHTML(formatTime(dupTs))}
        </div>
      `;
      log.appendChild(div);
      log.scrollTop = log.scrollHeight;
    } else {
      appendBubble("in", data.plaintext, data.timestamp);
    }
    appendWireEntry("in", data.ciphertext_hex, data.timestamp, "chat");
  });

  socket.on("chat_sent", (data) => {
    reconcileSyncedStatus();
    appendBubble("out", data.plaintext, data.timestamp);
    appendWireEntry("out", data.ciphertext_hex, data.timestamp, "chat");
  });

  socket.on("chat_decryption_failed", (data) => {
    reconcileSyncedStatus();
    appendTamperedBubble(data);
    // The tampered ciphertext still belongs in the wire view — it
    // arrived on the wire, after all — but distinctly marked so
    // the audience can correlate "this hex came in, AES-GCM caught
    // it, here's the bubble that explains why."
    appendWireEntry(
      "in", data.ciphertext_hex, data.timestamp, "chat",
      { rejected: true },
    );
  });

  // ---------- Incoming file events ----------
  // The receiver-side counterpart to the sender's "Uploading X% →
  // Sending → ✓ Sent" flow.
  let _receivingTotal = 0;
  let _receivingFilename = "";

  socket.on("file_meta_received", (meta) => {
    reconcileSyncedStatus();
    _receivingTotal = meta.total_chunks;
    _receivingFilename = meta.filename;
    showFileStatus(
      `Receiving <span class="text-slate-300">${escapeHTML(meta.filename)}</span> ` +
      `<span class="text-slate-500">(${formatBytes(meta.size)}, ${meta.total_chunks} chunks)</span>… 0%`
    );
    appendSystemBubble(
      `📎 incoming file: <strong>${escapeHTML(meta.filename)}</strong> ` +
      `(${formatBytes(meta.size)})`
    );
  });

  socket.on("file_chunk_received", (data) => {
    reconcileSyncedStatus();
    // Update the receive-progress percent.  We don't surface every
    // chunk's ciphertext to the wire view because big files would
    // spam the panel; the meta + complete events are evidence enough.
    if (_receivingTotal > 0) {
      const pct = Math.min(100, Math.round(
        ((data.chunk_index + 1) / _receivingTotal) * 100
      ));
      showFileStatus(
        `Receiving <span class="text-slate-300">${escapeHTML(_receivingFilename)}</span>… ${pct}%`
      );
    }
  });

  socket.on("file_sent", (data) => {
    reconcileSyncedStatus();
    appendSystemBubble(
      `<span class="text-emerald-400">✓ Sent</span> ` +
      `<strong>${escapeHTML(data.filename)}</strong> ` +
      `<span class="text-slate-500">(${formatBytes(data.size)}, ${data.total_chunks} chunks)</span>`
    );
    showFileStatus(
      `<span class="text-emerald-400">✓ Sent</span> ` +
      `<span class="text-slate-300">${escapeHTML(data.filename)}</span>`
    );
    hideFileStatus(3000);
  });

  socket.on("file_complete", (data) => {
    reconcileSyncedStatus();
    _receivingTotal = 0;
    _receivingFilename = "";
    const okGlyph = data.sha_ok
      ? '<span class="text-emerald-400">✓ Received</span>'
      : '<span class="text-rose-400">✗ checksum mismatch</span>';
    appendBubble(
      "in",
      `${okGlyph} — <a href="${data.download_url}" class="underline text-cyan-400">${escapeHTML(data.filename)}</a>`,
      Date.now() / 1000,
      "html",
    );
    showFileStatus(
      `${okGlyph} <span class="text-slate-300">${escapeHTML(data.filename)}</span>`
    );
    hideFileStatus(3000);
  });

  // ── Phase 4C: IDS gauge, threat banner, alert history ───────────────────

  // ---- state ----
  let idsAlertActive    = false;
  let idsActiveType     = null;   // "mitm" | "replay" | null
  let idsAlertTs        = null;   // ISO timestamp string when current alert started
  let idsAgoTimer       = null;   // setInterval id — updates "Xs ago" text
  let idsAutoFadeTimer  = null;   // setTimeout id — auto-dismisses banner after 10 s

  // In-memory alert history (not persisted across refresh by design).
  const IDS_MAX_HISTORY   = 5;
  const idsHistory        = [];   // [{type, startTs, endTs, chipEl}]

  // ---- gauge helpers ----
  function _gaugeColor(prob, alertType) {
    if (alertType) return "#dc2626";        // red  — active alert
    if (prob >= 0.70) return "#dc2626";     // red  — high zone
    if (prob >= 0.50) return "#f59e0b";     // amber — elevated zone
    return "#10b981";                       // emerald — normal
  }

  function _levelLabel(prob, idsState, alertType) {
    if (alertType === "mitm")   return "MITM DETECTED";
    if (alertType === "replay") return "REPLAY DETECTED";
    if (idsState === "warming_up") return "WARMING UP";
    if (prob >= 0.70) return "ELEVATED";
    if (prob >= 0.50) return "ELEVATED";
    return "LOW";
  }

  function _levelClass(prob, idsState, alertType) {
    if (alertType) return "text-red-400";
    if (idsState === "warming_up") return "text-slate-500";
    if (prob >= 0.50) return "text-amber-400";
    return "text-emerald-400";
  }

  function updateGauge(probabilities, idsState, alertType) {
    const prob = Math.max(
      (probabilities && probabilities.mitm)   || 0,
      (probabilities && probabilities.replay) || 0,
    );
    const pct = Math.round(prob * 100);
    const fill  = $("ids-gauge-fill");
    const pctEl = $("ids-gauge-pct");
    const lvlEl = $("ids-gauge-level");

    fill.style.width           = pct + "%";
    fill.style.backgroundColor = _gaugeColor(prob, alertType);

    if (alertType) {
      fill.classList.add("ids-gauge-pulse");
    } else {
      fill.classList.remove("ids-gauge-pulse");
    }

    pctEl.textContent = pct + "%";

    lvlEl.textContent  = _levelLabel(prob, idsState, alertType);
    // Swap colour class — remove all possible colours first.
    lvlEl.classList.remove(
      "text-emerald-400", "text-amber-400", "text-red-400", "text-slate-500"
    );
    lvlEl.classList.add(_levelClass(prob, idsState, alertType));
  }

  // ---- banner helpers ----
  function _bannerPalette(type) {
    // MITM → amber/yellow; Replay → rose/red.
    if (type === "mitm") {
      return {
        bg:     "bg-amber-950",
        border: "border-amber-600",
        text:   "text-amber-100",
        glow:   "rgba(217,119,6,0.4)",
      };
    }
    return {
      bg:     "bg-rose-950",
      border: "border-rose-600",
      text:   "text-rose-100",
      glow:   "rgba(220,38,38,0.4)",
    };
  }

  function _startAgoTimer() {
    _stopAgoTimer();
    idsAgoTimer = setInterval(() => {
      if (!idsAlertTs) return;
      const secs = Math.round((Date.now() - new Date(idsAlertTs).getTime()) / 1000);
      const agoEl = $("threat-started-ago");
      if (agoEl) agoEl.textContent = secs + "s";
    }, 1000);
  }

  function _stopAgoTimer() {
    if (idsAgoTimer !== null) {
      clearInterval(idsAgoTimer);
      idsAgoTimer = null;
    }
  }

  function _scheduleAutoFade() {
    _cancelAutoFade();
    idsAutoFadeTimer = setTimeout(() => {
      idsAutoFadeTimer = null;
      // Only auto-fade if no newer threat_alert has re-armed the timer.
      if (idsAlertActive) {
        hideThreatBanner(false);
      }
    }, 10000);
  }

  function _cancelAutoFade() {
    if (idsAutoFadeTimer !== null) {
      clearTimeout(idsAutoFadeTimer);
      idsAutoFadeTimer = null;
    }
  }

  function showThreatBanner(data) {
    _cancelAutoFade();
    _stopAgoTimer();

    idsAlertActive = true;
    idsActiveType  = data.type;
    idsAlertTs     = data.timestamp || new Date().toISOString();

    const palette  = _bannerPalette(data.type);
    const banner   = $("threat-banner");

    // Reset to a known base set of classes, then apply palette.
    // Keeping "hidden" removal and animation classes explicit avoids
    // regex-replacing arbitrary Tailwind utility names.
    const BANNER_COLOUR_CLASSES = [
      "bg-amber-950", "border-amber-600", "text-amber-100",
      "bg-rose-950",  "border-rose-600",  "text-rose-100",
    ];
    banner.classList.remove(...BANNER_COLOUR_CLASSES, "threat-banner-glow");
    banner.classList.add(
      palette.bg, palette.border, palette.text,
      "border-b-2", "flex-none", "threat-banner-glow"
    );

    // Populate content.
    $("threat-type").textContent =
      data.type === "mitm" ? "MITM Attack" : "Replay Attack";

    const confPct = Math.round((data.confidence || 0) * 100);
    $("threat-confidence").textContent = confPct + "%";

    const startedDate = new Date(idsAlertTs);
    $("threat-started-time").textContent = startedDate.toLocaleTimeString();
    $("threat-started-ago").textContent  = "0s";

    const snap = data.features_snapshot || {};
    const dfr  = snap.decrypt_failure_rate   != null
      ? Number(snap.decrypt_failure_rate).toFixed(3)   : "—";
    const dpc  = snap.duplicate_payload_count != null
      ? Number(snap.duplicate_payload_count).toFixed(1) : "—";
    $("threat-evidence").textContent =
      `decrypt_failure_rate=${dfr}, duplicate_payload_count=${dpc}`;

    // Show with slide-in animation.
    banner.classList.remove("hidden", "threat-banner-exit");
    banner.classList.add("threat-banner-enter");

    _startAgoTimer();
    _scheduleAutoFade();
  }

  function hideThreatBanner(showCleared, clearedData) {
    _stopAgoTimer();
    _cancelAutoFade();

    const banner = $("threat-banner");
    if (banner.classList.contains("hidden")) {
      // Already hidden — still show cleared bar if requested.
      if (showCleared && clearedData) _showClearedBar(clearedData);
      return;
    }
    banner.classList.remove("threat-banner-enter");
    banner.classList.add("threat-banner-exit");

    setTimeout(() => {
      banner.classList.add("hidden");
      banner.classList.remove("threat-banner-exit", "threat-banner-enter",
                              "threat-banner-glow");
      if (showCleared && clearedData) _showClearedBar(clearedData);
    }, 300);
  }

  function _showClearedBar(data) {
    const bar = $("threat-cleared-bar");
    const typeEl = $("threat-cleared-type");
    const durEl  = $("threat-cleared-duration");

    typeEl.textContent = data.previously_alerting_type
      ? (data.previously_alerting_type === "mitm" ? "MITM" : "Replay")
      : "threat";
    const secs = data.duration_seconds != null
      ? Math.round(data.duration_seconds) + "s"
      : "—";
    durEl.textContent = secs;

    bar.classList.remove("hidden");
    setTimeout(() => {
      bar.classList.add("hidden");
    }, 3000);
  }

  // ---- history chip helpers ----
  function _chipPalette(type) {
    if (type === "mitm") {
      return { bg: "#78350f", text: "#fde68a", border: "#d97706" };
    }
    return { bg: "#4c0519", text: "#fecdd3", border: "#e11d48" };
  }

  function _timeStr(isoOrMs) {
    if (!isoOrMs) return "—";
    const d = typeof isoOrMs === "number"
      ? new Date(isoOrMs)
      : new Date(isoOrMs);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function addHistoryChip(type, startTs) {
    const pal   = _chipPalette(type);
    const label = type === "mitm" ? "MITM" : "REPLAY";
    const chip  = document.createElement("span");
    chip.className = "ids-chip";
    chip.style.backgroundColor = pal.bg;
    chip.style.color            = pal.text;
    chip.style.border           = `1px solid ${pal.border}`;
    chip.dataset.tip            = `${label} · started ${_timeStr(startTs)}`;
    chip.textContent            = `${label} · ${_timeStr(startTs)} · active`;

    const strip = $("history-strip");
    const chips = $("history-chips");

    // Prepend — newest on the left — and enforce limit.
    chips.prepend(chip);
    while (chips.children.length > IDS_MAX_HISTORY) {
      chips.removeChild(chips.lastChild);
    }
    strip.classList.remove("hidden");

    // Store reference so we can update duration when the alert clears.
    idsHistory.unshift({ type, startTs, endTs: null, chipEl: chip });
    while (idsHistory.length > IDS_MAX_HISTORY) idsHistory.pop();

    return chip;
  }

  function finalizeActiveChip(durationSeconds) {
    const entry = idsHistory.find((h) => h.endTs === null);
    if (!entry || !entry.chipEl) return;
    entry.endTs = new Date().toISOString();
    const label = entry.type === "mitm" ? "MITM" : "REPLAY";
    const dur   = durationSeconds != null ? Math.round(durationSeconds) + "s" : "?s";
    const chip  = entry.chipEl;
    chip.textContent = `${label} · ${_timeStr(entry.startTs)} · ${dur}`;
    chip.dataset.tip = `${label} · started ${_timeStr(entry.startTs)} · lasted ${dur}`;
  }

  // ---- SocketIO event handlers ----

  socket.on("ids_probabilities", (data) => {
    // Show the IDS status bar on first event (sync must be done by then).
    $("ids-status-bar").classList.remove("hidden");
    updateGauge(
      data.probabilities || {},
      data.state || "warming_up",
      data.active_alert_type || null,
    );
  });

  socket.on("threat_alert", (data) => {
    reconcileSyncedStatus();
    $("ids-status-bar").classList.remove("hidden");
    // Update gauge immediately to "alerting" state.
    updateGauge(
      data.probabilities || {},
      "alerting",
      data.type,
    );
    showThreatBanner(data);
    // Add a history chip only for NEW alerts (not banner re-arms from
    // re-emitted events on confidence jumps).  We detect "new" by checking
    // whether the most-recent chip is still active.
    const lastEntry = idsHistory[0];
    const isNewAlert = !lastEntry || lastEntry.endTs !== null
      || lastEntry.type !== data.type;
    if (isNewAlert) {
      addHistoryChip(data.type, data.timestamp);
    }
  });

  socket.on("threat_cleared", (data) => {
    reconcileSyncedStatus();
    idsAlertActive = false;
    idsActiveType  = null;
    // Gauge drops back to whatever the current probabilities say —
    // the next ids_probabilities event will set the exact value.
    // Drive it to near-zero immediately for visual clarity.
    updateGauge({}, "monitoring", null);
    finalizeActiveChip(data.duration_seconds);
    hideThreatBanner(true, data);
  });

  // ---------- Phase-3 demo controls (Ctrl/Cmd+Shift+D) ----------
  const demoPanel = $("demo-panel");

  function isDemoOpen() {
    return !demoPanel.classList.contains("hidden");
  }

  function openDemoPanel() {
    demoPanel.classList.remove("hidden");
    socket.emit("demo_status");
  }

  function closeDemoPanel() {
    demoPanel.classList.add("hidden");
  }

  function toggleDemoPanel() {
    if (isDemoOpen()) closeDemoPanel(); else openDemoPanel();
  }

  document.addEventListener("keydown", (e) => {
    // Match Ctrl+Shift+D on Windows/Linux and Cmd+Shift+D on macOS.
    const modifier = e.ctrlKey || e.metaKey;
    const key = (e.key || "").toLowerCase();
    if (modifier && e.shiftKey && key === "d") {
      // Browser default for Cmd+Shift+D is "bookmark all tabs" — we
      // claim the chord while the page is focused.
      e.preventDefault();
      toggleDemoPanel();
    }
  });

  $("demo-panel-close").addEventListener("click", closeDemoPanel);
  $("demo-btn-mitm").addEventListener("click", () => {
    socket.emit("demo_launch_mitm");
  });
  $("demo-btn-replay").addEventListener("click", () => {
    socket.emit("demo_launch_replay");
  });
  $("demo-btn-stop").addEventListener("click", () => {
    socket.emit("demo_stop_attacks");
  });

  function renderDemoState(payload) {
    const active = (payload && payload.active) || [];
    const stats = (payload && payload.stats) || [];
    const activeEl = $("demo-status-active");
    const statsEl = $("demo-status-stats");
    if (active.length === 0) {
      activeEl.innerHTML = '<span class="text-rose-400">no attacks active</span>';
      statsEl.innerHTML = "—";
      return;
    }
    activeEl.innerHTML = active
      .map((n) => `<span class="text-rose-200">● ${escapeHTML(n)} active</span>`)
      .join("&nbsp;&nbsp;");
    statsEl.innerHTML = stats
      .filter((s) => s.active)
      .map((s) => {
        if (s.name === "mitm") {
          return `mitm: tampered ${s.frames_tampered}/${s.frames_seen} ` +
                 `(target ${(s.tamper_probability * 100).toFixed(0)}%)`;
        }
        if (s.name === "replay") {
          return `replay: buffered ${s.frames_buffered}, ` +
                 `replayed ${s.frames_replayed}, every ${s.interval_s}s`;
        }
        return `${escapeHTML(s.name)}: ${escapeHTML(JSON.stringify(s))}`;
      })
      .join("<br>");
  }

  socket.on("demo_attack_state", renderDemoState);
  socket.on("demo_attack_active", (data) => {
    // Refresh full state so the panel matches reality.
    socket.emit("demo_status");
  });
  socket.on("demo_attacks_stopped", () => {
    socket.emit("demo_status");
  });

  socket.on("peer_disconnected", () => {
    cancelConnectingDelay();
    setStatus("error");
    appendSystemBubble("peer disconnected");
  });

  socket.on("error", (data) => {
    cancelConnectingDelay();
    cancelInitialStateTimer();
    setStatus("error");
    appendSystemBubble(`error: ${escapeHTML(data.message || "unknown")}`);
  });

  // ---------- Chat form ----------
  $("chat-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const inp = $("chat-input");
    const text = inp.value.trim();
    if (!text) return;
    socket.emit("send_chat", { text });
    inp.value = "";
  });

  // ---------- File ingest: button + drag-and-drop ----------
  // The two entry points (button click → hidden <input type="file">
  // and drag-and-drop) BOTH call the same `sendFile(file)` so there's
  // exactly one upload code path to reason about.
  const dz = $("dropzone");
  const chooseBtn = $("choose-file-btn");
  const fileInput = $("file-input");

  chooseBtn.addEventListener("click", () => {
    if (chooseBtn.disabled) return;
    fileInput.click();
  });

  fileInput.addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    sendFile(file);
    // Reset the input so picking the same file twice in a row still
    // fires `change`.
    fileInput.value = "";
  });

  ["dragenter", "dragover"].forEach((ev) =>
    dz.addEventListener(ev, (e) => {
      e.preventDefault();
      if (chooseBtn.disabled) return;  // not synced yet — no visual cue
      dz.classList.add("border-cyan-400");
    }),
  );
  ["dragleave", "drop"].forEach((ev) =>
    dz.addEventListener(ev, (e) => {
      e.preventDefault();
      dz.classList.remove("border-cyan-400");
    }),
  );
  dz.addEventListener("drop", (e) => {
    e.preventDefault();
    if (chooseBtn.disabled) return;
    const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (!file) return;
    sendFile(file);
  });

  function sendFile(file) {
    if (!file) return;
    if (chooseBtn.disabled) {
      showFileStatus(
        '<span class="text-rose-400">not synced yet — wait for the green dot</span>',
      );
      hideFileStatus(3000);
      return;
    }

    // 1. Show the selected filename + size *before* upload starts.
    showFileStatus(
      `Selected <span class="text-slate-300">${escapeHTML(file.name)}</span> ` +
      `<span class="text-slate-500">(${formatBytes(file.size)})</span>`,
    );

    // 2. POST via XMLHttpRequest so we can surface upload progress.
    //    `fetch` doesn't expose upload progress events.
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/upload");

    xhr.upload.addEventListener("progress", (evt) => {
      if (!evt.lengthComputable) return;
      const pct = Math.min(100, Math.round((evt.loaded / evt.total) * 100));
      showFileStatus(
        `Transferring <span class="text-slate-300">${escapeHTML(file.name)}</span>… ${pct}%`,
      );
    });

    xhr.addEventListener("load", () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        // The HTTP POST landed — backend is now sending the file
        // chunk-by-chunk over the peer TCP socket.  The final
        // "✓ Sent" comes via the `file_sent` SocketIO event handler
        // above, so we just narrate the in-between phase here.
        showFileStatus(
          `Sending <span class="text-slate-300">${escapeHTML(file.name)}</span> over the secure channel…`,
        );
      } else {
        let msg = `upload failed (${xhr.status})`;
        try {
          msg = JSON.parse(xhr.responseText).error || msg;
        } catch (e) { /* not JSON; keep default */ }
        showFileStatus(
          `<span class="text-rose-400">${escapeHTML(msg)}</span>`,
        );
        hideFileStatus(4000);
      }
    });

    xhr.addEventListener("error", () => {
      showFileStatus(
        '<span class="text-rose-400">upload network error</span>',
      );
      hideFileStatus(4000);
    });

    const fd = new FormData();
    fd.append("file", file);
    xhr.send(fd);
  }
})();
