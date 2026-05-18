/**
 * metrics.js — Phase 5A performance dashboard
 *
 * Fetches /api/metrics_data on load, renders Chart.js charts, and
 * auto-refreshes the IDS latency section every 5 seconds.
 */

"use strict";

// ---------------------------------------------------------------------------
// Shared Chart.js defaults — dark "secure terminal" palette
// ---------------------------------------------------------------------------
const PALETTE = {
  teal:    "#22d3ee",   // cyan-400  (TPM / encrypt)
  amber:   "#fbbf24",   // amber-400 (RSA / decrypt)
  rose:    "#fb7185",   // rose-400  (DH / latency bars)
  slate600: "#475569",
  slate700: "#334155",
  slate300: "#cbd5e1",
  slate500: "#64748b",
};

Chart.defaults.color          = PALETTE.slate300;
Chart.defaults.borderColor    = PALETTE.slate700;
Chart.defaults.backgroundColor = "transparent";

function _chartDefaults(extraOpts = {}) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 400 },
    plugins: {
      legend: {
        labels: { color: PALETTE.slate300, boxWidth: 12, font: { size: 10 } },
      },
      tooltip: {
        backgroundColor: "#1e293b",
        borderColor: PALETTE.slate700,
        borderWidth: 1,
        titleColor: PALETTE.slate300,
        bodyColor: PALETTE.slate500,
      },
    },
    scales: {
      x: {
        ticks: { color: PALETTE.slate500, font: { size: 10 } },
        grid: { color: PALETTE.slate700 },
      },
      y: {
        ticks: { color: PALETTE.slate500, font: { size: 10 } },
        grid: { color: PALETTE.slate700 },
      },
    },
    ...extraOpts,
  };
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

function _show(id)  { document.getElementById(id).classList.remove("hidden"); }
function _hide(id)  { document.getElementById(id).classList.add("hidden"); }
function _el(id)    { return document.getElementById(id); }
function _fmt1(v)   { return v == null ? "—" : v.toFixed(1); }
function _fmt0(v)   { return v == null ? "—" : Math.round(v).toLocaleString(); }

function _dtRow(dl, term, value) {
  dl.insertAdjacentHTML("beforeend",
    `<div class="flex gap-1">
      <dt class="text-slate-500 flex-none">${term}:</dt>
      <dd class="text-slate-300 truncate">${value}</dd>
    </div>`
  );
}

// ---------------------------------------------------------------------------
// §1 — Key-Exchange bar chart
// ---------------------------------------------------------------------------

let _keyChart = null;

function _renderKeyExchange(ke) {
  if (!ke) {
    _show("no-key-exchange");
    return;
  }
  _hide("no-key-exchange");

  const labels = ["TPM (neural)", "RSA-2048", "DH-2048"];
  const means  = [ke.tpm?.mean_ms, ke.rsa_2048?.mean_ms, ke.dh_2048?.mean_ms];
  const stds   = [ke.tpm?.std_ms,  ke.rsa_2048?.std_ms,  ke.dh_2048?.std_ms];

  const ctx = _el("chart-key-exchange").getContext("2d");
  if (_keyChart) _keyChart.destroy();

  _keyChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Mean setup time (ms)",
        data: means,
        backgroundColor: [
          "rgba(34,211,238,0.25)",
          "rgba(251,191,36,0.25)",
          "rgba(251,113,133,0.25)",
        ],
        borderColor: [PALETTE.teal, PALETTE.amber, PALETTE.rose],
        borderWidth: 2,
        borderRadius: 3,
        // Error bars via custom drawing aren't built-in; show std in tooltip.
      }],
    },
    options: _chartDefaults({
      plugins: {
        ..._chartDefaults().plugins,
        title: { display: false },
        tooltip: {
          ..._chartDefaults().plugins.tooltip,
          callbacks: {
            afterBody: (items) => {
              const idx = items[0].dataIndex;
              const std = stds[idx];
              return std != null ? [`± ${std.toFixed(1)} ms (std dev)`] : [];
            },
          },
        },
      },
      scales: {
        ..._chartDefaults().scales,
        y: {
          ..._chartDefaults().scales.y,
          title: { display: true, text: "Time (ms)", color: PALETTE.slate500, font: { size: 10 } },
          beginAtZero: true,
        },
      },
    }),
  });

  // Summary table
  const tbody = _el("key-exchange-tbody");
  tbody.innerHTML = "";
  const rows = [
    { label: "TPM (neural)", d: ke.tpm,
      note: ke.tpm ? `avg ${ke.tpm.avg_rounds?.toFixed(0)} rounds` : "" },
    { label: "RSA-2048",    d: ke.rsa_2048,
      note: ke.rsa_2048 ? `keygen ${_fmt1(ke.rsa_2048.keypair_gen_ms_mean)} ms` : "" },
    { label: "DH-2048",     d: ke.dh_2048,
      note: ke.dh_2048 ? `param-gen ${_fmt0(ke.dh_2048.param_gen_ms_one_time)} ms (once)` : "" },
  ];
  for (const r of rows) {
    tbody.insertAdjacentHTML("beforeend", `
      <tr class="border-b border-slate-800">
        <td class="py-0.5 pr-2">${r.label}</td>
        <td class="text-right px-1">${_fmt1(r.d?.mean_ms)}</td>
        <td class="text-right px-1">${_fmt1(r.d?.median_ms)}</td>
        <td class="text-right px-1">${_fmt1(r.d?.std_ms)}</td>
        <td class="text-right px-1">${_fmt1(r.d?.min_ms)}</td>
        <td class="text-right px-1">${_fmt1(r.d?.max_ms)}</td>
        <td class="text-right pl-1 text-slate-500">${r.note}</td>
      </tr>`);
  }
  _show("key-exchange-table");
}

// ---------------------------------------------------------------------------
// §2 — AES-GCM throughput line chart (log x-axis)
// ---------------------------------------------------------------------------

let _tputChart = null;

function _renderThroughput(tp) {
  if (!tp || !tp.results?.length) {
    _show("no-throughput");
    return;
  }
  _hide("no-throughput");

  const results = tp.results;
  const xValues = results.map(r => r.size_bytes);
  const xLabels = results.map(r => r.size_human);
  const encData = results.map(r => ({ x: r.size_bytes, y: r.encrypt_throughput_mbps }));
  const decData = results.map(r => ({ x: r.size_bytes, y: r.decrypt_throughput_mbps }));

  const ctx = _el("chart-throughput").getContext("2d");
  if (_tputChart) _tputChart.destroy();

  _tputChart = new Chart(ctx, {
    type: "line",
    data: {
      datasets: [
        {
          label: "Encrypt MB/s",
          data: encData,
          borderColor: PALETTE.teal,
          backgroundColor: "rgba(34,211,238,0.08)",
          pointBackgroundColor: PALETTE.teal,
          pointRadius: 4,
          tension: 0.3,
          fill: true,
        },
        {
          label: "Decrypt MB/s",
          data: decData,
          borderColor: PALETTE.amber,
          backgroundColor: "rgba(251,191,36,0.08)",
          pointBackgroundColor: PALETTE.amber,
          pointRadius: 4,
          tension: 0.3,
          fill: true,
        },
      ],
    },
    options: _chartDefaults({
      scales: {
        x: {
          ..._chartDefaults().scales.x,
          type: "logarithmic",
          title: { display: true, text: "Message size", color: PALETTE.slate500, font: { size: 10 } },
          ticks: {
            color: PALETTE.slate500,
            font: { size: 10 },
            callback: (val) => {
              const labels = { 64: "64B", 256: "256B", 1024: "1KB",
                               16384: "16KB", 262144: "256KB",
                               1048576: "1MB", 4194304: "4MB" };
              return labels[val] || "";
            },
          },
        },
        y: {
          ..._chartDefaults().scales.y,
          title: { display: true, text: "Throughput (MB/s)", color: PALETTE.slate500, font: { size: 10 } },
          beginAtZero: true,
        },
      },
    }),
  });

  // Summary table
  const tbody = _el("throughput-tbody");
  tbody.innerHTML = "";
  for (const r of results) {
    tbody.insertAdjacentHTML("beforeend", `
      <tr class="border-b border-slate-800">
        <td class="py-0.5 pr-2">${r.size_human}</td>
        <td class="text-right px-1 text-teal-400">${_fmt1(r.encrypt_throughput_mbps)}</td>
        <td class="text-right px-1 text-amber-400">${_fmt1(r.decrypt_throughput_mbps)}</td>
        <td class="text-right px-1">${r.encrypt_mean_ms != null ? r.encrypt_mean_ms.toFixed(4) : "—"}</td>
        <td class="text-right pl-1">${r.decrypt_mean_ms != null ? r.decrypt_mean_ms.toFixed(4) : "—"}</td>
      </tr>`);
  }
  _show("throughput-table");
}

// ---------------------------------------------------------------------------
// §3 — IDS Detection Latency histogram (refreshes every 5 s)
// ---------------------------------------------------------------------------

let _latChart = null;

// Bin boundaries in milliseconds (matching the spec: 0-1s, 1-2s, 2-5s, 5-10s, >10s)
const LAT_BINS = [
  { label: "0 – 1 s",   lo:     0, hi:  1_000 },
  { label: "1 – 2 s",   lo:  1_000, hi:  2_000 },
  { label: "2 – 5 s",   lo:  2_000, hi:  5_000 },
  { label: "5 – 10 s",  lo:  5_000, hi: 10_000 },
  { label: "> 10 s",    lo: 10_000, hi: Infinity },
];

function _renderLatency(lat) {
  if (!lat || lat.count === 0) {
    if (_latChart) { _latChart.destroy(); _latChart = null; }
    _show("no-latency");
    _hide("latency-stats");
    return;
  }
  _hide("no-latency");
  _show("latency-stats");

  // Update stat tiles
  _el("lat-mean").textContent   = lat.mean_ms   != null ? (_fmt1(lat.mean_ms / 1000) + " s") : "—";
  _el("lat-median").textContent = lat.median_ms  != null ? (_fmt1(lat.median_ms / 1000) + " s") : "—";
  _el("lat-min").textContent    = lat.min_ms     != null ? (_fmt1(lat.min_ms / 1000)  + " s") : "—";
  _el("lat-max").textContent    = lat.max_ms     != null ? (_fmt1(lat.max_ms / 1000)  + " s") : "—";

  // Bin the raw measurements
  const measurements = lat.measurements_ms || [];
  const counts = LAT_BINS.map(b =>
    measurements.filter(v => v >= b.lo && v < b.hi).length
  );

  const ctx = _el("chart-latency").getContext("2d");
  if (_latChart) _latChart.destroy();

  _latChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: LAT_BINS.map(b => b.label),
      datasets: [{
        label: `Detection latency (n=${lat.count})`,
        data: counts,
        backgroundColor: "rgba(251,113,133,0.30)",
        borderColor: PALETTE.rose,
        borderWidth: 2,
        borderRadius: 3,
      }],
    },
    options: _chartDefaults({
      scales: {
        ..._chartDefaults().scales,
        y: {
          ..._chartDefaults().scales.y,
          title: { display: true, text: "Count", color: PALETTE.slate500, font: { size: 10 } },
          beginAtZero: true,
          ticks: {
            ..._chartDefaults().scales.y.ticks,
            stepSize: 1,
            precision: 0,
          },
        },
      },
    }),
  });
}

// ---------------------------------------------------------------------------
// §4 — System info + session stats
// ---------------------------------------------------------------------------

function _renderMeta(data) {
  const dl = _el("benchmark-meta");
  dl.innerHTML = "";

  const keTs  = data.key_exchange?.system_info?.timestamp;
  const tpTs  = data.throughput?.system_info?.timestamp;
  const pyVer = data.key_exchange?.system_info?.python_version
             || data.throughput?.system_info?.python_version
             || "—";
  const plat  = (data.key_exchange?.system_info?.platform
              || data.throughput?.system_info?.platform
              || "—").split("-").slice(0, 3).join("-");

  _dtRow(dl, "Benchmarks run",   keTs  ? new Date(keTs).toLocaleString() : "not yet run");
  _dtRow(dl, "Throughput run",   tpTs  ? new Date(tpTs).toLocaleString() : "not yet run");
  _dtRow(dl, "Python",           pyVer);
  _dtRow(dl, "Platform",         plat);
  if (data.key_exchange?.tpm) {
    _dtRow(dl, "TPM runs",       data.key_exchange.tpm.runs);
    _dtRow(dl, "RSA runs",       data.key_exchange.rsa_2048?.runs ?? "—");
    _dtRow(dl, "DH runs",        data.key_exchange.dh_2048?.runs ?? "—");
    _dtRow(dl, "DH param-gen",   `${_fmt0(data.key_exchange.dh_2048?.param_gen_ms_one_time)} ms (one-time)`);
  }

  const sess = data.session || {};
  _el("session-role").textContent = sess.role || "—";

  const dl2 = _el("session-stats");
  dl2.innerHTML = "";
  _dtRow(dl2, "Sync time",       sess.sync_time_ms != null ? `${sess.sync_time_ms} ms` : "not synced");
  _dtRow(dl2, "Sync rounds",     sess.sync_rounds  != null ? sess.sync_rounds : "—");
  _dtRow(dl2, "Messages sent",   sess.messages_encrypted ?? 0);
  const bytesHuman = sess.bytes_encrypted > 0
    ? `${(sess.bytes_encrypted / 1024).toFixed(1)} KB` : "0 B";
  _dtRow(dl2, "Bytes encrypted", bytesHuman);
  if (data.ids_latency) {
    _dtRow(dl2, "IDS samples",   data.ids_latency.count ?? 0);
  }
}

// ---------------------------------------------------------------------------
// Data fetch + render loop
// ---------------------------------------------------------------------------

let _fullData = null;

async function _fetchAndRender(partial = false) {
  try {
    const resp = await fetch("/api/metrics_data");
    if (!resp.ok) return;
    const data = await resp.json();
    _fullData = data;

    if (!partial) {
      // First load: render everything
      const hasKeyEx  = !!data.key_exchange;
      const hasTput   = !!data.throughput;
      const noData    = !hasKeyEx && !hasTput;

      if (noData) _show("no-benchmark-notice");
      else        _hide("no-benchmark-notice");

      _renderKeyExchange(data.key_exchange);
      _renderThroughput(data.throughput);
      _renderMeta(data);
    } else {
      // Partial refresh: IDS latency + session stats only
      _renderMeta(data);
    }

    // IDS latency always refreshes
    _renderLatency(data.ids_latency);

    const now = new Date().toLocaleTimeString();
    _el("last-updated").textContent = `updated ${now}`;
  } catch (_) {
    // Network error or JSON parse error — silently skip this refresh cycle.
  }
}

// Initial full render
_fetchAndRender(false);

// Auto-refresh the live sections (IDS latency + session stats) every 5 s.
setInterval(() => _fetchAndRender(true), 5_000);
