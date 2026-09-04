/* ============================================================
   SentraNet Engine — logika bersama untuk semua halaman.
   Satu sumber kebenaran untuk: model aktif, inference, statistik,
   feed simulasi, dan alert log. Disimpan di localStorage supaya
   nilai tetap konsisten saat berpindah halaman (tanpa backend).
   ============================================================ */
(function (global) {
  "use strict";

  const NS = "sentranet_v2";
  const K_STATE = NS + "_state";
  const K_MODEL = NS + "_model";
  const K_SOURCE = NS + "_model_source";

  const CATS = [
    "SYN Flood (DoS)",
    "Port Scan (Probe)",
    "Brute Force (R2L)",
    "DDoS Burst",
    "Botnet C2 Beacon",
    "Anomali Lain"
  ];

  const SEVERITY_MAP = {
    "SYN Flood (DoS)": "CRITICAL",
    "DDoS Burst": "CRITICAL",
    "Brute Force (R2L)": "HIGH",
    "Botnet C2 Beacon": "HIGH",
    "Port Scan (Probe)": "MEDIUM",
    "Anomali Lain": "LOW"
  };

  const PATTERN_TEXT = {
    "SYN Flood (DoS)": "Possible SYN Flood / DoS",
    "DDoS Burst": "Possible DDoS Burst",
    "Port Scan (Probe)": "Possible Port Scan / Probe",
    "Brute Force (R2L)": "Possible Brute Force / R2L",
    "Botnet C2 Beacon": "Possible Botnet C2 Beacon",
    "Anomali Lain": "Pola tidak cocok dengan kategori yang dikenal"
  };

  const METRIC_TOOLTIPS = {
    accuracy: "Persentase prediksi yang benar dari seluruh sampel.",
    precision: "Seberapa sering prediksi attack benar-benar merupakan attack.",
    recall: "Seberapa banyak attack sungguhan yang berhasil terdeteksi.",
    f1: "Rata-rata harmonik precision dan recall — keseimbangan keduanya.",
    roc_auc: "Kemampuan model membedakan normal vs attack pada berbagai threshold."
  };

  /* ---------- DEFAULT (BASELINE) MODEL — jujur, belum dilatih ---------- */
  const DEFAULT_MODEL = {
    meta: {
      name: "baseline-heuristic-v1",
      model_type: "Logistic Regression (heuristic baseline)",
      dataset: "Not trained on real dataset",
      training_date: null,
      evaluation_status: "Not evaluated",
      evaluation_scope: null,
      threshold: 0.5,
      accuracy: null,
      precision: null,
      recall: null,
      f1: null,
      roc_auc: null,
      test_samples: null,
      dataset_metrics: null
    },
    numeric_features: ["duration", "src_bytes", "dst_bytes", "count", "srv_count", "serror_rate", "same_srv_rate"],
    scaler_mean: [1.2, 4.8, 5.2, 1.0, 1.0, 0.15, 0.75],
    scaler_std: [1.8, 2.6, 2.9, 1.1, 1.0, 0.30, 0.30],
    categorical: {
      protocol_type: ["tcp", "udp", "icmp"],
      service: ["http", "ftp", "smtp", "other"],
      flag: ["SF", "S0", "REJ", "other"]
    },
    weights: [
      0.55, 1.35, 0.55, 1.25, 1.05, 3.10, 0.85,
      0.10, -0.05, 0.35,
      0.15, -0.10, -0.05, 0.30,
      -2.00, 2.55, 1.45, 0.20
    ],
    bias: -2.4
  };

  let ACTIVE_MODEL = null;
  let MODEL_SOURCE = "baseline"; // 'baseline' | 'uploaded'
  let lastLatencyMs = 0;
  const subscribers = [];

  /* ---------------------- persistence ---------------------- */
  function defaultState() {
    const catCounts = {};
    CATS.forEach((c) => (catCounts[c] = 0));
    return {
      totalCount: 0,
      attackCount: 0,
      normalCount: 0,
      catCounts,
      timeline: [],
      alerts: [],
      feed: [],
      feedRunning: true
    };
  }

  function loadState() {
    try {
      const raw = localStorage.getItem(K_STATE);
      if (!raw) return defaultState();
      const parsed = JSON.parse(raw);
      const base = defaultState();
      return Object.assign(base, parsed, { catCounts: Object.assign(base.catCounts, parsed.catCounts || {}) });
    } catch (e) {
      return defaultState();
    }
  }

  function saveState(state) {
    try {
      localStorage.setItem(K_STATE, JSON.stringify(state));
    } catch (e) {
      /* storage full or unavailable — fail silently, dashboard keeps running in-memory */
    }
    subscribers.forEach((fn) => {
      try {
        fn(state);
      } catch (err) {
        console.error("SentraNet subscriber error:", err);
      }
    });
  }

  function loadModel() {
    try {
      const raw = localStorage.getItem(K_MODEL);
      const src = localStorage.getItem(K_SOURCE);
      if (raw) {
        ACTIVE_MODEL = JSON.parse(raw);
        MODEL_SOURCE = src === "uploaded" ? "uploaded" : "baseline";
        return;
      }
    } catch (e) {
      /* fall through to baseline */
    }
    ACTIVE_MODEL = JSON.parse(JSON.stringify(DEFAULT_MODEL));
    MODEL_SOURCE = "baseline";
  }

  function saveModel(model, source) {
    ACTIVE_MODEL = model;
    MODEL_SOURCE = source;
    try {
      localStorage.setItem(K_MODEL, JSON.stringify(model));
      localStorage.setItem(K_SOURCE, source);
    } catch (e) {
      /* ignore quota errors */
    }
  }

  function resetModel() {
    saveModel(JSON.parse(JSON.stringify(DEFAULT_MODEL)), "baseline");
  }

  /* ---------------------- inference ---------------------- */
  function sigmoid(z) {
    return 1 / (1 + Math.exp(-z));
  }

  function computeDerived(sample) {
    const eps = 1e-3;
    const bytes_per_sec = (sample.src_bytes + sample.dst_bytes) / (sample.duration + eps);
    const pkts_per_sec = (sample.count + sample.srv_count) / (sample.duration + eps);
    const byte_asymmetry = sample.dst_bytes / (sample.src_bytes + sample.dst_bytes + 1);
    return { bytes_per_sec, pkts_per_sec, byte_asymmetry };
  }

  const FEATURE_SOURCES = {
    duration: (s) => s.duration,
    src_bytes: (s) => s.src_bytes,
    dst_bytes: (s) => s.dst_bytes,
    count: (s) => s.count,
    srv_count: (s) => s.srv_count,
    serror_rate: (s) => s.serror_rate ?? 0,
    same_srv_rate: (s) => s.same_srv_rate ?? 1,
    bytes_per_sec: (s) => computeDerived(s).bytes_per_sec,
    pkts_per_sec: (s) => computeDerived(s).pkts_per_sec,
    byte_asymmetry: (s) => computeDerived(s).byte_asymmetry
  };
  const LOG_FEATURES = new Set(["duration", "src_bytes", "dst_bytes", "count", "srv_count", "bytes_per_sec", "pkts_per_sec"]);

  function preprocess(sample, model) {
    const feats = model.numeric_features || DEFAULT_MODEL.numeric_features;
    const numeric = feats.map((name, i) => {
      const getter = FEATURE_SOURCES[name];
      const raw = getter ? getter(sample) : 0;
      const t = LOG_FEATURES.has(name) ? Math.log1p(Math.max(0, raw)) : raw;
      const mean = model.scaler_mean && model.scaler_mean[i] !== undefined ? model.scaler_mean[i] : 0;
      const std = model.scaler_std && model.scaler_std[i] ? model.scaler_std[i] : 1;
      return (t - mean) / std;
    });
    const proto = model.categorical.protocol_type.map((c) => (c === sample.protocol_type ? 1 : 0));
    const service = model.categorical.service.map((c) => (c === sample.service ? 1 : 0));
    if (service.every((x) => x === 0)) service[service.length - 1] = 1;
    const flag = model.categorical.flag.map((c) => (c === sample.flag ? 1 : 0));
    if (flag.every((x) => x === 0)) flag[flag.length - 1] = 1;
    return [...numeric, ...proto, ...service, ...flag];
  }

  function getThreshold() {
    const t = ACTIVE_MODEL && ACTIVE_MODEL.meta && ACTIVE_MODEL.meta.threshold;
    return typeof t === "number" && isFinite(t) ? t : 0.5;
  }

  function predict(sample, model) {
    model = model || ACTIVE_MODEL;
    const t0 = performance.now();
    const x = preprocess(sample, model);
    let z = model.bias;
    for (let i = 0; i < x.length && i < model.weights.length; i++) z += x[i] * model.weights[i];
    const p = sigmoid(z);
    lastLatencyMs = performance.now() - t0;
    return { probAttack: p, isAttack: p >= getThreshold() };
  }

  function classifyCategory(sample, p) {
    if (p < getThreshold()) return "Normal";
    if (sample.serror_rate > 0.5 || (sample.flag === "S0" && sample.count > 10)) {
      return sample.count > 50 ? "DDoS Burst" : "SYN Flood (DoS)";
    }
    if (sample.count > 8 && sample.serror_rate < 0.3) return "Port Scan (Probe)";
    if ((sample.service === "ftp" || sample.service === "smtp") && sample.flag !== "SF") return "Brute Force (R2L)";
    if (sample.duration > 10 && sample.count <= 1 && sample.flag === "SF") return "Botnet C2 Beacon";
    return "Anomali Lain";
  }

  function severityFor(category, prob) {
    let base = SEVERITY_MAP[category] || "MEDIUM";
    if (base === "LOW" && prob >= 0.85) base = "MEDIUM";
    return base;
  }

  function patternFor(category) {
    return PATTERN_TEXT[category] || "Pola tidak dikenal";
  }

  /* ---------------------- weights.json validation ---------------------- */
  function validateWeights(m) {
    if (typeof m !== "object" || m === null || Array.isArray(m)) {
      return { valid: false, reason: "File bukan JSON object yang valid." };
    }
    if (!Array.isArray(m.weights) || m.weights.length === 0) {
      return { valid: false, reason: "Missing required field: weights" };
    }
    if (m.weights.some((w) => typeof w !== "number" || !isFinite(w))) {
      return { valid: false, reason: "weights mengandung nilai non-angka (NaN/Infinity)." };
    }
    if (typeof m.bias !== "number" || !isFinite(m.bias)) {
      return { valid: false, reason: "Missing required field: bias" };
    }
    if (!Array.isArray(m.numeric_features) || m.numeric_features.length === 0) {
      return { valid: false, reason: "Missing required field: numeric_features" };
    }
    if (
      !m.categorical ||
      !Array.isArray(m.categorical.protocol_type) ||
      !Array.isArray(m.categorical.service) ||
      !Array.isArray(m.categorical.flag)
    ) {
      return { valid: false, reason: "Missing required field: categorical (protocol_type/service/flag)" };
    }
    const totalDims =
      m.numeric_features.length + m.categorical.protocol_type.length + m.categorical.service.length + m.categorical.flag.length;
    if (m.weights.length < totalDims) {
      return {
        valid: false,
        reason: `Jumlah weights (${m.weights.length}) tidak cukup untuk jumlah fitur (${totalDims}).`
      };
    }
    if (m.scaler_mean && m.scaler_mean.length !== m.numeric_features.length) {
      return { valid: false, reason: "scaler_mean length tidak cocok dengan numeric_features." };
    }
    if (m.scaler_std && m.scaler_std.length !== m.numeric_features.length) {
      return { valid: false, reason: "scaler_std length tidak cocok dengan numeric_features." };
    }
    if (!m.meta || typeof m.meta !== "object") {
      m.meta = {};
    }
    return { valid: true };
  }

  /* ---------------------- IP simulation (private ranges only) ---------------------- */
  function rnd(n) {
    return Math.floor(Math.random() * n);
  }
  function randIP() {
    const r = Math.random();
    if (r < 0.5) return `10.${rnd(255)}.${rnd(255)}.${rnd(254) + 1}`;
    if (r < 0.8) return `192.168.${rnd(255)}.${rnd(254) + 1}`;
    return `172.16.${rnd(31)}.${rnd(254) + 1}`;
  }

  /* ---------------------- sample generation ---------------------- */
  function genRandomSample() {
    const isSuspicious = Math.random() < 0.28;
    if (isSuspicious) {
      const kind = Math.random();
      if (kind < 0.4) {
        return {
          duration: 0, protocol_type: "tcp", service: "other", flag: "S0", src_bytes: 0, dst_bytes: 0,
          count: 20 + Math.floor(Math.random() * 40), srv_count: 15 + Math.floor(Math.random() * 40),
          serror_rate: 0.7 + Math.random() * 0.3, same_srv_rate: Math.random() * 0.3
        };
      } else if (kind < 0.75) {
        return {
          duration: 0, protocol_type: "tcp", service: "other", flag: "REJ", src_bytes: Math.random() * 50, dst_bytes: 0,
          count: 10 + Math.floor(Math.random() * 30), srv_count: 8 + Math.floor(Math.random() * 30),
          serror_rate: 0.2 + Math.random() * 0.4, same_srv_rate: Math.random() * 0.2
        };
      } else {
        return {
          duration: 1 + Math.random() * 3, protocol_type: "tcp", service: Math.random() < 0.5 ? "ftp" : "smtp", flag: "S0",
          src_bytes: 20 + Math.random() * 40, dst_bytes: 0,
          count: 5 + Math.floor(Math.random() * 10), srv_count: 5 + Math.floor(Math.random() * 10),
          serror_rate: 0.3 + Math.random() * 0.3, same_srv_rate: 0.6 + Math.random() * 0.3
        };
      }
    }
    const services = ["http", "ftp", "smtp", "other"];
    return {
      duration: Math.floor(Math.random() * 40), protocol_type: "tcp", service: services[Math.floor(Math.random() * services.length)],
      flag: "SF", src_bytes: Math.floor(Math.random() * 2000), dst_bytes: Math.floor(Math.random() * 3000),
      count: 1 + Math.floor(Math.random() * 4), srv_count: 1 + Math.floor(Math.random() * 4),
      serror_rate: Math.random() * 0.1, same_srv_rate: 0.8 + Math.random() * 0.2
    };
  }

  /* ---------------------- attack simulator profiles ---------------------- */
  const ATTACK_PROFILES = {
    synflood: {
      icon: "🔥", label: "SYN Flood (DoS)", category: "SYN Flood (DoS)",
      desc: "Banyak koneksi TCP setengah-terbuka dalam waktu singkat.",
      gen: () => ({
        duration: 0, protocol_type: "tcp", service: "other", flag: "S0", src_bytes: 0, dst_bytes: 0,
        count: 20 + Math.floor(Math.random() * 30), srv_count: 15 + Math.floor(Math.random() * 30),
        serror_rate: 0.7 + Math.random() * 0.3, same_srv_rate: Math.random() * 0.3
      })
    },
    portscan: {
      icon: "🔍", label: "Port Scan (Probe)", category: "Port Scan (Probe)",
      desc: "Banyak koneksi ke port berbeda, kebanyakan ditolak.",
      gen: () => ({
        duration: 0, protocol_type: "tcp", service: "other", flag: "REJ", src_bytes: Math.random() * 20, dst_bytes: 0,
        count: 10 + Math.floor(Math.random() * 25), srv_count: 8 + Math.floor(Math.random() * 25),
        serror_rate: 0.2 + Math.random() * 0.4, same_srv_rate: Math.random() * 0.2
      })
    },
    bruteforce: {
      icon: "🔑", label: "Brute Force (R2L)", category: "Brute Force (R2L)",
      desc: "Percobaan login berulang ke service FTP/SMTP.",
      gen: () => ({
        duration: 1 + Math.random() * 3, protocol_type: "tcp", service: "ftp", flag: "S0", src_bytes: 20 + Math.random() * 40, dst_bytes: 0,
        count: 5 + Math.floor(Math.random() * 10), srv_count: 5 + Math.floor(Math.random() * 10),
        serror_rate: 0.3 + Math.random() * 0.3, same_srv_rate: 0.6 + Math.random() * 0.3
      })
    },
    ddos: {
      icon: "⚡", label: "DDoS Burst", category: "DDoS Burst",
      desc: "Volume trafik masif dari banyak arah sekaligus.",
      gen: () => ({
        duration: 0, protocol_type: Math.random() < 0.5 ? "udp" : "tcp", service: "other", flag: "S0", src_bytes: Math.random() * 10, dst_bytes: 0,
        count: 60 + Math.floor(Math.random() * 120), srv_count: 50 + Math.floor(Math.random() * 120),
        serror_rate: 0.8 + Math.random() * 0.2, same_srv_rate: Math.random() * 0.15
      })
    },
    botnet: {
      icon: "🕸️", label: "Botnet C2 Beacon", category: "Botnet C2 Beacon",
      desc: "Koneksi periodik berdurasi wajar ke host command-and-control.",
      gen: () => ({
        duration: 15 + Math.random() * 40, protocol_type: "tcp", service: "other", flag: "SF", src_bytes: 40 + Math.random() * 80, dst_bytes: 20 + Math.random() * 40,
        count: 1, srv_count: 1, serror_rate: 0.05, same_srv_rate: 0.9
      })
    },
    mixed: {
      icon: "🌪️", label: "Gelombang Campuran", category: null,
      desc: "Kombinasi acak dari semua profil di atas — skenario paling realistis.",
      gen: () => {
        const keys = ["synflood", "portscan", "bruteforce", "ddos", "botnet"];
        const k = keys[Math.floor(Math.random() * keys.length)];
        return ATTACK_PROFILES[k].gen();
      }
    }
  };

  /* ---------------------- alert grouping ---------------------- */
  const GROUP_WINDOW_MS = 25000;

  function pushAlertGrouped(state, category, prob, sample, timeNow) {
    const severity = severityFor(category, prob);
    const timeStr = new Date(timeNow).toLocaleTimeString("id-ID");
    let group = state.alerts.find((a) => a.category === category && timeNow - a.lastSeenTs < GROUP_WINDOW_MS);
    if (group) {
      group.count++;
      group.lastSeen = timeStr;
      group.lastSeenTs = timeNow;
      group.lastProb = prob;
      group.severity = severity;
      group.events.unshift({ time: timeStr, prob, meta: `${sample.protocol_type}/${sample.service} · flag ${sample.flag}` });
      if (group.events.length > 6) group.events.length = 6;
    } else {
      group = {
        id: "al_" + timeNow + "_" + Math.random().toString(36).slice(2, 7),
        category,
        severity,
        count: 1,
        firstSeen: timeStr,
        lastSeen: timeStr,
        lastSeenTs: timeNow,
        lastProb: prob,
        status: "ACTIVE",
        events: [{ time: timeStr, prob, meta: `${sample.protocol_type}/${sample.service} · flag ${sample.flag}` }]
      };
      state.alerts.unshift(group);
      if (state.alerts.length > 100) state.alerts.length = 100;
    }
  }

  /* ---------------------- registration (shared by feed/test/simulator) ---------------------- */
  function registerDetection(sample, probAttack, isAttack, categoryOverride) {
    const state = loadState();
    const now = Date.now();
    const category = isAttack ? categoryOverride || classifyCategory(sample, probAttack) : null;

    state.totalCount++;
    if (isAttack) {
      state.attackCount++;
      if (state.catCounts[category] === undefined) state.catCounts[category] = 0;
      state.catCounts[category]++;
      pushAlertGrouped(state, category, probAttack, sample, now);
    } else {
      state.normalCount++;
    }

    state.timeline.push({ normal: isAttack ? 0 : 1, attack: isAttack ? 1 : 0 });
    if (state.timeline.length > 20) state.timeline.shift();

    state.feed.push({
      time: new Date(now).toLocaleTimeString("id-ID"),
      ip: randIP(),
      service: sample.service,
      flag: sample.flag,
      isAttack,
      category,
      prob: probAttack
    });
    if (state.feed.length > 30) state.feed.shift();

    saveState(state);
    return { category, severity: isAttack ? severityFor(category, probAttack) : null };
  }

  function resetSession() {
    saveState(defaultState());
  }

  function onUpdate(fn) {
    subscribers.push(fn);
  }

  function getLastLatencyMs() {
    return lastLatencyMs;
  }

  loadModel();

  global.SentraNet = {
    CATS,
    SEVERITY_MAP,
    METRIC_TOOLTIPS,
    ATTACK_PROFILES,
    DEFAULT_MODEL,
    getModel: () => ACTIVE_MODEL,
    getModelSource: () => MODEL_SOURCE,
    saveModel,
    resetModel,
    loadModel,
    predict,
    classifyCategory,
    severityFor,
    patternFor,
    validateWeights,
    randIP,
    genRandomSample,
    registerDetection,
    resetSession,
    loadState,
    saveState,
    onUpdate,
    getLastLatencyMs,
    getThreshold
  };
})(window);
