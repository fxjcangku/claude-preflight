"use strict";

(() => {
  const byId = (id) => document.getElementById(id);
  const unknown = "未知";
  const defaultMark = "—";
  const statusText = { pass: "一致", fail: "不一致", unknown: "未确定" };
  const tones = { pass: "good", fail: "warn", unknown: "neutral" };
  const names = typeof Intl.DisplayNames === "function"
    ? new Intl.DisplayNames(["zh-Hans"], { type: "region" }) : null;
  const fullTime = new Intl.DateTimeFormat("zh-Hans", {
    month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false
  });
  const shortTime = new Intl.DateTimeFormat("zh-Hans", {
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false
  });
  const refresh = byId("refresh-button");
  const form = byId("settings-form");
  const submit = form.querySelector("button[type=submit]");
  const countryInput = byId("target-input");
  const timezoneInput = byId("timezone-input");
  const auto = byId("auto-refresh");
  const notice = byId("app-notice");
  let state = null;
  let editing = false;
  let revealIp = false;
  let busy = false;
  let intervalId;
  let browserZone = null;

  function region(code) {
    if (!code) return unknown;
    try { return names?.of(code) || code; } catch { return code; }
  }

  function formattedTime(value, formatter = fullTime) {
    const timestamp = Date.parse(value);
    return Number.isFinite(timestamp) ? formatter.format(timestamp) : defaultMark;
  }

  function zoneOf(timeZone) {
    try { return new Intl.DateTimeFormat("en", { timeZone }).resolvedOptions().timeZone; }
    catch { return null; }
  }

  function compare(actual, expected) {
    if (!actual || !expected) return "unknown";
    return actual === expected ? "pass" : "fail";
  }

  function summary(statuses) {
    if (statuses.includes("fail")) return "fail";
    return statuses.includes("unknown") || !statuses.length ? "unknown" : "pass";
  }

  function node(tag, className, value) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (value !== undefined) element.textContent = value;
    return element;
  }

  function icon(name) {
    const ns = "http://www.w3.org/2000/svg";
    const visual = document.createElementNS(ns, "svg");
    const use = document.createElementNS(ns, "use");
    visual.setAttribute("class", "icon");
    visual.setAttribute("aria-hidden", "true");
    use.setAttribute("href", "#i-" + name);
    visual.append(use);
    return visual;
  }

  function setText(id, text) {
    byId(id).textContent = text ?? defaultMark;
  }

  function lastSample() {
    return state?.history.at(-1);
  }

  function latency(sample) {
    const net = sample?.network;
    return net && !net.error && Number.isFinite(net.latency_ms) && net.latency_ms >= 0
      ? net.latency_ms : null;
  }

  function renderIp() {
    const address = lastSample()?.network?.ip;
    const toggle = byId("ip-toggle");
    toggle.disabled = !address;
    toggle.setAttribute("aria-pressed", String(revealIp));
    toggle.setAttribute("aria-label", revealIp ? "隐藏完整 IP" : "显示完整 IP");
    let visible = defaultMark;
    if (address) {
      if (revealIp) visible = address;
      else if (address.includes(":")) visible = "••••:••••:••••:••••";
      else visible = "•••.•••.•••.•••";
    }
    setText("exit-ip", visible);
  }

  function renderChecks(sample) {
    const container = byId("checks-list");
    const checks = [...(state.assessment?.checks || [])];
    if (sample) {
      const expected = state.target.timezone;
      checks.push({
        key: "browser_timezone", label: "浏览器时区", actual: browserZone,
        expected, status: compare(zoneOf(browserZone || "Invalid"), zoneOf(expected))
      });
    }
    container.replaceChildren();
    if (!checks.length) {
      container.append(node("p", "empty-copy", "运行检测后，这里会显示各项检查结果。"));
      setText("checks-summary", "");
      return;
    }
    const passed = checks.filter(check => check.status === "pass").length;
    setText("checks-summary", passed + " / " + checks.length + " 项一致");
    for (const check of checks) {
      const row = node("div", "check-row");
      row.dataset.tone = tones[check.status] || "neutral";
      const badge = node("span", "check-icon");
      const symbol = check.key.includes("timezone") ? "time" : check.key === "country" ? "route" : "monitor";
      badge.append(icon(symbol));
      const value = check.actual || unknown;
      const copy = node("div", "check-copy");
      const expected = check.expected || unknown;
      copy.append(node("strong", "", check.label), node("small", "", value + " · 目标 " + expected));
      row.append(badge, copy, node("span", "check-state", statusText[check.status] || unknown));
      container.append(row);
    }
  }

  function renderHistory() {
    const items = state.history;
    const target = state.target;
    const list = byId("history-list");
    list.replaceChildren();
    setText("history-summary", items.length ? "按当前目标比较 · " + items.length + " 条" : "");
    for (const sample of [...items].reverse()) {
      const row = node("div", "history-row");
      const time = node("time", "", formattedTime(sample.time));
      time.dateTime = sample.time;
      const net = sample.network;
      const sys = sample.system;
      const statuses = [
        compare(net.country, target.country), compare(sys.region, target.country),
        compare(sys.system_timezone, target.timezone), compare(sys.terminal_timezone, target.timezone)
      ];
      const outcome = summary(statuses);
      const label = node("span", "", statusText[outcome]);
      label.dataset.tone = tones[outcome];
      const ms = latency(sample);
      row.append(time, node("span", "", region(net.country)),
        node("span", "", ms === null ? defaultMark : ms + " ms"), label);
      list.append(row);
    }
    if (!items.length) list.append(node("p", "empty-copy", "暂无检测记录"));
    const values = items.map(latency).filter(value => value !== null);
    setText("history-count", items.length);
    setText("history-low", values.length ? Math.min(...values) + " ms" : defaultMark);
    setText("history-high", values.length ? Math.max(...values) + " ms" : defaultMark);
    byId("history-empty").hidden = values.length > 0;
    if (!values.length) setText("history-empty", items.length ? "暂无成功的延迟样本" : "等待检测数据");
    drawChart();
  }

  function drawChart() {
    const canvas = byId("history-chart");
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    if (width <= 0 || height <= 0) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 3);
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const points = (state?.history || []).map(sample => ({
      t: Date.parse(sample.time), value: latency(sample)
    })).filter(p => Number.isFinite(p.t));
    const values = points.map(p => p.value).filter(value => value !== null);
    const left = 42, right = width - 9, top = 10, bottom = height - 25;
    const max = values.length ? Math.max(...values) : 0;
    const step = 10 ** Math.floor(Math.log10(Math.max(1, max)));
    const ceiling = Math.max(2, Math.ceil(max * 1.06 / (step / 2)) * step / 2);
    const y = value => bottom - (value / ceiling) * (bottom - top);
    ctx.font = '10px Menlo, monospace';
    ctx.textBaseline = "middle";
    for (let tick = 0; tick <= 2; tick++) {
      const n = ceiling * tick / 2;
      const lineY = Math.round(y(n)) + .5;
      ctx.strokeStyle = "#2a373d";
      ctx.lineWidth = 1;
      ctx.setLineDash([3, 4]);
      ctx.beginPath(); ctx.moveTo(left, lineY); ctx.lineTo(right, lineY); ctx.stroke();
      if (values.length) {
        ctx.fillStyle = "#92a3ad"; ctx.textAlign = "right";
        ctx.fillText(n >= 10000 ? (n / 1000).toFixed(0) + "k" : String(Math.round(n)), left - 7, lineY);
      }
    }
    ctx.setLineDash([]);
    if (!values.length || !points.length) return;
    const first = Math.min(...points.map(p => p.t));
    const last = Math.max(...points.map(p => p.t));
    const x = t => last === first ? (left + right) / 2 : left + ((t - first) / (last - first)) * (right - left);
    let segment = [];
    const drawSegment = () => {
      if (!segment.length) return;
      const path = new Path2D();
      segment.forEach((p, i) => i === 0 ? path.moveTo(x(p.t), y(p.value)) : path.lineTo(x(p.t), y(p.value)));
      if (segment.length > 1) {
        const under = new Path2D(path);
        under.lineTo(x(segment.at(-1).t), bottom); under.lineTo(x(segment[0].t), bottom); under.closePath();
        const gradient = ctx.createLinearGradient(0, top, 0, bottom);
        gradient.addColorStop(0, "rgba(140,232,197,.17)"); gradient.addColorStop(1, "rgba(140,232,197,0)");
        ctx.fillStyle = gradient; ctx.fill(under);
        ctx.strokeStyle = "#8ce8c5"; ctx.lineWidth = 2; ctx.lineJoin = "round"; ctx.stroke(path);
      }
      ctx.fillStyle = "#a2f0d2";
      for (const p of segment) {
        ctx.beginPath(); ctx.arc(x(p.t), y(p.value), points.length < 20 ? 3 : 1.6, 0, Math.PI * 2); ctx.fill();
      }
      segment = [];
    };
    for (const point of points) {
      if (point.value === null) drawSegment(); else segment.push(point);
    }
    drawSegment();
    ctx.fillStyle = "#92a3ad";
    ctx.textAlign = first === last ? "center" : "left";
    ctx.fillText(shortTime.format(first), first === last ? x(first) : left, height - 8);
    if (first !== last) { ctx.textAlign = "right"; ctx.fillText(shortTime.format(last), right, height - 8); }
  }

  function render(payload) {
    state = payload;
    const sample = lastSample();
    const net = sample?.network || {};
    const sys = sample?.system || {};
    browserZone = new Intl.DateTimeFormat().resolvedOptions().timeZone || null;
    if (!editing) {
      countryInput.value = state.target.country;
      timezoneInput.value = state.target.timezone;
    }
    setText("last-updated", sample ? formattedTime(sample.time) : "尚未检测");
    if (sample) byId("last-updated").dateTime = sample.time;
    setText("exit-country", net.country ? region(net.country) : sample ? "未确定" : defaultMark);
    const exitResult = compare(net.country, state.target.country);
    const pill = byId("hero-status");
    pill.dataset.tone = tones[exitResult];
    pill.textContent = sample ? ({ pass: "符合目标", fail: "与目标不同", unknown: "无地区数据" })[exitResult] : "待检测";
    let endpoint = "";
    try { endpoint = new URL(net.endpoint).hostname; } catch { /* No endpoint before the first measurement. */ }
    setText("exit-detail", sample ? net.error || [net.country, endpoint].filter(Boolean).join(" · ") : "");
    renderIp();
    const duration = latency(sample);
    setText("latency-value", duration ?? defaultMark);
    setText("latency-detail", net.error ? "探测未完成" : net.http_status ? "HTTP " + net.http_status : "");
    setText("system-timezone", sys.system_timezone);
    setText("browser-timezone", browserZone);
    setText("auto-timezone", sys.auto_timezone === true ? "已开启" : sys.auto_timezone === false ? "已关闭" : null);
    setText("route-detail", net.route);
    setText("proxy-detail", sys.proxy_summary || (sys.proxy_enabled === true ? "已启用" : sys.proxy_enabled === false ? "未启用" : null));
    setText("language-detail", sys.language || sys.locale);
    setText("cli-detail", sys.claude_available === true ? "已找到" : sys.claude_available === false ? "未找到" : null);
    renderChecks(sample);
    renderHistory();
    if (typeof window.drawPreflightGlobe === "function") window.drawPreflightGlobe(net.country || null);
  }

  function markService(text, tone) {
    const label = byId("service-state");
    label.textContent = text;
    label.dataset.tone = tone;
  }

  function showMessage(message) {
    notice.textContent = message;
    notice.hidden = !message;
  }

  async function request(path, body) {
    const options = { cache: "no-store" };
    if (body !== undefined) {
      options.method = "POST";
      options.headers = { "Content-Type": "application/json" };
      options.body = JSON.stringify(body);
    }
    options.signal = AbortSignal.timeout(30000);
    const response = await fetch(path, options);
    const data = await response.json().catch(() => null);
    if (!response.ok) throw new Error(data?.error || "请求失败（HTTP " + response.status + "）");
    if (!data || !Array.isArray(data.history) || !data.target) throw new Error("本机服务返回的数据格式无效");
    return data;
  }

  function lock(action) {
    busy = Boolean(action);
    refresh.disabled = busy;
    submit.disabled = busy;
    const checking = action === "check";
    refresh.setAttribute("aria-busy", String(checking));
    refresh.querySelector("span").textContent = checking ? "检测中…" : "立即检测";
    if (checking) markService("正在检测", "neutral");
  }

  async function check() {
    if (busy) return;
    lock("check");
    showMessage("");
    try {
      render(await request("/api/check", {}));
      markService("已连接", "good");
    } catch (error) {
      markService("检测请求失败", "bad");
      showMessage("检测未完成。" + error.message + "。请确认本机服务正在运行，然后重试。");
    } finally { lock(null); }
  }

  async function load() {
    lock("load");
    try {
      render(await request("/api/state"));
      markService("已连接", "good");
    } catch (error) {
      markService("连接失败", "bad");
      showMessage("无法读取本机状态。" + error.message + "。可点击「立即检测」重试。");
    } finally { lock(null); }
    if (state && !state.history.length) await check();
  }

  form.addEventListener("input", () => {
    editing = true;
    setText("settings-status", "有未保存的修改");
    byId("settings-status").dataset.tone = "neutral";
  });
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (busy || !form.reportValidity()) return;
    const originalCountry = countryInput.value, originalZone = timezoneInput.value;
    const target = { country: originalCountry.trim().toUpperCase(), timezone: originalZone.trim() };
    lock("save");
    try {
      const payload = await request("/api/settings", target);
      const changed = originalCountry !== countryInput.value || originalZone !== timezoneInput.value;
      editing = changed;
      render(payload);
      markService("已连接", "good");
      showMessage("");
      setText("settings-status", changed ? "先前的设置已保存，当前输入仍有修改。" : "已保存检测目标。");
      byId("settings-status").dataset.tone = "good";
    } catch (error) {
      setText("settings-status", error.message);
      byId("settings-status").dataset.tone = "bad";
    } finally { lock(null); }
  });
  refresh.addEventListener("click", check);
  byId("ip-toggle").addEventListener("click", () => { revealIp = !revealIp; renderIp(); });
  function schedule() {
    clearInterval(intervalId);
    if (auto.checked) intervalId = window.setInterval(check, 60000);
  }
  try { auto.checked = localStorage.getItem("preflight.auto") === "1"; } catch { /* Storage is optional. */ }
  auto.addEventListener("change", () => {
    try { localStorage.setItem("preflight.auto", auto.checked ? "1" : "0"); } catch { /* No persistence. */ }
    schedule();
  });
  schedule();
  const anchors = [...document.querySelectorAll('.primary-nav a[href^="#"]')];
  function updateNav() {
    let active = anchors[0];
    const margin = window.innerWidth <= 710 ? 85 : 65;
    for (const anchor of anchors.slice(1)) {
      if (document.querySelector(anchor.hash).getBoundingClientRect().top <= margin) active = anchor;
    }
    const nearEnd = window.scrollY > 0 && window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 3;
    if (nearEnd && location.hash !== "#history") active = anchors.at(-1);
    for (const anchor of anchors) {
      anchor.classList.toggle("is-active", anchor === active);
      if (anchor === active) anchor.setAttribute("aria-current", "location");
      else anchor.removeAttribute("aria-current");
    }
  }
  window.addEventListener("scroll", updateNav, { passive: true });
  window.addEventListener("hashchange", updateNav);
  if ("ResizeObserver" in window) new ResizeObserver(drawChart).observe(byId("history-chart").parentElement);
  else window.addEventListener("resize", drawChart);
  updateNav();
  load();
})();
