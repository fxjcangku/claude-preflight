"use strict";

(() => {
  const byId = (id) => document.getElementById(id);
  const unknown = "未知";
  const defaultMark = "—";
  const statusText = { pass: "一致", fail: "不一致", unknown: "未确定" };
  const tones = { pass: "good", fail: "bad", unknown: "neutral" };
  const readyText = { ok: "已就绪", pending: "待配置/批准", error: "未通过", unknown: "未知" };
  const readyTone = { ok: "good", pending: "pending", error: "bad", unknown: "neutral" };
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
  const clientNames = { web: "专用网页", desktop: "受管桌面版" };
  const submittingClients = new Set();
  let launchPoll, launchRevision = 0;
  let state = null;
  let readiness = null;
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

  function countryFlag(code) {
    if (!/^[A-Z]{2}$/.test(code || "") || code === "ZZ") return "";
    return String.fromCodePoint(...Array.from(code, letter => 0x1f1e6 + letter.charCodeAt(0) - 65));
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
    const el = byId(id);
    if (el) el.textContent = text ?? defaultMark;
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
    const copyBtn = byId("ip-copy");
    toggle.disabled = !address;
    if (copyBtn) copyBtn.disabled = !address;
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

  function makeRcRow(label, value, tone = "neutral") {
    const li = document.createElement("li");
    const k = document.createElement("span");
    k.textContent = label;
    const v = document.createElement("strong");
    v.textContent = value;
    v.dataset.tone = tone;
    li.append(k, v);
    return li;
  }

  function renderReadiness(data) {
    readiness = data;
    if (!data) return;

    const overall = byId("readiness-overall");
    if (overall) {
      overall.dataset.tone = readyTone[data.overall] || "neutral";
      overall.textContent = readyText[data.overall] || "未知";
    }

    // Top VPN status card
    const vpn = data.vpn || {};
    const vpnPill = byId("vpn-status-pill");
    if (vpnPill) {
      vpnPill.dataset.tone = readyTone[vpn.state] || "neutral";
      vpnPill.textContent = vpn.state === "ok" ? "已连接" : vpn.state === "pending" ? "待配置" : vpn.state === "error" ? "异常" : "未知";
    }
    const appTitle = vpn.activeApp
      ? (vpn.running ? `${vpn.activeApp} · 运行中` : `${vpn.activeApp} · 未运行`)
      : (vpn.proxyReady || vpn.tunnelReady ? "系统 VPN / 代理" : "未检测到 VPN");
    setText("vpn-app-name", appTitle);
    setText("vpn-proxy-chip", vpn.proxyAddress || (vpn.tunnelReady ? `TUN (${(vpn.tunnels || []).length})` : "无代理"));
    setText("vpn-summary", vpn.detail || "自动检测本机 VPN 客户端与代理状态");

    // 1. VPN Readiness Card
    const rcVpn = byId("rc-vpn");
    const rcVpnList = byId("rc-vpn-list");
    if (rcVpn && rcVpnList) {
      rcVpn.dataset.tone = readyTone[vpn.state] || "neutral";
      setText("rc-vpn-badge", readyText[vpn.state] || "未知");
      const apps = Array.isArray(vpn.detectedApps) ? vpn.detectedApps : [];
      const appNames = apps.length ? apps.map(a => a.name).slice(0, 2).join(" / ") : "未发现";
      rcVpnList.replaceChildren(
        makeRcRow("客户端", appNames, apps.length ? "good" : "bad"),
        makeRcRow("代理 / 隧道", vpn.proxyAddress || (vpn.tunnelReady ? "TUN 已启用" : "未就绪"),
          (vpn.proxyReady || vpn.tunnelReady) ? "good" : "bad"),
        makeRcRow("台湾候选节点", vpn.taiwanCandidates > 0 ? `${vpn.taiwanCandidates} 个` : (vpn.onevpnInstalled ? "未找到" : "以实测为准"),
          vpn.taiwanCandidates > 0 ? "good" : (vpn.onevpnInstalled ? "bad" : "neutral")),
        makeRcRow("Claude 分流", vpn.onevpnInstalled
          ? (vpn.claudeRulesReady ? `${vpn.claudeRulesCount}/6 已就绪` : `${vpn.claudeRulesCount}/6 待配置`)
          : "由当前 VPN 路由",
          vpn.onevpnInstalled ? (vpn.claudeRulesReady ? "good" : "pending") : "neutral")
      );
    }

    // 2. Claude Readiness Card
    const claude = data.claude || {};
    const rcClaude = byId("rc-claude");
    const rcClaudeList = byId("rc-claude-list");
    if (rcClaude && rcClaudeList) {
      rcClaude.dataset.tone = readyTone[claude.state] || "neutral";
      setText("rc-claude-badge", readyText[claude.state] || "未知");
      const proxyLabel = claude.proxyState === "ready" ? "已导入生效"
        : claude.proxyState === "conflict" ? "存在冲突" : "未安装";
      const proxyTone = claude.proxyState === "ready" ? "good"
        : claude.proxyState === "conflict" ? "bad" : "pending";
      const watcherOn = claude.watcher && claude.watcher.installed && claude.watcher.loaded && claude.watcher.running;
      rcClaudeList.replaceChildren(
        makeRcRow("桌面版", claude.installed ? (claude.running ? "已安装 · 运行中" : "已安装") : "未安装",
          claude.installed ? "good" : "bad"),
        makeRcRow("本地登录态", claude.sessionDetected ? "已检测到会话" : "未检测到",
          claude.sessionDetected ? "good" : "neutral"),
        makeRcRow("代理描述文件", proxyLabel, proxyTone),
        makeRcRow("Dock 监护", watcherOn ? "运行中" : "未启用", watcherOn ? "good" : "pending")
      );
    }

    // 3. LuLu Readiness Card
    const lulu = data.lulu || {};
    const rcLulu = byId("rc-lulu");
    const rcLuluList = byId("rc-lulu-list");
    if (rcLulu && rcLuluList) {
      rcLulu.dataset.tone = readyTone[lulu.state] || "neutral";
      setText("rc-lulu-badge", readyText[lulu.state] || "未知");
      rcLuluList.replaceChildren(
        makeRcRow("安装版本", lulu.installed ? (lulu.version || "已安装") : "未安装", lulu.installed ? "good" : "bad"),
        makeRcRow("扩展与过滤器", (lulu.extensionReady && lulu.socketFilterReady) ? "已批准启用" : "待系统批准",
          (lulu.extensionReady && lulu.socketFilterReady) ? "good" : "pending"),
        makeRcRow("全局例外开关", lulu.prefsReady ? "已安全关闭" : "待关闭", lulu.prefsReady ? "good" : "pending"),
        makeRcRow("Claude 规则", lulu.conflict ? "存在冲突" : (lulu.rulesReady ? "拦截 + 47836" : "待合并导入"),
          lulu.conflict ? "bad" : (lulu.rulesReady ? "good" : "pending"))
      );
    }

    // 4. Region & Timezone Readiness Card
    const reg = data.region || {};
    const rcRegion = byId("rc-region");
    const rcRegionList = byId("rc-region-list");
    if (rcRegion && rcRegionList) {
      rcRegion.dataset.tone = readyTone[reg.state] || "neutral";
      setText("rc-region-badge", readyText[reg.state] || "未知");
      const backups = data.backups || {};
      rcRegionList.replaceChildren(
        makeRcRow("本机地区", reg.locale || unknown, reg.locale && reg.locale.includes("TW") ? "good" : "pending"),
        makeRcRow("系统时区", reg.timezone || unknown, reg.timezone === "Asia/Taipei" ? "good" : "pending"),
        makeRcRow("自动更新时区", reg.autoTimezone === false ? "已关闭" : reg.autoTimezone === true ? "已开启" : unknown,
          reg.autoTimezone === false ? "good" : reg.autoTimezone === true ? "pending" : "neutral"),
        makeRcRow("复原备份", backups.any ? "已保存基线" : "暂无改动", backups.any ? "good" : "neutral")
      );
    }
  }

  function renderTripleAlignment(sample) {
    const bar = byId("triple-alignment");
    const badge = byId("alignment-badge");
    if (!bar) return;
    if (!sample) {
      bar.dataset.tone = "neutral";
      setText("tri-exit", "待检测");
      setText("tri-region", "待检测");
      setText("tri-timezone", "待检测");
      setText("tri-verdict", "等待实测核验");
      if (badge) { badge.dataset.tone = "neutral"; badge.textContent = "待质检"; }
      return;
    }
    const net = sample.network || {};
    const sys = sample.system || {};
    const target = state.target;
    const exitFlag = countryFlag(net.country);
    setText("tri-exit", net.country ? `${exitFlag} ${region(net.country)} (${net.country})` : "未确定");
    setText("tri-region", sys.region ? `${countryFlag(sys.region)} ${sys.region}` : unknown);
    const zoneMatch = compare(sys.system_timezone, target.timezone) === "pass"
      && compare(sys.terminal_timezone, target.timezone) === "pass"
      && compare(zoneOf(browserZone || "Invalid"), zoneOf(target.timezone)) === "pass";
    setText("tri-timezone", sys.system_timezone ? (zoneMatch ? `${sys.system_timezone} (三端一致)` : `${sys.system_timezone}`) : unknown);

    const exitOk = compare(net.country, target.country);
    const regionOk = compare(sys.region, target.country);
    const tzOk = summary([
      compare(sys.system_timezone, target.timezone),
      compare(sys.terminal_timezone, target.timezone),
      compare(zoneOf(browserZone || "Invalid"), zoneOf(target.timezone)),
    ]);
    const allStatus = summary([exitOk, regionOk, tzOk]);
    bar.dataset.tone = tones[allStatus];
    if (allStatus === "pass") {
      setText("tri-verdict", "✅ 三方一致 · 通过台湾质检");
      if (badge) { badge.dataset.tone = "good"; badge.textContent = "🇹🇼 三方一致 · 通过"; }
    } else if (allStatus === "fail") {
      const reasons = [];
      if (exitOk === "fail") reasons.push(`出口为 ${net.country}`);
      if (regionOk === "fail") reasons.push(`地区为 ${sys.region}`);
      if (tzOk === "fail") reasons.push("时区不一致");
      setText("tri-verdict", "❌ 质检不符：" + reasons.join(" / "));
      if (badge) { badge.dataset.tone = "bad"; badge.textContent = "三方不一致"; }
    } else {
      setText("tri-verdict", "⚪ 存在未知项，请重新检测");
      if (badge) { badge.dataset.tone = "neutral"; badge.textContent = "结果未知"; }
    }
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
      const actualDisplay = check.key === "country" && check.actual
        ? `${countryFlag(check.actual)} ${region(check.actual)} (${check.actual})`
        : (check.actual || unknown);
      const copy = node("div", "check-copy");
      const expected = check.expected || unknown;
      copy.append(node("strong", "", check.label), node("small", "", actualDisplay + " · 目标 " + expected));
      row.append(badge, copy, node("span", "check-state", statusText[check.status] || unknown));
      container.append(row);
    }
  }

  function renderHistory() {
    const items = state.history;
    const target = state.target;
    const list = byId("history-list");
    list.replaceChildren();
    setText("history-summary", items.length ? "按台湾目标比较 · " + items.length + " 条" : "");
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
      const place = net.country ? `${countryFlag(net.country)} ${region(net.country)} (${net.country})` : unknown;
      row.append(time, node("span", "", place),
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
      ctx.strokeStyle = "rgba(180,210,220,0.14)";
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
        gradient.addColorStop(0, "rgba(126,232,192,.22)"); gradient.addColorStop(1, "rgba(126,232,192,0)");
        ctx.fillStyle = gradient; ctx.fill(under);
        ctx.strokeStyle = "#7ee8c0"; ctx.lineWidth = 2; ctx.lineJoin = "round"; ctx.stroke(path);
      }
      ctx.fillStyle = "#a7f3d0";
      for (const p of segment) {
        ctx.beginPath(); ctx.arc(x(p.t), y(p.value), points.length < 20 ? 3.2 : 1.8, 0, Math.PI * 2); ctx.fill();
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

  function renderLaunches(launches) {
    if (!launches) return;
    window.clearTimeout(launchPoll);
    const lines = [];
    let nextPoll = 0;
    for (const [client, name] of Object.entries(clientNames)) {
      const row = launches[client] || {};
      const waiting = row.state === "starting" || submittingClients.has(client);
      const running = row.state === "running";
      const button = byId("launch-" + client);
      button.disabled = waiting || running || !row.state;
      button.setAttribute("aria-busy", String(waiting));
      let tone, text;
      if (waiting) { tone = "warn"; text = "正在检查启动条件…"; nextPoll = 1000; }
      else if (running) { tone = "good"; text = "的受管进程正在运行。"; nextPoll ||= 4000; }
      else if (row.state === "failed") { tone = "bad"; text = "：" + (row.error || "启动失败。"); }
      else if (row.state === "ended") { tone = "neutral"; text = "会话已结束。"; }
      if (text) {
        const line = node("span", "launch-line", name + text);
        line.dataset.tone = tone;
        lines.push(line);
      }
    }
    const feedback = byId("launch-feedback");
    delete feedback.dataset.tone;
    feedback.replaceChildren(...lines);
    feedback.hidden = !lines.length;
    if (nextPoll) launchPoll = window.setTimeout(pollLaunches, nextPoll);
  }

  async function pollLaunches() {
    const revision = launchRevision;
    try {
      const payload = await request("/api/state");
      if (revision === launchRevision) renderLaunches(payload.launches);
    } catch {
      if (revision !== launchRevision) return;
      const feedback = byId("launch-feedback");
      feedback.hidden = false;
      feedback.dataset.tone = "warn";
      feedback.textContent = "暂时无法确认受管客户端状态，正在重试。";
      launchPoll = window.setTimeout(pollLaunches, 3000);
    }
  }

  for (const client of Object.keys(clientNames)) {
    const button = byId("launch-" + client);
    button.addEventListener("click", async () => {
      if (submittingClients.has(client)) return;
      ++launchRevision;
      submittingClients.add(client);
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
      try {
        const payload = await request("/api/launch", { client });
        submittingClients.delete(client);
        renderLaunches(payload.launches);
      } catch (error) {
        submittingClients.delete(client);
        button.disabled = false;
        button.setAttribute("aria-busy", "false");
        const message = byId("launch-feedback");
        message.hidden = false;
        message.dataset.tone = "bad";
        message.textContent = clientNames[client] + "：" + error.message;
        window.clearTimeout(launchPoll);
        launchPoll = window.setTimeout(pollLaunches, 2000);
      }
    });
  }

  function render(payload) {
    renderLaunches(payload.launches);
    state = payload;
    const sample = lastSample();
    const net = sample?.network || {};
    const sys = sample?.system || {};
    browserZone = new Intl.DateTimeFormat().resolvedOptions().timeZone || null;
    countryInput.value = state.target.country;
    timezoneInput.value = state.target.timezone;
    setText("last-updated", sample ? formattedTime(sample.time) : "尚未检测");
    if (sample) byId("last-updated").dateTime = sample.time;
    setText("exit-country", net.country ? region(net.country) : sample ? "未确定" : defaultMark);
    setText("exit-flag", countryFlag(net.country) || "🌐");
    const codeChip = byId("exit-code");
    if (codeChip) {
      codeChip.hidden = !net.country;
      codeChip.textContent = net.country || "";
    }
    const exitResult = compare(net.country, state.target.country);
    const pill = byId("hero-status");
    pill.dataset.tone = tones[exitResult];
    pill.textContent = sample ? ({ pass: "实测台湾出口", fail: "非台湾出口", unknown: "无地区数据" })[exitResult] : "待检测";
    let endpoint = "";
    try { endpoint = new URL(net.endpoint).hostname; } catch { /* No endpoint before the first measurement. */ }
    setText("exit-detail", sample ? [endpoint && "探测主机 " + endpoint, net.route, net.error].filter(Boolean).join(" · ") : "");
    renderIp();
    const duration = latency(sample);
    setText("latency-value", duration ?? defaultMark);
    setText("latency-detail", net.error ? "探测未完成" : net.http_status ? "HTTP " + net.http_status : "");
    setText("system-timezone", sys.system_timezone);
    setText("browser-timezone", browserZone);
    setText("auto-timezone", sys.auto_timezone === true ? "已开启（建议关闭）" : sys.auto_timezone === false ? "已关闭" : null);
    setText("route-detail", net.route);
    setText("proxy-detail", sys.proxy_summary || (sys.proxy_enabled === true ? "已启用" : sys.proxy_enabled === false ? "未启用" : null));
    setText("language-detail", sys.language || sys.locale);
    setText("cli-detail", sys.claude_available === true ? "已找到" : sys.claude_available === false ? "未找到" : null);
    renderTripleAlignment(sample);
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

  async function loadReadiness() {
    try {
      const response = await fetch("/api/readiness", { cache: "no-store", signal: AbortSignal.timeout(15000) });
      if (!response.ok) return;
      const data = await response.json();
      renderReadiness(data);
    } catch {
      /* Readiness panel keeps last known reading. */
    }
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
      const [payload] = await Promise.all([request("/api/check", {}), loadReadiness()]);
      render(payload);
      markService("已连接", "good");
    } catch (error) {
      markService("检测请求失败", "bad");
      showMessage("检测未完成。" + error.message + "。请确认本机服务正在运行，然后重试。");
    } finally { lock(null); }
  }

  async function load() {
    lock("load");
    try {
      const [payload] = await Promise.all([request("/api/state"), loadReadiness()]);
      render(payload);
      markService("已连接", "good");
    } catch (error) {
      markService("连接失败", "bad");
      showMessage("无法读取本机状态。" + error.message + "。可点击「立即检测」重试。");
    } finally { lock(null); }
    if (state && !state.history.length) await check();
  }

  window.preflightRefreshAll = () => {
    loadReadiness();
    if (!busy) check();
  };

  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (busy) return;
    const target = { country: countryInput.value.trim().toUpperCase(), timezone: timezoneInput.value.trim() };
    lock("save");
    try {
      const payload = await request("/api/settings", target);
      render(payload);
      markService("已连接", "good");
      showMessage("");
      setText("settings-status", "已核验：目标已锁定为台湾（TW / Asia/Taipei）。");
      byId("settings-status").dataset.tone = "good";
    } catch (error) {
      setText("settings-status", error.message);
      byId("settings-status").dataset.tone = "bad";
    } finally { lock(null); }
  });

  refresh.addEventListener("click", check);
  const readinessBtn = byId("readiness-refresh");
  if (readinessBtn) readinessBtn.addEventListener("click", loadReadiness);

  byId("guard-lock").addEventListener("click", async () => {
    const button = byId("guard-lock"), message = byId("guard-feedback");
    button.disabled = true;
    message.hidden = false;
    message.dataset.tone = "warn";
    message.textContent = "正在等待受管会话确认…";
    try {
      const response = await fetch("/api/lock", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: "{}", signal: AbortSignal.timeout(20000)
      });
      if (!response.ok) throw Error();
      const result = await response.json();
      if (result.unconfirmed) {
        message.textContent = `已确认 ${result.confirmed} 个，另有 ${result.unconfirmed} 个未确认。请先保留当前节点。`;
      } else if (result.confirmed) {
        message.dataset.tone = "good";
        message.textContent = `已锁定 ${result.confirmed} 个受管会话，取消 ${result.cancelled || 0} 个待启动会话。请完全退出已锁定的旧客户端，确认节点后重新打开。`;
      } else if (result.cancelled) {
        message.dataset.tone = "good";
        message.textContent = `已取消 ${result.cancelled} 个待启动会话。确认节点后可重新启动。`;
      } else {
        message.dataset.tone = "neutral";
        message.textContent = "当前没有受管会话。普通浏览器标签页和独立启动的 App 不在锁定范围。";
      }
    } catch { message.textContent = "未收到本机锁定确认，请先保留当前节点。"; }
    finally { button.disabled = false; }
  });

  byId("ip-toggle").addEventListener("click", () => { revealIp = !revealIp; renderIp(); });
  const ipCopy = byId("ip-copy");
  if (ipCopy) {
    ipCopy.addEventListener("click", async () => {
      const address = lastSample()?.network?.ip;
      if (!address) return;
      try {
        await navigator.clipboard.writeText(address);
        setText("ip-copy-hint", "已复制");
        window.setTimeout(() => setText("ip-copy-hint", ""), 1800);
      } catch {
        setText("ip-copy-hint", "");
      }
    });
  }

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
      const el = document.querySelector(anchor.hash);
      if (el && el.getBoundingClientRect().top <= margin) active = anchor;
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
