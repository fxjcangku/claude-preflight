(() => {
  const bridge = window.webkit?.messageHandlers?.preflight;
  if (!bridge || typeof bridge.postMessage !== "function") return;

  document.documentElement.dataset.platform = "mac";
  document.getElementById("setup-availability").hidden = true;
  const feedback = document.getElementById("setup-feedback");
  const pipeline = document.getElementById("setup-pipeline");
  const actions = new Map([
    ["configureAll", document.getElementById("configure-all")],
    ["restoreConfiguration", document.getElementById("restore-configuration")],
    ["configureTaiwan", document.getElementById("configure-taiwan")],
    ["configureVpn", document.getElementById("configure-vpn")],
    ["configureFirewall", document.getElementById("configure-firewall")],
  ]);
  const actionLabels = {
    configureAll: "正在执行一键配置（备份 → 台湾地区与时区 → VPN 节点与分流 → LuLu 规则与代理），请留意系统授权提示…",
    restoreConfiguration: "正在执行一键复原，按首次备份撤销 Preflight 所做的更改…",
    configureTaiwan: "正在配置台湾地区（TW）与台北时区（Asia/Taipei），请留意系统管理员授权提示…",
    configureVpn: "正在配置并实测 VPN 台湾出口与 Claude 分流规则…",
    configureFirewall: "正在安全合并 LuLu 防火墙规则、核验 Claude 固定代理与 Dock 监护…",
  };
  let pending = null;

  function updateButtons() {
    for (const [action, button] of actions) {
      if (!button) continue;
      button.disabled = pending !== null;
      button.setAttribute("aria-busy", String(pending === action));
    }
  }

  function renderSteps(steps) {
    if (!pipeline) return;
    if (!Array.isArray(steps) || !steps.length) {
      pipeline.hidden = true;
      pipeline.replaceChildren();
      return;
    }
    const toneMap = { ok: "good", error: "bad", pending: "pending", skipped: "neutral" };
    const dotMap = { ok: "✅", error: "❌", pending: "⏳", skipped: "⚪" };
    const tagMap = { ok: "已验证", error: "未通过", pending: "待批准", skipped: "未执行" };
    pipeline.replaceChildren();
    for (const step of steps) {
      const li = document.createElement("li");
      li.className = "pipe-step";
      const st = step.status || "pending";
      li.dataset.tone = toneMap[st] || "neutral";

      const dot = document.createElement("span");
      dot.className = "pipe-dot";
      dot.setAttribute("aria-hidden", "true");
      dot.textContent = dotMap[st] || "⚪";

      const copy = document.createElement("div");
      copy.className = "pipe-copy";
      const title = document.createElement("strong");
      title.textContent = step.label || step.id || "配置步骤";
      const detail = document.createElement("small");
      detail.textContent = step.detail || "";
      copy.append(title, detail);

      const tag = document.createElement("span");
      tag.className = "pipe-tag";
      tag.textContent = tagMap[st] || "未知";

      li.append(dot, copy, tag);
      pipeline.append(li);
    }
    pipeline.hidden = false;
  }

  window.preflightNativeSetupResult = function (result) {
    if (!result) return;
    if (result.action === "status" && pending === null) {
      feedback.dataset.tone = result.ok === true ? "good" : result.ok === false ? "bad" : "pending";
      if (typeof result.message === "string" && result.message) feedback.textContent = result.message;
      return;
    }
    if (!actions.has(result.action) || (pending && pending !== result.action)) return;
    pending = null;
    const needsAttention = result.actionRequired === true || ["pending", "actionRequired"].includes(result.status);
    feedback.dataset.tone = needsAttention ? "pending"
      : (result.ok === true ? "good" : result.ok === false ? "bad" : "pending");
    feedback.textContent = typeof result.message === "string" && result.message
      ? result.message : (feedback.dataset.tone === "good" ? "配置已完成并验证。"
        : feedback.dataset.tone === "bad" ? "配置未完成。" : "请在系统设置中确认后重试。");
    if (Array.isArray(result.steps)) renderSteps(result.steps);
    updateButtons();
    if (typeof window.preflightRefreshAll === "function") {
      window.preflightRefreshAll();
    }
  };

  for (const [action, button] of actions) {
    if (!button) continue;
    button.addEventListener("click", () => {
      if (pending !== null) return;
      pending = action;
      updateButtons();
      feedback.dataset.tone = "pending";
      feedback.textContent = actionLabels[action] || "正在执行 Mac 配置，请查看系统提示…";
      try {
        bridge.postMessage({ action });
      } catch {
        window.preflightNativeSetupResult({ action, ok: false, message: "无法连接到 Mac App，请重新打开 Preflight 后再试。" });
      }
    });
  }
  updateButtons();
})();
