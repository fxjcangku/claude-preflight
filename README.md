# Preflight

在打开 Claude 前，看看这台 Mac 的网络从哪里出去。Preflight 在本机展示公网 IP、出口地区、代理、请求耗时，以及系统、终端和浏览器各自报告的时区。

[查看工具介绍](https://fxjcangku.github.io/claude-preflight/)

![Preflight 本机面板，使用文档示例 IP 和模拟检测记录](docs/preview.png)

## 在 Mac 上使用

需要 Git 和 Python 3.9 或更新版本。检测使用 macOS 自带的 `curl`、`scutil` 和 `defaults`，Python 只使用标准库。

```sh
git clone https://github.com/fxjcangku/claude-preflight.git
cd claude-preflight
./claude-preflight
```

浏览器会打开本机面板。首次打开时进行一次采样，随后可以手动刷新或开启每分钟一次的自动检测。点击公网 IP 旁的眼睛可显示完整地址。在启动服务的终端按 Control-C 退出。

## 启动前检查

```sh
./claude-preflight check
./claude-preflight check --json
./claude-preflight run
```

`run` 先核验 OneVPN 进程、代理监听器和隧道，通过其代理检测 Claude 出口，再比较出口地区、macOS 地区、系统时区和终端时区。通过后才从当前目录受管启动。检测发现不符时返回 1，缺少必要观测且没有已知不符项时返回 2。图形面板额外显示当前浏览器的时区和系统首选语言。

默认目标是 `TW` 和 `Asia/Taipei`。面板中的「检测设置」可以修改后续检测目标。在终端也可以只覆盖本次目标，或把参数传给 Claude。

```sh
./claude-preflight check --country JP --timezone Asia/Tokyo
./claude-preflight run -- --version
```

## OneVPN 断线与换节点

监测面板可以独立使用。受管启动针对 macOS 的 OneVPN 1.5.1，要求它的 HTTPS 回环代理及 TUN 隧道正常。CLI 和浏览器均使用独立的加密隧道转发端口，Preflight 不解密 HTTPS。

| 入口 | 用法 |
| --- | --- |
| 终端 Claude Code | `./claude-preflight run` 使用 macOS 沙盒限制进程的网络套接字，启动前实测允许与拒绝端口。 |
| 专用 Claude 网页窗口 | `./claude-preflight run --client web` 打开独立的 Chrome 资料夹，先用本地模拟代理验证代理失效时普通网页请求不会改为直连。 |
| 原生 Claude 桌面版 | `./claude-preflight run --client desktop` 要求启用 LuLu 并为整个 Claude 应用设置专用规则；无法核对时拒绝启动。本机中继端口为 `127.0.0.1:47836`。 |

**切换节点前**，在面板点击「锁定受管连接」，或在另一个终端运行 `./claude-preflight lock`。等到已确认锁定会话数后再切换。锁定会关闭中继上的既有连接，并拒绝该会话的新连接。切换后重新受管启动可恢复。

出口探测未能确认 IP 时，中继立即关闭已有连接并拒绝新连接。监护程序只通过重新核验的原 OneVPN 端口重试，间隔从 2 秒增至 4 秒、再到 8 秒。确认节点和出口 IP 均与启动时一致后，中继自动恢复。若 OneVPN 进程、代理端口、节点、隧道或系统时区发生变化或无法核验，或确认出口 IP 已变，会话会保持锁定，直到重新受管启动。直接在 OneVPN 里换节点会有采样时间窗。如果需要在切换发生**之前**停流量，请使用上面的锁定入口。同一 Mac 的普通 Safari/Chrome 标签页、通过外部系统服务发起的请求及远程执行环境不属于这些会话。

中继允许 Claude 服务使用的域名，以及邮件登录页面加载验证脚本所需的 `challenges.cloudflare.com:443`。登录页使用 hCaptcha 时，中继允许通过 HTTPS 从 `hcaptcha.com` 及其子域加载验证脚本和相关资源。Google 账号选择器也可通过中继访问 `accounts.google.com`，并从 `www.gstatic.com` 和 `ssl.gstatic.com` 加载登录资源。这些 HTTPS 请求都经过同一个受管中继，锁定时一起断开。第三方 SSO、MCP 或外部工具所需的其他域名可能会被拦截。[Claude 网络要求](https://code.claude.com/docs/en/desktop#network-access-requirements) · [hCaptcha 官方资源域名说明](https://docs.hcaptcha.com/#content-security-policy-settings)

## 从 Dock 打开原生桌面版

1. **启用 LuLu。** 将 Claude 安装到 `/Applications/Claude.app`，完全退出 Claude。安装 LuLu 4.5.7，在 macOS 提示时批准系统扩展和网络过滤器。在 LuLu 当前配置中关闭全局回环放行、DNS 放行、Allow List 和 Block Mode。这些开关作用于该配置下的所有应用。新装 LuLu 如需静默运行，可选 Passive Mode，设置为允许未匹配连接并关闭自动创建规则。[LuLu 安装与设置](https://objective-see.org/products/lulu.html)
2. **给 Claude 添加两条永久规则。** 在 LuLu 菜单的「Rules → Show…」中打开「All Rules」，点击加号。两条规则的程序路径都填 `/Applications/Claude.app/*`。第一条选 Block，远端地址和端口都填 `*`。第二条选 Allow，远端地址填 `127.0.0.1`，端口填 `47836`，使用普通地址匹配。如果已有针对 Claude 或其助手的其他放行规则，按启动时的冲突提示检查。
3. **安装 Claude 的代理描述文件。** 在仓库目录运行 `open config/Claude-Preflight.mobileconfig`。前往「系统设置 → 通用 → 设备管理」，在「已下载」中打开「Claude Preflight」，查看内容并点击「安装」。示例在当前用户的 Claude 应用域中仅设置 `egressProxyUrl=http://127.0.0.1:47836`，下次启动 Claude 时生效。[查看示例文件](config/Claude-Preflight.mobileconfig) · [Anthropic 代理设置](https://claude.com/docs/third-party/claude-desktop/network-proxy) · [Apple 描述文件安装说明](https://support.apple.com/zh-cn/guide/mac-help/mh35561/mac)
4. **选择启动方式。** 连接 OneVPN 后，在仓库目录运行 `./claude-preflight install-watcher`，以后点击 Dock 中原来的 Claude 图标即可。监护程序随当前用户登录而启动，检查通过后才开放中继。也可以直接运行 `./claude-preflight run --client desktop`，仅为这次启动提供中继。

**停用 Dock 监护**时，先退出 Claude，再运行 `./claude-preflight uninstall-watcher`。如果要恢复 Claude 原来的网络设置，再到「设备管理」中移除「Claude Preflight」，并在 LuLu 中移除上述两条 Claude 规则。保留规则和描述文件时，可继续通过终端受管启动。

## 如何理解结果

- 仪表盘和 `check` 通过 `www.cloudflare.com/cdn-cgi/trace` 测量出口 IP、地区和 HTTPS 请求耗时。若 OneVPN 断开且系统改为直连，Cloudflare 会看到直连出口。受管启动先核验 OneVPN，再通过其本地代理访问 `claude.ai/cdn-cgi/trace` 核对 Claude 路径。
- 探测优先使用适用于 HTTPS 的代理环境变量，随后读取 macOS 系统代理。支持显式 HTTPS、SOCKS 代理和代理例外。系统仅提供自动代理脚本而无法确定路径时，界面显示未知。
- 时区按 IANA 名称比较。台北和上海通常同为 UTC+8，`Asia/Taipei` 与 `Asia/Shanghai` 会得到不同结果。系统首选语言单独展示，可保留简体中文。
- 面板仅监听本机 `127.0.0.1`。本次服务最近 60 次观测保存在内存，退出后清空。仅检测目标保存到 `~/Library/Application Support/Claude Preflight/target.json`。网络诊断端点能看到本次请求的出口 IP。
- 这是独立的开源工具。检查结果反映本机观测和用户设置的期望值。

## 开发

```sh
python3 -m unittest discover -s tests
./claude-preflight ui --no-open
```

`preflight/` 包含检测、命令行和本地服务，`preflight/static/` 是监测面板，`docs/` 是项目介绍页，`tests/` 是自动化测试。

代码采用 [MIT 许可证](LICENSE)。地球图中的陆地点阵和地区参考点来自公共领域的 [Natural Earth 1:110m 数据](https://github.com/nvkelso/natural-earth-vector/blob/ca96624a56bd078437bca8184e78163e5039ad19/geojson/ne_110m_admin_0_countries.geojson)，标记仅表示大致地区。
