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

`run` 会检查出口地区、macOS 地区、系统时区和终端时区。四项都符合目标时才从当前工作目录启动 PATH 里的 Claude CLI。检测发现不符时返回 1，缺少必要观测且没有已知不符项时返回 2。图形面板额外显示当前浏览器的时区和系统首选语言。

默认目标是 `TW` 和 `Asia/Taipei`。面板中的「检测设置」可以修改后续检测目标。在终端也可以只覆盖本次目标，或把参数传给 Claude。

```sh
./claude-preflight check --country JP --timezone Asia/Tokyo
./claude-preflight run -- --version
```

## 如何理解结果

- 出口 IP 和地区来自一次访问 `https://claude.ai/cdn-cgi/trace` 的 HTTPS 响应。耗时包含连接建立和 HTTP 往返；所示路径属于这一次探测。账号地区或其他客户端的实际路径需要在相应服务中核对。
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
