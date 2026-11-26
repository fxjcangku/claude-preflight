# Preflight Mac 开发接手指令

> 交接状态已更新（`v0.2.0`）：完整的 OneVPN 三阶段配置、通用 VPN 自动检测、LuLu 4.5.7 安全合并导入与复原、前置条件自检面板、台湾单地区约束以及双架构 Mac App（`dist/Preflight.app`、`dist/Preflight-0.2.0-macOS.zip`）均已完成构建、离线单测（114 项）和本机 `/Applications/Preflight.app` 安装验收。首次系统授权（管理员时区授权、辅助功能权限、LuLu 扩展/过滤器、描述文件安装）需用户本人在本机完成系统确认。

请在 [claude-preflight 仓库](https://github.com/fxjcangku/claude-preflight) 继续实现并验证独立的 macOS App。先看当前工作树、已有改动及测试，保留其他开发者的进行中修改。目标是用户从 Dock 打开 App，点击一次即可发起完整配置，再次点击可恢复首次配置前保存的状态。打开手工教程仅算引导步骤。

## 产品与交互

- 使用原生窗口、侧栏和克制的半透明玻璃外观，分出总览、网络检测、客户端保护、配置与恢复。网络出口的国旗由实测地区代码生成。实测成功用绿色，失败用红色，未知用灰色，等待授权用琥珀色，同时显示文字。
- 配置目标仅限台湾（🇹🇼）。地区设为 `TW`，时区设为 `Asia/Taipei`，保留当前界面语言、简体字和字体。VPN 需自行安装、订阅并连接。本工具不提供 VPN 或节点。防火墙使用已安装的官方 LuLu。
- 保留「一键配置」「一键复原」以及地区和防火墙的单项操作。原生桥只接受本机面板主框架和预定义操作。普通网页中禁用系统配置按钮。

## 配置与恢复

1. **变更前备份。** 首次修改前原子保存当前地区、系统时区及自动时区开关、将要修改的 OneVPN 规则和节点选择，以及既有 LuLu 规则、Claude 代理描述文件和监护启动项的状态。备份仅当前用户可读，成功写入后才进行修改。重复点击或从中断处重试时，沿用首次备份。
2. **设置本机与 VPN。** 写入并读回台湾地区和台北时区。从用户自己的 OneVPN 配置选择台湾节点，为 Claude 相关流量设置分流，并实测所选路径。OneVPN 1.5.1 的控制器默认关闭。可在用户启动配置流程后正常退出 OneVPN，按原结构合并必要的 Flutter 偏好，再重开、等候就绪并核验。切换前先锁定已有受管连接，核对进程、代理监听器和隧道。保留无关规则及用户订阅。无法找到台湾节点或测得其他出口时，显示原因。
3. **配置 LuLu 和 Claude。** 为 Claude 应用目录及其助手永久阻止所有出站，只精确允许本机 IPv4 回环的受管端口 `47836`。先核对既有规则。LuLu 4.5.7 不提供命令行导入，官方图形界面的规则导入会替换相应规则集。使用官方接口时须备份、合并、重新核验无关规则；无法确保保留时停止并说明。已有正确规则直接复用，不将其记为 App 新增。通过官方配置描述文件设置 Claude 的 `egressProxyUrl`，由 macOS 完成首次网络扩展、过滤器或描述文件批准，再核验实际状态。[LuLu 规则与导入说明](https://objective-see.org/products/lulu.html) · [Claude 代理说明](https://claude.com/docs/third-party/claude-desktop/network-proxy)
4. **启动保护并验收。** 开启中继及所需监护，区分从 Dock 打开的桌面版、专用浏览器和受管 CLI。经核验的 OneVPN 路径必须返回台湾出口，桌面版须验证可访问指定中继且其他目的地确实被阻止。出口暂时未知时先暂停，仅在确认原节点和原出口后恢复。手动锁定、节点或出口改变等不可逆锁定需重新受管启动。任一步待批准、失败或未测，都要保留真实状态。
5. **一键复原。** 先停止本次受管转发，再按备份撤销 App 所做的改动。保留原有 LuLu 规则、描述文件及其他应用设置。遇到用户后续改动或需系统批准的步骤显示具体项目，逐项读回核验。不得把某个地区硬编码成用户原来的设置。

## 当前起点与验收方法

- `macos/Preflight.swift` 管窗口、WebKit 桥与系统授权。`preflight/static/` 是界面，`preflight/server.py` 管本机服务。`preflight/configuration.py` 已有地区备份、变更和还原，`preflight/firewall_setup.py` 已能核验 LuLu、引导描述文件安装及管理监护。`preflight/native_firewall.py` 只读检查规则。
- `preflight/guard.py`、`relay.py`、`dock.py`、`chrome_web.py` 负责受管会话、中继、Dock 监护及专用网页。`docs/` 是介绍页，`tests/` 是测试。交接时完整的 LuLu 自动规则合并导入、OneVPN 配置与整条流程验收尚待补齐。已有源码和构建脚本，尚未确认本次 App 已在用户 Mac 安装或发布。接手后以实际工作树和发行页更新这些状态。
- 先跑离线测试。用模拟配置覆盖重复执行、备份损坏、用户拒绝授权、半途失败、规则保留、无台湾节点，以及锁定和复原。使用隔离的本机模拟端点检查真实客户端允许与阻止路径。测试无需登录账号，截图只用示例数据，日志、仓库、发行包和交接说明均不得携带真实节点、订阅、凭证或公网地址。

```sh
python3 -m unittest discover -s tests
bash macos/build-app.sh --zip
codesign --verify --strict dist/Preflight.app
lipo -archs dist/Preflight.app/Contents/MacOS/Preflight
```

请实际运行构建结果，验证首次配置、待授权后的继续、再次启动和复原，并记录测试边界。发行目标为 macOS 13+、Apple 芯片与 Intel 双架构，使用本机 Python 3.9+。目标版本为 `v0.2.0`，资产名为 `Preflight-0.2.0-macOS.zip`。发布前核对下载资产、架构、签名及 README/介绍页的说明；当前为未经 Apple 公证的构建。把未测试、未安装和未发布的项目如实标出。
