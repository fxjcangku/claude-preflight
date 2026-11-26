"""Entry points for the dashboard, terminal report and checked launch."""
import argparse
import json
import sys

from .core import evaluate, load_target, snapshot, validate_target
from .desktop_launch import StartupFailure, notify_dashboard


def main():
    parser = argparse.ArgumentParser(prog="claude-preflight", description="Preflight · 本机环境监测")
    commands = parser.add_subparsers(dest="command")
    web = commands.add_parser("ui", help="打开本地监测面板（默认）")
    web.add_argument("--port", type=int, default=0, help="指定本地端口，默认自动分配")
    web.add_argument("--no-open", action="store_true", help="仅打印地址")
    commands.add_parser("lock", help="切换 OneVPN 节点前，锁定已受管会话的网络")
    commands.add_parser("watch-desktop", help="为从 Dock 打开的 Claude 等待并执行保护")
    commands.add_parser("install-watcher", help="为当前用户启用 Dock 启动监护")
    commands.add_parser("uninstall-watcher", help="移除当前用户的 Dock 启动监护")
    config = commands.add_parser("configure", help="管理可复原的 macOS 地区和时区设置")
    config.add_argument("--action", choices=("status", "taiwan", "restore"), default="status")
    config.add_argument("--verify", action="store_true", help="核验管理员操作后的实际设置")
    config.add_argument("--json", action="store_true")
    firewall = commands.add_parser("configure-firewall", help="管理可复原的桌面网络保护设置")
    firewall.add_argument("--action", choices=("status", "apply", "restore"), default="status")
    firewall.add_argument("--verify", action="store_true", help="核验官方 LuLu 导入后的规则状态")
    firewall.add_argument("--json", action="store_true")
    vpn = commands.add_parser("configure-vpn", help="为现有 OneVPN 设置或复原分流规则")
    vpn.add_argument("--action", choices=("status", "apply", "restore"), default="status")
    vpn.add_argument("--phase", choices=("prepare", "commit", "verify"), default="prepare")
    vpn.add_argument("--node", help="由本机配置助手返回的节点标识")
    vpn.add_argument("--json", action="store_true")
    readiness = commands.add_parser("readiness", help="输出前置条件自检状态")
    readiness.add_argument("--json", action="store_true")
    attach = commands.add_parser("attach-desktop", help="为指定的已打开 Claude 桌面进程执行受管检查")
    attach.add_argument("pid", type=int)
    for mode, title in (("check", "执行检测"), ("run", "所有必检项通过后启动 Claude Code")):
        sub = commands.add_parser(mode, help=title)
        sub.add_argument("--country", help="覆盖本次期望地区，例如 TW")
        sub.add_argument("--timezone", help="覆盖本次期望时区，例如 Asia/Taipei")
        if mode == "check":
            sub.add_argument("--json", action="store_true", help="输出含公网 IP 的结构化结果")
        else:
            sub.add_argument("--client", choices=("cli", "web", "desktop"), default="cli",
                             help="要通过 OneVPN 受管通道启动的客户端")
            sub.add_argument("args", nargs=argparse.REMAINDER, help="在 -- 后添加 Claude 参数")
    args = parser.parse_args()
    try:
        if args.command == "configure":
            from .configuration import configure
            result = configure(args.action, verify=args.verify)
            print(json.dumps(result, ensure_ascii=False) if args.json else result["message"])
            return 2 if result["actionRequired"] == "error" else 0
        if args.command == "configure-firewall":
            from .firewall_setup import configure_firewall
            result = configure_firewall(args.action, verify=args.verify)
            print(json.dumps(result, ensure_ascii=False) if args.json else result["message"])
            return 2 if result["status"] == "error" else 0
        if args.command == "configure-vpn":
            from .vpn_setup import configure_vpn
            result = configure_vpn(args.action, args.phase, args.node)
            print(json.dumps(result, ensure_ascii=False) if args.json else result["message"])
            return 2 if result["status"] == "error" else 0
        if args.command == "readiness":
            from .status_check import collect_readiness
            result = collect_readiness()
            print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else result["overall"])
            return 0
        if args.command in ("watch-desktop", "install-watcher", "uninstall-watcher"):
            from .dock import install_dock_watcher, uninstall_dock_watcher, watch_dock
            action = {"watch-desktop": watch_dock, "install-watcher": install_dock_watcher,
                      "uninstall-watcher": uninstall_dock_watcher}[args.command]
            action()
            return 0
        if args.command == "lock":
            from .guard import lock_guards
            return lock_guards()
        if args.command in (None, "ui"):
            from .server import serve
            port = getattr(args, "port", 0)
            if not 0 <= port <= 65535:
                parser.error("端口必须介于 0 和 65535 之间")
            serve(port=port, open_browser=not getattr(args, "no_open", False))
            return 0
        target = load_target()
        target = validate_target(getattr(args, "country", None) or target["country"],
                                 getattr(args, "timezone", None) or target["timezone"])
        if args.command in ("run", "attach-desktop"):
            from .guard import probe_guarded_network
            sample = snapshot(network_probe=probe_guarded_network)
        else:
            sample = snapshot()
        assessment = evaluate(sample, target)
        if getattr(args, "json", False):
            print(json.dumps(dict(target=target, sample=sample, assessment=assessment),
                             ensure_ascii=False, indent=2))
        else:
            labels = {"pass": "通过", "fail": "不符", "unknown": "未知"}
            print("Preflight · " + sample["time"])
            for row in assessment["checks"]:
                print(f"  {labels[row['status']]}  {row['label']}: {row['actual'] or '未知'}"
                      f"  (目标 {row['expected']})")
            net = sample["network"]
            print(f"  探测路径: {net['route']}  |  公网 IP: {net['ip'] or '未知'}")
            if net["error"]:
                print("  网络诊断: " + net["error"])
        if assessment["status"] != "pass":
            if args.command in ("run", "attach-desktop"):
                notify_dashboard("ENVIRONMENT")
            return 1 if assessment["status"] == "fail" else 2
        if args.command == "attach-desktop":
            from .guard import run_guard
            return run_guard([], sample["network"]["ip"], client="desktop", attach_pid=args.pid)
        if args.command == "run":
            from .guard import run_guard
            forwarded = args.args[1:] if args.args[:1] == ["--"] else args.args
            sys.stdout.flush()
            return run_guard(forwarded, sample["network"]["ip"], client=args.client)
        return 0
    except (OSError, ValueError) as exc:
        if isinstance(exc, StartupFailure):
            notify_dashboard(exc.code)
        print(f"Preflight: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
