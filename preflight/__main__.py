"""Entry points for the dashboard, terminal report and checked launch."""
import argparse
import json
import os
import sys

from .core import evaluate, load_target, snapshot, validate_target


def main():
    parser = argparse.ArgumentParser(prog="claude-preflight", description="Preflight · 本机环境监测")
    commands = parser.add_subparsers(dest="command")
    web = commands.add_parser("ui", help="打开本地监测面板（默认）")
    web.add_argument("--port", type=int, default=0, help="指定本地端口，默认自动分配")
    web.add_argument("--no-open", action="store_true", help="仅打印地址")
    for mode, title in (("check", "执行检测"), ("run", "所有必检项通过后启动 Claude Code")):
        sub = commands.add_parser(mode, help=title)
        sub.add_argument("--country", help="覆盖本次期望地区，例如 TW")
        sub.add_argument("--timezone", help="覆盖本次期望时区，例如 Asia/Taipei")
        if mode == "check":
            sub.add_argument("--json", action="store_true", help="输出含公网 IP 的结构化结果")
        else:
            sub.add_argument("args", nargs=argparse.REMAINDER, help="在 -- 后添加 Claude 参数")
    args = parser.parse_args()
    try:
        if args.command in (None, "ui"):
            from .server import serve
            port = getattr(args, "port", 0)
            if not 0 <= port <= 65535:
                parser.error("端口必须介于 0 和 65535 之间")
            serve(port=port, open_browser=not getattr(args, "no_open", False))
            return 0
        target = load_target()
        target = validate_target(args.country if args.country is not None else target["country"],
                                 args.timezone if args.timezone is not None else target["timezone"])
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
            return 1 if assessment["status"] == "fail" else 2
        if args.command == "run":
            forwarded = args.args[1:] if args.args[:1] == ["--"] else args.args
            sys.stdout.flush()
            try:
                os.execvp("claude", ["claude", *forwarded])
            except FileNotFoundError:
                print("未在 PATH 中找到 Claude Code CLI。", file=sys.stderr)
                return 127
        return 0
    except (OSError, ValueError) as exc:
        print(f"Preflight: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
