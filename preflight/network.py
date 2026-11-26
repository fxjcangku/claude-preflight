"""Measure the unauthenticated HTTPS trace as seen from this Mac."""

import ipaddress
import os
import re
import subprocess
import sys
from urllib.parse import urlsplit
from urllib.request import getproxies_environment, proxy_bypass_environment


_HOST = "www.cloudflare.com"
ENDPOINT = f"https://{_HOST}/cdn-cgi/trace"
_ISO_COUNTRIES = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM
BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX
CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG
GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR
IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV
LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE
NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO
RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF
TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF
WS YE YT ZA ZM ZW
""".split())


def _select_proxy():
    env = getproxies_environment()
    if proxy_bypass_environment(_HOST, env):
        return "直连（环境变量指定例外）", None
    if env.get("https") or env.get("all"):
        return "环境变量代理", env.get("https") or env["all"]

    # A lone HTTP_PROXY or NO_PROXY does not configure the HTTPS route.
    settings = subprocess.run(
        ["/usr/sbin/scutil", "--proxy"], capture_output=True, check=True, timeout=2
    ).stdout.decode("utf-8")
    if not settings.lstrip().startswith("<dictionary> {"):
        raise ValueError("无法读取系统代理设置")
    fields = dict(re.findall(r"^\s*([A-Za-z]+) : (.+)$", settings, re.MULTILINE))
    automatic = any(fields.get(key) == "1" for key in
                    ("ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"))
    kind = next((k for k in ("HTTPS", "SOCKS") if fields.get(k + "Enable") == "1"), None)
    if not (automatic or kind):
        return "直连（无显式代理）", None

    # macOS exceptions may include CIDRs. Bound the system resolver lookup in
    # its own process so an unresponsive DNS server cannot hang a report.
    bypass = subprocess.run(
        [sys.executable, "-I", "-c",
         "from urllib.request import proxy_bypass_macosx_sysconf as bypass; "
         f"print(int(bypass({_HOST!r})))"],
        capture_output=True, check=True, timeout=3,
    ).stdout.strip()
    if bypass == b"1":
        return "直连（系统代理例外）", None
    if bypass != b"0":
        raise ValueError("无法判断系统代理例外")
    if automatic:
        raise ValueError("当前系统使用自动代理，无法确认此次请求的代理路径")
    host = fields.get(kind + "Proxy", "")
    port = fields.get(kind + "Port", "")
    if not host or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("系统代理配置不完整")
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    scheme = "http" if kind == "HTTPS" else "socks5h"
    return f"系统 {kind} 代理", f"{scheme}://{host}:{port}"


def _proxy_url(value):
    if "://" not in value:
        value = "http://" + value
    try:
        url = urlsplit(value)
        if (url.scheme in {"http", "https", "socks4", "socks4a", "socks5", "socks5h"}
                and url.hostname and url.port != 0 and not url.query and not url.fragment
                and url.path in ("", "/") and not any(c.isspace() for c in value)):
            return value
    except ValueError:
        pass
    raise ValueError("代理地址格式不受支持")


def _trace(body, expected_host):
    try:
        lines = body.decode("ascii").splitlines()
        fields = {}
        for line in lines:
            key, separator, value = line.partition("=")
            if not separator or not key or key in fields:
                raise ValueError
            fields[key] = value
        country = fields["loc"]
        address = ipaddress.ip_address(fields["ip"])
        if (country not in _ISO_COUNTRIES or not address.is_global
                or address.is_multicast or "%" in fields["ip"]
                or fields.get("h") != expected_host):
            raise ValueError
        return country, str(address)
    except (KeyError, UnicodeError, ValueError):
        raise ValueError("响应缺少匹配的探测主机、公网 IP 或地区信息") from None


def probe_network():
    """Return fresh probe results. Latency includes DNS, TLS and HTTP transfer."""
    result = dict(country=None, ip=None, latency_ms=None, http_status=None,
                  endpoint=ENDPOINT, route="未知", error=None)
    try:
        result["route"], proxy = _select_proxy()
        # Supply credentials, if configured, through the child's environment
        # only. Disable curlrc, persistent state and inherited proxy overrides.
        env = {"PATH": os.defpath, "LC_ALL": "C"}
        if proxy is not None:
            env["https_proxy"] = _proxy_url(proxy)
        run = subprocess.run(
            ["/usr/bin/curl", "-q", "--silent", "--proto", "=https",
             "--connect-timeout", "3", "--max-time", "6", "--max-filesize", "16384",
             "--write-out", "\\n%{http_code} %{time_total}", ENDPOINT],
            env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=7,
        )
        body, _, metadata = run.stdout.rpartition(b"\n")
        match = re.fullmatch(rb"(\d{3}) (\d+(?:\.\d+)?)", metadata)
        if match and int(match[1]) != 0:
            result["http_status"] = int(match[1])
            result["latency_ms"] = round(float(match[2]) * 1000)
        if run.returncode:
            result["error"] = f"HTTPS 请求失败（curl {run.returncode}）"
        elif result["http_status"] != 200:
            result["error"] = "探测端点未返回 HTTP 200"
        else:
            result["country"], result["ip"] = _trace(body, _HOST)
    except subprocess.TimeoutExpired:
        result["error"] = "网络探测超时"
    except (OSError, subprocess.SubprocessError, UnicodeError):
        result["error"] = "无法读取系统代理或执行网络探测"
    except ValueError as exc:
        result["error"] = str(exc)
    return result
