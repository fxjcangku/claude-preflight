import ApplicationServices
import Cocoa
import WebKit

private typealias Reply = [String: Any]

private struct HostFailure: LocalizedError {
    let errorDescription: String?
    init(_ message: String) { errorDescription = message }
}

private let backend = Bundle.main.bundleURL.appendingPathComponent("Contents/Resources/backend")
private let entry = backend.appendingPathComponent("claude-preflight")
private let actions = ["configureAll", "configureTaiwan", "configureVpn", "configureFirewall", "restoreConfiguration"]
private let work = DispatchQueue(label: "Preflight.configuration")
private let oneVpnBundleId = "top.proxy101.onevpn"
private let oneVpnAppURL = URL(fileURLWithPath: "/Applications/OneVPN.app")
private let luluAppURL = URL(fileURLWithPath: "/Applications/LuLu.app")
private let accessibilitySettingsURL = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")!
private let profileSettingsURL = URL(string: "x-apple.systempreferences:com.apple.Profiles-Settings.extension")!
private let luluDownloadURL = URL(string: "https://objective-see.org/products/lulu.html")!

private struct StepStatus {
    let id: String
    let label: String
    var status: String  // "ok", "pending", "error", "skipped"
    var detail: String

    func toDict() -> Reply {
        ["id": id, "label": label, "status": status, "detail": detail]
    }
}

private struct SetupResult {
    var status: String
    var message: String
    var destination: URL? = nil
    var extraDestination: URL? = nil
    var steps: [StepStatus] = []
}

private func process(_ path: String, _ args: [String]) -> Process {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: path)
    task.arguments = args
    task.standardInput = FileHandle.nullDevice
    task.standardError = FileHandle.nullDevice
    task.standardOutput = FileHandle.nullDevice
    return task
}

private func python(_ args: [String]) -> Process {
    let task = process("/usr/bin/python3", ["-I", "-B", entry.path] + args)
    task.currentDirectoryURL = backend
    return task
}

private func request(_ args: [String]) throws -> Reply {
    let task = python(args + ["--json"])
    let pipe = Pipe()
    task.standardOutput = pipe
    try task.run()
    defer { try? pipe.fileHandleForReading.close() }
    var data = Data()
    while let chunk = try pipe.fileHandleForReading.read(upToCount: 4096), !chunk.isEmpty {
        guard data.count + chunk.count <= 65_536 else {
            task.terminate()
            throw HostFailure("设置服务返回的数据过长。")
        }
        data.append(chunk)
    }
    task.waitUntilExit()
    guard let value = try? JSONSerialization.jsonObject(with: data) as? Reply,
          let message = value["message"] as? String, !message.isEmpty, message.count <= 2048 else {
        throw HostFailure("未能读取本机设置服务的结果。")
    }
    return value
}

private func quote(_ text: String) -> String {
    "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

private func authorize(_ steps: [Reply]) throws {
    guard !steps.isEmpty, steps.count <= 3 else { throw HostFailure("时区配置步骤无效。") }
    var lines = ["set -e"]
    for step in steps {
        switch step["operation"] as? String {
        case "setTimezone":
            guard Set(step.keys) == ["operation", "timezone"], let zone = step["timezone"] as? String,
                  zone.utf8.count <= 128, zone.range(of: #"^[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*$"#,
                                                    options: .regularExpression) != nil,
                  TimeZone(identifier: zone) != nil else { throw HostFailure("时区名称无效。") }
            lines.append("/usr/sbin/systemsetup -settimezone " + quote(zone))
        case "setAutomaticTimezone":
            guard Set(step.keys) == ["operation", "enabled"], let enabled = step["enabled"] as? Bool else {
                throw HostFailure("自动时区设置无效。")
            }
            let flag = enabled ? "true" : "false"
            let script = """
                ObjC.import("Foundation");
                if (!$.NSBundle.bundleWithPath("/System/Library/PrivateFrameworks/CoreTime.framework").load) throw Error("CoreTime unavailable");
                ObjC.bindFunction("TMSetAutomaticTimeZoneEnabled", ["void", ["bool"]]);
                ObjC.bindFunction("TMIsAutomaticTimeZoneEnabled", ["bool", []]);
                $.TMSetAutomaticTimeZoneEnabled(\(flag));
                for (let i=0;i<20 && Boolean($.TMIsAutomaticTimeZoneEnabled())!==\(flag);i++) $.NSThread.sleepForTimeInterval(0.1);
                if (Boolean($.TMIsAutomaticTimeZoneEnabled())!==\(flag)) throw Error("setting not confirmed");
                """
            lines.append("/usr/bin/osascript -l JavaScript -e " + quote(script))
        default:
            throw HostFailure("无法识别的管理员操作。")
        }
    }
    let appleScript = """
        on run argv
          do shell script (item 1 of argv) with administrator privileges with prompt "Preflight 需要更改系统时区设置。"
        end run
        """
    let task = process("/usr/bin/osascript", ["-e", appleScript, lines.joined(separator: "\n")])
    try task.run()
    task.waitUntilExit()
    guard task.terminationStatus == 0 else {
        throw HostFailure("管理员操作未完成或已取消。已保存的设置备份可用于重试或复原。")
    }
}

private func regional(_ action: String) throws -> String {
    let args = ["configure", "--action", action]
    var result = try request(args)
    if result["actionRequired"] as? String == "admin" {
        guard let steps = result["adminPlan"] as? [Reply] else { throw HostFailure("时区配置步骤不完整。") }
        try authorize(steps)
        result = try request(args + ["--verify"])
    }
    guard result["ok"] as? Bool == true, result["actionRequired"] as? String == "none" else {
        throw HostFailure(result["message"] as? String ?? "系统设置未通过核验。")
    }
    return result["message"] as? String ?? "已核对系统设置。"
}

private func quitOneVPNGracefully() throws {
    let running = NSRunningApplication.runningApplications(withBundleIdentifier: oneVpnBundleId)
    if running.isEmpty { return }
    for app in running {
        app.terminate()
    }
    // Also ask politely via AppleScript in case menu-bar app ignores standard terminate
    let quitScript = process("/usr/bin/osascript", ["-e", "tell application id \"\(oneVpnBundleId)\" to quit"])
    try? quitScript.run()
    quitScript.waitUntilExit()

    let deadline = Date().addingTimeInterval(15.0)
    while Date() < deadline {
        if NSRunningApplication.runningApplications(withBundleIdentifier: oneVpnBundleId).isEmpty {
            // Brief settle time for Flutter SharedPreferences flush
            Thread.sleep(forTimeInterval: 0.6)
            return
        }
        Thread.sleep(forTimeInterval: 0.3)
    }
    throw HostFailure("等待 OneVPN 正常退出超时。请先手动退出 OneVPN，然后重试。")
}

private func relaunchOneVPN() throws {
    guard FileManager.default.fileExists(atPath: oneVpnAppURL.path) else {
        throw HostFailure("未找到 /Applications/OneVPN.app。")
    }
    let config = NSWorkspace.OpenConfiguration()
    config.activates = false
    let semaphore = DispatchSemaphore(value: 0)
    var launchError: Error?
    NSWorkspace.shared.openApplication(at: oneVpnAppURL, configuration: config) { _, error in
        launchError = error
        semaphore.signal()
    }
    _ = semaphore.wait(timeout: .now() + 10.0)
    if launchError != nil {
        throw HostFailure("重新打开 OneVPN 失败，请手动启动 OneVPN 后重试。")
    }
}

private func configureVpnFlow(restore: Bool) throws -> SetupResult {
    let mode = restore ? "restore" : "apply"
    let prep = try request(["configure-vpn", "--action", mode, "--phase", "prepare"])
    guard let status = prep["status"] as? String, let message = prep["message"] as? String else {
        throw HostFailure("未能识别 OneVPN 配置准备结果。")
    }
    if status == "ok" && (prep["needRestart"] as? Bool) == false {
        return SetupResult(status: "ok", message: message)
    }
    if status == "error" {
        return SetupResult(status: "error", message: message)
    }
    if prep["actionRequired"] as? String == "quitClaude" {
        return SetupResult(status: "pending", message: message)
    }
    guard prep["actionRequired"] as? String == "restartOneVPN" else {
        return SetupResult(status: status, message: message)
    }

    if restore {
        try quitOneVPNGracefully()
        let committed = try request(["configure-vpn", "--action", "restore", "--phase", "commit"])
        if committed["status"] as? String == "error" {
            try? relaunchOneVPN()
            return SetupResult(status: "error", message: committed["message"] as? String ?? "复原 OneVPN 偏好失败。")
        }
        try relaunchOneVPN()
        let verified = try request(["configure-vpn", "--action", "restore", "--phase", "verify"])
        let finalMsg = (committed["conflicts"] as? [String])?.isEmpty == false
            ? (committed["message"] as? String ?? "已复原未冲突的 OneVPN 设置。")
            : (verified["message"] as? String ?? "已复原 OneVPN 设置。")
        return SetupResult(status: verified["status"] as? String == "error" ? "error" : "ok", message: finalMsg)
    }

    // Apply flow: iterate through Taiwan candidates until live exit probe confirms TW
    var candidates = (prep["candidates"] as? [String]) ?? []
    if candidates.isEmpty, let single = prep["node"] as? String {
        candidates = [single]
    }
    guard !candidates.isEmpty else {
        return SetupResult(status: "error", message: "当前 OneVPN 订阅中未找到台湾候选节点。")
    }

    var lastError = "未能实测确认台湾出口（TW）。"
    let maxAttempts = min(candidates.count, 4)
    for index in 0..<maxAttempts {
        let token = candidates[index]
        guard token.range(of: #"^[a-f0-9]{16}$"#, options: .regularExpression) != nil else {
            throw HostFailure("候选节点标识无效。")
        }
        try quitOneVPNGracefully()
        let committed = try request(["configure-vpn", "--action", "apply", "--phase", "commit", "--node", token])
        guard committed["actionRequired"] as? String == "relaunchOneVPN" else {
            try? relaunchOneVPN()
            return SetupResult(status: "error", message: committed["message"] as? String ?? "写入 OneVPN 偏好失败。")
        }
        try relaunchOneVPN()
        let verified = try request(["configure-vpn", "--action", "apply", "--phase", "verify", "--node", token])
        if verified["status"] as? String == "ok" {
            return SetupResult(status: "ok", message: verified["message"] as? String ?? "已配置并实测确认 OneVPN 台湾出口（TW）。")
        }
        lastError = verified["message"] as? String ?? lastError
        if verified["retryable"] as? Bool != true {
            break
        }
    }
    return SetupResult(status: "error", message: lastError + "（已保留首次备份，可检查订阅后重试或一键复原。）")
}

private func isTrustedAccessibility(prompt: Bool) -> Bool {
    let key = kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String
    let options = [key: prompt] as CFDictionary
    return AXIsProcessTrustedWithOptions(options)
}

private func validateStagingPath(_ path: String) -> URL? {
    let url = URL(fileURLWithPath: path).standardizedFileURL
    let allowedDir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/Claude Preflight")
        .standardizedFileURL
    let allowedNames = Set(["lulu-import.json", "lulu-restore.json"])
    guard url.deletingLastPathComponent().path == allowedDir.path,
          allowedNames.contains(url.lastPathComponent),
          FileManager.default.fileExists(atPath: url.path) else {
        return nil
    }
    return url
}

private func runLuLuOfficialUIImport(stagedFile: URL) throws {
    let appleScript = """
        on run argv
          set targetPath to item 1 of argv
          do shell script "/usr/bin/open -a /Applications/LuLu.app"
          delay 1.0
          tell application "System Events"
            tell process "LuLu"
              set frontmost to true
              set menuReady to false
              repeat 20 times
                if exists menu bar item "Rules" of menu bar 1 then
                  set menuReady to true
                  exit repeat
                end if
                delay 0.25
              end repeat
              if not menuReady then error "LuLu Rules menu unavailable"
              click menu item "Import..." of menu "Rules" of menu bar item "Rules" of menu bar 1
              set openReady to false
              repeat 30 times
                if exists (first window whose subrole is "AXDialog" or name contains "Open" or exists button "Open") then
                  set openReady to true
                  exit repeat
                end if
                delay 0.25
              end repeat
              if not openReady then error "LuLu Import open panel did not appear"
              delay 0.3
              keystroke "g" using {command down, shift down}
              delay 0.5
              keystroke targetPath
              delay 0.3
              key code 36
              delay 0.6
              key code 36
              delay 1.2
              repeat 25 times
                if exists (first window whose exists button "OK") then
                  try
                    click button "OK" of (first window whose exists button "OK")
                  end try
                  exit repeat
                end if
                delay 0.25
              end repeat
            end tell
          end tell
        end run
        """
    let task = process("/usr/bin/osascript", ["-e", appleScript, stagedFile.path])
    try task.run()
    task.waitUntilExit()
    guard task.terminationStatus == 0 else {
        throw HostFailure("未能通过 LuLu 官方导入界面完成规则合并，请确认已授予 Preflight 辅助功能权限且 LuLu 已启动后重试。")
    }
    // Give LuLu daemon a moment to persist rules.plist
    Thread.sleep(forTimeInterval: 0.8)
}

private func firewall(_ action: String) throws -> SetupResult {
    let response = try request(["configure-firewall", "--action", action])
    guard let status = response["status"] as? String, ["ok", "pending", "error"].contains(status),
          let message = response["message"] as? String else { throw HostFailure("未能识别防火墙配置结果。") }

    if status == "pending", let step = response["actionRequired"] as? String,
       (step == "luluImport" || step == "luluRestore"),
       let rawPath = response["importPath"] as? String,
       let staged = validateStagingPath(rawPath) {
        if !isTrustedAccessibility(prompt: true) {
            return SetupResult(
                status: "pending",
                message: "已备份现有 LuLu 规则。请在「系统设置 → 隐私与安全性 → 辅助功能」中允许 Preflight，授权后再次点击即可通过 LuLu 官方界面自动安全合并规则。",
                destination: accessibilitySettingsURL
            )
        }
        try runLuLuOfficialUIImport(stagedFile: staged)
        // Re-verify persisted rules.plist & unrelated-rule fingerprint via backend
        let verified = try request(["configure-firewall", "--action", action, "--verify"])
        guard let vStatus = verified["status"] as? String, ["ok", "pending", "error"].contains(vStatus),
              let vMessage = verified["message"] as? String else {
            throw HostFailure("LuLu 导入后的规则核验结果无效。")
        }
        return buildFirewallDestination(status: vStatus, message: vMessage, response: verified)
    }

    return buildFirewallDestination(status: status, message: message, response: response)
}

private func buildFirewallDestination(status: String, message: String, response: Reply) -> SetupResult {
    var destination: URL?
    var extra: URL?
    if status == "pending" {
        let step = response["actionRequired"] as? String
        let profile = backend.appendingPathComponent("config/Claude-Preflight.mobileconfig")
        if step == "lulu" && response["openPath"] as? String == luluAppURL.path { destination = luluAppURL }
        if step == "profile" && response["openPath"] as? String == profile.path {
            destination = profile
            extra = profileSettingsURL
        }
        if step == "lulu" && response["openURL"] as? String == luluDownloadURL.absoluteString {
            destination = luluDownloadURL
        }
        if step == "removeProfile" && response["openURL"] as? String == profileSettingsURL.absoluteString {
            destination = profileSettingsURL
        }
    }
    return SetupResult(status: status, message: message, destination: destination, extraDestination: extra)
}

private func setup(_ action: String) throws -> SetupResult {
    switch action {
    case "configureTaiwan":
        let msg = try regional("taiwan")
        return SetupResult(status: "ok", message: msg, steps: [
            StepStatus(id: "region", label: "台湾地区与台北时区", status: "ok", detail: msg)
        ])

    case "configureVpn":
        let vpnRes = try configureVpnFlow(restore: false)
        return SetupResult(status: vpnRes.status, message: vpnRes.message, destination: vpnRes.destination, steps: [
            StepStatus(id: "vpn", label: "OneVPN 台湾节点与分流", status: vpnRes.status, detail: vpnRes.message)
        ])

    case "configureFirewall":
        let fwRes = try firewall("apply")
        return SetupResult(status: fwRes.status, message: fwRes.message, destination: fwRes.destination,
                           extraDestination: fwRes.extraDestination, steps: [
            StepStatus(id: "firewall", label: "LuLu 规则、代理与监护", status: fwRes.status, detail: fwRes.message)
        ])

    case "configureAll":
        var steps = [
            StepStatus(id: "region", label: "台湾地区与台北时区", status: "pending", detail: "待执行"),
            StepStatus(id: "vpn", label: "OneVPN 台湾节点与分流", status: "pending", detail: "待执行"),
            StepStatus(id: "firewall", label: "LuLu 防火墙、代理与监护", status: "pending", detail: "待执行"),
        ]
        // 1. Region & Timezone
        let regionMsg: String
        do {
            regionMsg = try regional("taiwan")
            steps[0] = StepStatus(id: "region", label: "台湾地区与台北时区", status: "ok", detail: regionMsg)
        } catch {
            let errMsg = (error as? HostFailure)?.errorDescription ?? "地区和时区设置未能完成。"
            steps[0] = StepStatus(id: "region", label: "台湾地区与台北时区", status: "error", detail: errMsg)
            return SetupResult(status: "error", message: errMsg, steps: steps)
        }
        // 2. OneVPN Taiwan node + Claude split rules + real TW exit probe
        let vpnRes: SetupResult
        do {
            vpnRes = try configureVpnFlow(restore: false)
            steps[1] = StepStatus(id: "vpn", label: "OneVPN 台湾节点与分流", status: vpnRes.status, detail: vpnRes.message)
        } catch {
            let errMsg = (error as? HostFailure)?.errorDescription ?? "OneVPN 节点配置未能完成。"
            steps[1] = StepStatus(id: "vpn", label: "OneVPN 台湾节点与分流", status: "error", detail: errMsg)
            return SetupResult(status: "error", message: "1. " + regionMsg + "\n2. " + errMsg, steps: steps)
        }
        if vpnRes.status != "ok" {
            return SetupResult(status: vpnRes.status,
                               message: "1. " + regionMsg + "\n2. " + vpnRes.message,
                               destination: vpnRes.destination, steps: steps)
        }
        // 3. LuLu safe merge-import + Claude profile + Dock watcher
        let fwRes: SetupResult
        do {
            fwRes = try firewall("apply")
            steps[2] = StepStatus(id: "firewall", label: "LuLu 防火墙、代理与监护", status: fwRes.status, detail: fwRes.message)
        } catch {
            let errMsg = (error as? HostFailure)?.errorDescription ?? "防火墙与代理配置未能完成。"
            steps[2] = StepStatus(id: "firewall", label: "LuLu 防火墙、代理与监护", status: "error", detail: errMsg)
            return SetupResult(status: "error",
                               message: "1. " + regionMsg + "\n2. " + vpnRes.message + "\n3. " + errMsg,
                               steps: steps)
        }
        let summary = fwRes.status == "ok"
            ? "一键配置并实测通过：台湾地区与台北时区、OneVPN 台湾出口（TW）与分流规则、LuLu 防火墙、Claude 固定代理和 Dock 监护已全部就绪。"
            : "1. " + regionMsg + "\n2. " + vpnRes.message + "\n3. " + fwRes.message
        return SetupResult(status: fwRes.status, message: summary, destination: fwRes.destination,
                           extraDestination: fwRes.extraDestination, steps: steps)

    case "restoreConfiguration":
        var steps = [
            StepStatus(id: "firewall", label: "复原防火墙、代理与监护", status: "pending", detail: "待执行"),
            StepStatus(id: "vpn", label: "复原 OneVPN 设置", status: "pending", detail: "待执行"),
            StepStatus(id: "region", label: "复原地区与时区", status: "pending", detail: "待执行"),
        ]
        // 1. Firewall / Dock watcher / LuLu managed rules / Profile
        let fwRes: SetupResult
        do {
            fwRes = try firewall("restore")
            steps[0] = StepStatus(id: "firewall", label: "复原防火墙、代理与监护", status: fwRes.status, detail: fwRes.message)
        } catch {
            let errMsg = (error as? HostFailure)?.errorDescription ?? "防火墙复原未能完成。"
            steps[0] = StepStatus(id: "firewall", label: "复原防火墙、代理与监护", status: "error", detail: errMsg)
            return SetupResult(status: "error", message: errMsg, steps: steps)
        }
        if fwRes.status != "ok" {
            return SetupResult(status: fwRes.status, message: fwRes.message, destination: fwRes.destination,
                               extraDestination: fwRes.extraDestination, steps: steps)
        }
        // 2. OneVPN restore
        let vpnRes: SetupResult
        do {
            vpnRes = try configureVpnFlow(restore: true)
            steps[1] = StepStatus(id: "vpn", label: "复原 OneVPN 设置", status: vpnRes.status, detail: vpnRes.message)
        } catch {
            let errMsg = (error as? HostFailure)?.errorDescription ?? "OneVPN 复原未能完成。"
            steps[1] = StepStatus(id: "vpn", label: "复原 OneVPN 设置", status: "error", detail: errMsg)
            return SetupResult(status: "error", message: "1. " + fwRes.message + "\n2. " + errMsg, steps: steps)
        }
        if vpnRes.status != "ok" {
            return SetupResult(status: vpnRes.status, message: "1. " + fwRes.message + "\n2. " + vpnRes.message,
                               destination: vpnRes.destination, steps: steps)
        }
        // 3. Region & Timezone restore
        do {
            let regionMsg = try regional("restore")
            steps[2] = StepStatus(id: "region", label: "复原地区与时区", status: "ok", detail: regionMsg)
            return SetupResult(status: "ok",
                               message: "一键复原已完成：" + fwRes.message + " " + vpnRes.message + " " + regionMsg,
                               steps: steps)
        } catch {
            let errMsg = (error as? HostFailure)?.errorDescription ?? "地区和时区复原未能完成。"
            steps[2] = StepStatus(id: "region", label: "复原地区与时区", status: "error", detail: errMsg)
            return SetupResult(status: "error",
                               message: "1. " + fwRes.message + "\n2. " + vpnRes.message + "\n3. " + errMsg,
                               steps: steps)
        }

    default:
        throw HostFailure("不支持的操作。")
    }
}

@main
private final class Preflight: NSObject, NSApplicationDelegate, NSWindowDelegate,
                                WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandler {
    private var window: NSWindow!
    private var web: WKWebView!
    private var server: Process?
    private var origin: URL?
    private var busy = false
    private var checked = false
    private var quitting = false

    static func main() {
        let app = NSApplication.shared
        let delegate = Preflight()
        app.setActivationPolicy(.regular)
        app.delegate = delegate
        withExtendedLifetime(delegate) { app.run() }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        installMenu()
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1320, height: 900),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                          backing: .buffered, defer: false)
        window.minSize = NSSize(width: 1060, height: 740)
        window.title = "Preflight"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isMovableByWindowBackground = true
        window.isOpaque = false
        window.backgroundColor = .clear
        window.appearance = NSAppearance(named: .darkAqua)
        window.isReleasedWhenClosed = false
        window.delegate = self
        window.center()

        let backdrop = NSVisualEffectView()
        backdrop.material = .hudWindow
        backdrop.blendingMode = .behindWindow
        backdrop.state = .followsWindowActiveState
        window.contentView = backdrop
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        let start = """
            (() => {
              const mark = () => { if (!document.documentElement) return false;
                document.documentElement.dataset.platform = 'mac'; return true; };
              if (!mark()) { const o = new MutationObserver(() => { if (mark()) o.disconnect(); });
                o.observe(document, {childList:true}); }
            })()
            """
        config.userContentController.addUserScript(WKUserScript(source: start, injectionTime: .atDocumentStart,
                                                              forMainFrameOnly: true))
        config.userContentController.add(self, name: "preflight")
        web = WKWebView(frame: .zero, configuration: config)
        web.setValue(false, forKey: "drawsBackground")
        web.navigationDelegate = self
        web.uiDelegate = self
        web.translatesAutoresizingMaskIntoConstraints = false
        backdrop.addSubview(web)
        NSLayoutConstraint.activate([web.leadingAnchor.constraint(equalTo: backdrop.leadingAnchor),
                                     web.trailingAnchor.constraint(equalTo: backdrop.trailingAnchor),
                                     web.topAnchor.constraint(equalTo: backdrop.topAnchor),
                                     web.bottomAnchor.constraint(equalTo: backdrop.bottomAnchor)])
        show()
        startServer()
    }

    private func installMenu() {
        let menu = NSMenu()
        let app = NSMenuItem()
        app.submenu = NSMenu(title: "Preflight")
        app.submenu?.addItem(withTitle: "关于 Preflight", action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        app.submenu?.addItem(.separator())
        app.submenu?.addItem(withTitle: "隐藏 Preflight", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        app.submenu?.addItem(withTitle: "退出 Preflight", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(app)
        let edit = NSMenuItem()
        edit.submenu = NSMenu(title: "编辑")
        for (title, selector, key) in [("剪切", "cut:", "x"), ("复制", "copy:", "c"),
                                       ("粘贴", "paste:", "v"), ("全选", "selectAll:", "a")] {
            edit.submenu?.addItem(withTitle: title, action: Selector(selector), keyEquivalent: key)
        }
        menu.addItem(edit)
        let windowMenu = NSMenuItem()
        windowMenu.submenu = NSMenu(title: "窗口")
        windowMenu.submenu?.addItem(withTitle: "关闭窗口", action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        windowMenu.submenu?.addItem(withTitle: "最小化", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        menu.addItem(windowMenu)
        NSApp.mainMenu = menu
    }

    private func show() {
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        show()
        return true
    }

    func applicationWillTerminate(_ notification: Notification) {
        quitting = true
        if let server, server.isRunning { server.terminate() }
    }

    private func sheet(_ message: String) {
        let alert = NSAlert()
        alert.messageText = "Preflight"
        alert.informativeText = message
        alert.addButton(withTitle: "知道了")
        alert.beginSheetModal(for: window)
    }

    private func startServer() {
        let task = python(["ui", "--no-open", "--port", "0"])
        let pipe = Pipe()
        task.standardOutput = pipe
        task.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async {
                guard let self, !self.quitting, self.server === task else { return }
                self.origin = nil
                self.server = nil
                self.sheet("本机面板服务已停止。请退出并重新打开 Preflight。")
            }
        }
        do { try task.run() } catch {
            sheet("本机服务无法启动。请确认系统 Python 3 可用。")
            return
        }
        server = task
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let handle = pipe.fileHandleForReading
            var line = Data()
            defer { try? handle.close() }
            while line.count < 48, let byte = try? handle.read(upToCount: 1), !byte.isEmpty {
                if byte.first == 10 { break }
                line.append(byte)
            }
            guard let text = String(data: line, encoding: .ascii),
                  text.range(of: #"^http://127\.0\.0\.1:[1-9][0-9]{0,4}/$"#, options: .regularExpression) != nil,
                  let url = URL(string: text), let port = url.port, (1...65535).contains(port) else {
                if task.isRunning { task.terminate() }
                return
            }
            DispatchQueue.main.async {
                guard let self, self.server === task, task.isRunning else { return }
                self.origin = url
                self.web.load(URLRequest(url: url))
            }
        }
    }

    private func local(_ url: URL?) -> Bool {
        guard let origin, let url else { return false }
        return url.scheme == "http" && url.host == "127.0.0.1" && url.port == origin.port
            && url.user == nil && url.password == nil
    }

    private func openExternal(_ url: URL) {
        guard url.user == nil, url.password == nil else { return }
        let host = url.host?.lowercased()
        let project = host == "github.com" && (url.path == "/fxjcangku/claude-preflight" ||
                                                 url.path.hasPrefix("/fxjcangku/claude-preflight/"))
        let official = ["claude.ai", "claude.com", "anthropic.com", "objective-see.org",
                        "support.apple.com", "fxjcangku.github.io"].contains(host ?? "")
        if (url.scheme == "https" && (official || project) && (url.port == nil || url.port == 443)) ||
            (url.scheme == "http" && host == "127.0.0.1") {
            NSWorkspace.shared.open(url)
        }
    }

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = action.request.url else { decisionHandler(.cancel); return }
        if local(url), action.targetFrame?.isMainFrame == true { decisionHandler(.allow); return }
        decisionHandler(.cancel)
        if action.sourceFrame.isMainFrame && action.navigationType == .linkActivated { openExternal(url) }
    }

    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for action: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if action.sourceFrame.isMainFrame, action.navigationType == .linkActivated, let url = action.request.url {
            openExternal(url)
        }
        return nil
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard !checked, local(webView.url), webView.url?.path == "/" else { return }
        checked = true
        work.async { [weak self] in
            guard let result = try? request(["configure", "--action", "status"]) else { return }
            let ok = result["ok"] as? Bool == true
            let matches = result["configured"] as? Bool == true
            let message = ok ? (matches ? "已就绪：当前地区和时区符合台湾设置。" : "已读取本机环境，点击「一键配置」开始。") : "未能读取当前地区和时区。"
            DispatchQueue.main.async { [weak self] in
                guard let self, !self.busy else { return }
                self.publish("status", SetupResult(status: ok ? "ok" : "error", message: message))
            }
        }
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        let frame = message.frameInfo
        guard message.webView === web, message.name == "preflight", frame.isMainFrame,
              local(web.url), web.url?.path == "/", frame.securityOrigin.protocol == "http",
              frame.securityOrigin.host == "127.0.0.1", frame.securityOrigin.port == origin?.port,
              let body = message.body as? Reply, body.count == 1,
              let action = body["action"] as? String, actions.contains(action), !busy else { return }
        busy = true
        work.async { [weak self] in
            let result: SetupResult
            do { result = try setup(action) }
            catch let error as HostFailure { result = SetupResult(status: "error", message: error.errorDescription ?? "设置未能完成。") }
            catch { result = SetupResult(status: "error", message: "设置服务未能完成操作，请重试。") }
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.busy = false
                self.show()
                self.publish(action, result)
                if result.status == "pending" {
                    self.sheet(result.message)
                    if let url = result.destination { NSWorkspace.shared.open(url) }
                    if let extra = result.extraDestination { NSWorkspace.shared.open(extra) }
                }
            }
        }
    }

    private func publish(_ action: String, _ result: SetupResult) {
        guard local(web.url), web.url?.path == "/" else { return }
        var payload: Reply = [
            "action": action,
            "ok": result.status == "ok",
            "status": result.status,
            "message": result.message,
            "actionRequired": result.status == "pending",
        ]
        if !result.steps.isEmpty {
            payload["steps"] = result.steps.map { $0.toDict() }
        }
        web.callAsyncJavaScript("window.preflightNativeSetupResult?.(payload)", arguments: ["payload": payload],
                                in: nil, in: .page) { _ in }
    }
}
