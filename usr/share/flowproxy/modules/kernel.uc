/**
 * FlowProxy | modules/kernel.uc
 * Role: read-only sing-box release check. The self-use edition must not
 * download, install, replace, restart, or roll back the kernel binary.
 */

'use strict';

import { cursor } from 'uci';

import { PATH, BIN, LIMIT } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { with_changed } from 'flowproxy.core.module_result';
import { ExecSafe } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';
import { fetch_with_policy } from 'flowproxy.core.resource_fetch';

function _strip_v(tag) {
    return replace(sprintf("%s", tag || ""), regexp('^v'), "");
}

function _current_version(trace_id) {
    let res = ExecSafe(BIN.SINGBOX, ["version"], { timeout: 3 }, trace_id);
    if (!res.ok || !res.data || !res.data.stdout) return "unknown";

    let lines = split(res.data.stdout || "", "\n");
    for (let i = 0; i < length(lines); i++) {
        let v = match(lines[i], regexp('^sing-box version (.*)'));
        if (v) return trim(v[1] || "");
    }
    return "unknown";
}

function _openwrt_arch(trace_id) {
    let arch_res = ExecSafe(BIN.SH, ["-c", "opkg print-architecture | awk '{print $2}' | grep -vE '^all$|^noarch$' | tail -n 1"], null, trace_id);
    let arch = (arch_res.ok && arch_res.data) ? trim(arch_res.data.stdout || "") : "";
    if (arch) return arch;

    let uname_res = ExecSafe(BIN.SH, ["-c", "uname -m"], null, trace_id);
    return (uname_res.ok && uname_res.data) ? trim(uname_res.data.stdout || "") : "";
}

function _package_ext(trace_id) {
    let chk_apk = ExecSafe(BIN.SH, ["-c", "command -v apk"], null, trace_id);
    if (chk_apk.ok && chk_apk.data && trim(chk_apk.data.stdout || "")) return "apk";
    return "ipk";
}

function _find_asset(release_data, arch, ext) {
    let assets = release_data.assets || [];
    let rx_ext = regexp(sprintf('\\.%s$', ext));
    let rx_arch = regexp(sprintf('openwrt_%s\\.%s$', arch, ext));
    let rx_aarch64_check = regexp('aarch64');
    let rx_aarch64_gen = regexp(sprintf('openwrt_aarch64_generic\\.%s$', ext));

    for (let i = 0; i < length(assets); i++) {
        let name = assets[i].name || "";
        if (match(name, rx_ext) && match(name, rx_arch)) {
            return assets[i];
        }
    }

    if (match(arch || "", rx_aarch64_check)) {
        for (let i = 0; i < length(assets); i++) {
            let name = assets[i].name || "";
            if (match(name, rx_ext) && match(name, rx_aarch64_gen)) {
                return assets[i];
            }
        }
    }

    return null;
}

function _summary(body) {
    let s = sprintf("%s", body || "");
    s = replace(s, "\r", "\n");
    let lines = split(s, "\n");
    let out = [];
    for (let i = 0; i < length(lines); i++) {
        let line = trim(lines[i] || "");
        if (!line) continue;
        push(out, line);
        if (length(out) >= 6) break;
    }
    let text = join("\n", out);
    if (length(text) > 700) text = substr(text, 0, 700) + "...";
    return text;
}

function _select_release(track, body, trace_id) {
    let decoded = null;
    try {
        decoded = json(body || "");
    } catch (e) {
        log(trace_id, 'WARN', 'KERNEL', 'GitHub release JSON parse failed: ' + e);
        return null;
    }

    if (track === "stable") {
        return type(decoded) === "object" ? decoded : null;
    }

    if (type(decoded) === "array") {
        for (let i = 0; i < length(decoded); i++) {
            let item = decoded[i];
            if (item && item.prerelease === true && item.tag_name) return item;
        }
    }

    return null;
}

function _github_release(track, trace_id) {
    let u = cursor();
    u.load("flowproxy");
    let token = u.get("flowproxy", "config", "github_token") || "";

    let api_url = "https://api.github.com/repos/SagerNet/sing-box/releases";
    if (track === "stable") api_url += "/latest";
    else api_url += "?per_page=5";

    let extra_args = [
        "-H", "User-Agent: FlowProxy-OpenWrt-Gateway/1.0"
    ];
    if (token) {
        push(extra_args, "-H", "Authorization: token " + token);
    }

    let api_fetch = fetch_with_policy(api_url, null, 'github_api', trace_id, {
        timeout_sec: LIMIT.DL_TIMEOUT,
        extra_args: extra_args,
        fail_on_http: false
    });

    if (!api_fetch.ok || int(api_fetch.http_code || "0") < 200 || int(api_fetch.http_code || "0") >= 300) {
        return Fail(ERR.E_SYSTEM_BUSY, sprintf(
            "GitHub API check failed (effective=%s exit=%d http=%s).",
            api_fetch.effective_mode || "none",
            api_fetch.exit_code || 0,
            api_fetch.http_code || "-"
        ), trace_id);
    }

    let release_data = _select_release(track, api_fetch.response_body || "", trace_id);
    if (!release_data || !release_data.tag_name) {
        return Fail(ERR.E_SYSTEM_BUSY, "GitHub API returned no usable release for track=" + track, trace_id);
    }

    return Success(release_data, 200, trace_id);
}

/**
 * Compatibility entry point: update_kernel now means read-only update check.
 * It intentionally never downloads packages, replaces /usr/bin/sing-box,
 * creates .bak files, restarts services, or touches dataplane state.
 */
function task_update_kernel(trace_id, payload) {
    try {
        let safe_payload = payload || {};
        let track = safe_payload.track === "beta" ? "beta" : "stable";

        log(trace_id, 'INFO', 'KERNEL', 'Checking latest sing-box version, track=' + track);

        let current_version = _current_version(trace_id);
        let arch = _openwrt_arch(trace_id);
        let package_ext = _package_ext(trace_id);
        if (!arch) return Fail(ERR.E_SYSTEM_BUSY, "Unable to detect OpenWrt architecture", trace_id);

        let release_res = _github_release(track, trace_id);
        if (!release_res.ok) return release_res;
        let release_data = release_res.data;

        let latest_version = _strip_v(release_data.tag_name);
        let asset = _find_asset(release_data, arch, package_ext);
        let download_url = asset ? (asset.browser_download_url || "") : "";
        let asset_name = asset ? (asset.name || "") : "";
        let update_available = current_version !== "unknown" && latest_version !== "" && current_version !== latest_version;

        log(trace_id, 'INFO', 'KERNEL', sprintf(
            'Latest %s version detected: current=%s latest=%s update_available=%s',
            track,
            current_version,
            latest_version,
            update_available ? "true" : "false"
        ));

        return Success(with_changed(false, {
            current_version: current_version,
            latest_version: latest_version,
            update_available: update_available,
            track: track,
            target_arch: arch,
            package_type: package_ext,
            asset_name: asset_name,
            download_url: download_url,
            release_url: release_data.html_url || "",
            published_at: release_data.published_at || "",
            summary: _summary(release_data.body || ""),
            runtime_applied: false,
            kernel_installed: false,
            download_performed: false,
            restart_performed: false,
            msg: sprintf(
                "Kernel update check complete: current=%s latest=%s track=%s update_available=%s",
                current_version,
                latest_version,
                track,
                update_available ? "true" : "false"
            )
        }), 200, trace_id);

    } catch (e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'KERNEL', 'Kernel update check crashed: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "Kernel update check crashed: " + err_msg, trace_id);
    }
}

export { task_update_kernel };
