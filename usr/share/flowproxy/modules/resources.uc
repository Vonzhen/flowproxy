/**
 * FlowProxy | modules/resources.uc | v1.1 Dual-Source Edition
 * 职责：负责远端资源（境内外 IP、域名分流白名单）的异步拉取、版本校验与本地落盘。
 * 核心对齐：GitHub raw 主源 + jsDelivr 容灾，全链路 curl/HTTP/体积/内容校验。
 */

'use strict';

// 1. [解构原生库] 遵守铁律 5
import { readfile, writefile, stat } from 'fs';
import { cursor } from 'uci';

// 2. [引入基石法则] 遵守铁律 3
import { PATH, BIN, LIMIT } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { with_changed } from 'flowproxy.core.module_result';
import { ExecSafe, shell_escape } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';
import { fetch_with_policy } from 'flowproxy.core.resource_fetch';

const MIN_DL_BYTES = 16;
const RESOURCE_BACKUP_DIR = sprintf("%s/backup/resources", PATH.RUNTIME);
const RESOURCE_TARGETS = [ "china_ip4", "china_ip6", "gfw_list", "china_list" ];

// [资源武器库映射字典]
const RESOURCES = {
    'china_ip4':  { repo: '1715173329/IPCIDR-CHINA',  ref: 'master',  file: 'ipv4.txt',        post_process: false },
    'china_ip6':  { repo: '1715173329/IPCIDR-CHINA',  ref: 'master',  file: 'ipv6.txt',        post_process: false },
    'gfw_list':   { repo: 'Loyalsoldier/v2ray-rules-dat', ref: 'release', file: 'gfw.txt',         post_process: false },
    'china_list': { repo: 'Loyalsoldier/v2ray-rules-dat', ref: 'release', file: 'direct-list.txt', post_process: true }
};

function _http_ok(code_str) {
    let c = trim(code_str || "");
    if (length(c) < 3) return false;
    let lead = substr(c, 0, 1);
    return (lead === '2' || lead === '3');
}

function _is_html_error(content) {
    if (!content || length(content) < 5) return false;
    let head = substr(content, 0, 512);
    return (match(head, regexp('<html', 'i')) || match(head, regexp('<!doctype\\s+html', 'i')));
}

function _validate_file_body(path) {
    let st = stat(path);
    if (!st || !st.size || st.size < MIN_DL_BYTES) {
        return { ok: false, error: "empty_payload", file_size: (st && st.size) ? st.size : 0 };
    }
    let sample = readfile(path);
    if (!sample || length(sample) === 0) {
        return { ok: false, error: "empty_payload", file_size: 0 };
    }
    if (_is_html_error(sample)) {
        return { ok: false, error: "html_error_page", file_size: st.size };
    }
    return { ok: true, file_size: st.size };
}

function _curl_download(url, temp_file, trace_id) {
    let res = fetch_with_policy(url, temp_file, 'asset_download', trace_id, {
        timeout_sec: LIMIT.DL_TIMEOUT
    });

    if (!res.ok) {
        ExecSafe(BIN.RM, ['-f', temp_file], null, trace_id);
        return {
            ok: false,
            error: res.error || "curl_failed",
            curl_exit: res.curl_exit,
            http_code: res.http_code || "0",
            file_size: res.file_size || 0,
            effective: res.effective || "none"
        };
    }

    let http_code = res.http_code || "";
    if (!_http_ok(http_code)) {
        ExecSafe(BIN.RM, ['-f', temp_file], null, trace_id);
        return { ok: false, error: "http_error", curl_exit: res.curl_exit, http_code: http_code, file_size: 0 };
    }

    let valid = _validate_file_body(temp_file);
    if (!valid.ok) {
        ExecSafe(BIN.RM, ['-f', temp_file], null, trace_id);
        return {
            ok: false,
            error: valid.error,
            curl_exit: res.curl_exit,
            http_code: http_code,
            file_size: valid.file_size || 0
        };
    }

    return { ok: true, curl_exit: res.curl_exit, http_code: http_code, file_size: valid.file_size, effective: res.effective };
}

function _download_dual_source(res_info, commit_sha, temp_file, trace_id) {
    let raw_url = sprintf("https://raw.githubusercontent.com/%s/%s/%s", res_info.repo, commit_sha, res_info.file);
    let cdn_url = sprintf("https://fastly.jsdelivr.net/gh/%s@%s/%s", res_info.repo, commit_sha, res_info.file);

    let primary = _curl_download(raw_url, temp_file, trace_id);
    if (primary.ok) {
        primary.source = "primary";
        return primary;
    }

    log(trace_id, 'WARN', 'RESOURCES', sprintf(
        "Primary (GitHub raw) failed: %s curl_exit=%d http=%s",
        primary.error || "unknown", primary.curl_exit, primary.http_code || "-"
    ));

    let fallback = _curl_download(cdn_url, temp_file, trace_id);
    if (fallback.ok) {
        fallback.source = "fallback";
        return fallback;
    }

    log(trace_id, 'WARN', 'RESOURCES', sprintf(
        "Fallback (jsdelivr) failed: %s curl_exit=%d http=%s",
        fallback.error || "unknown", fallback.curl_exit, fallback.http_code || "-"
    ));

    return {
        ok: false,
        error: "download_failed",
        source: "none",
        curl_exit: fallback.curl_exit,
        http_code: fallback.http_code,
        file_size: fallback.file_size || 0,
        primary_error: primary.error,
        fallback_error: fallback.error
    };
}

function _Log(module, level, msg, trace_id) {
    log(trace_id, level, module || 'RESOURCES', msg);
}

function backup_resources(trace_id, log_module) {
    let bak_path = sprintf("%s/%s", RESOURCE_BACKUP_DIR, trace_id);
    ExecSafe(BIN.RM, ["-rf", bak_path], null, trace_id);
    ExecSafe(BIN.MKDIR, ["-p", RESOURCE_BACKUP_DIR], null, trace_id);
    let cmd = sprintf("if [ -d %s ]; then cp -a %s %s; else mkdir -p %s; fi",
        shell_escape(PATH.ASSETS),
        shell_escape(PATH.ASSETS),
        shell_escape(bak_path),
        shell_escape(bak_path)
    );
    let res = ExecSafe(BIN.SH, ["-c", cmd], null, trace_id);
    if (!res.ok) {
        return Fail(ERR.E_SYSTEM_BUSY, "resource backup failed: " + res.detail, trace_id);
    }
    _Log(log_module, 'INFO', 'resource backup created: ' + bak_path, trace_id);
    return Success({ path: bak_path }, 200, trace_id);
}

function restore_resources(trace_id, bak_path, log_module) {
    _Log(log_module, 'WARN', 'rollback resources attempted', trace_id);
    if (!bak_path) return Fail(ERR.E_SYSTEM_BUSY, "resource backup path missing", trace_id);
    let cmd = sprintf("rm -rf %s; mkdir -p %s; if [ -d %s ]; then cp -a %s/. %s/; fi",
        shell_escape(PATH.ASSETS),
        shell_escape(PATH.ASSETS),
        shell_escape(bak_path),
        shell_escape(bak_path),
        shell_escape(PATH.ASSETS)
    );
    let res = ExecSafe(BIN.SH, ["-c", cmd], null, trace_id);
    if (!res.ok) {
        _Log(log_module, 'ERROR', 'rollback resources failed: ' + res.detail, trace_id);
        return Fail(ERR.E_SYSTEM_BUSY, "resource rollback failed: " + res.detail, trace_id);
    }
    _Log(log_module, 'WARN', 'rollback resources success', trace_id);
    return Success(true, 200, trace_id);
}

function _deploy_stage_atomic(stage_file, final_file, list_type, trace_id) {
    let bak_file = final_file + ".bak";
    let stage_valid = _validate_file_body(stage_file);
    if (!stage_valid.ok) {
        ExecSafe(BIN.RM, ['-f', stage_file], null, trace_id);
        let fail_res = Fail(ERR.E_SYSTEM_BUSY, sprintf(
            "Staged output invalid for [%s]: %s (size=%d)",
            list_type, stage_valid.error, stage_valid.file_size || 0
        ), trace_id);
        fail_res.data = {
            stage_file: stage_file,
            final_file: final_file,
            bak_file: bak_file,
            restore_attempted: false,
            restore_success: false,
            restore_failed: false,
            danger_state: false
        };
        return fail_res;
    }

    if (stat(final_file)) {
        let bak_res = ExecSafe(BIN.CP, ['-f', final_file, bak_file], null, trace_id);
        if (!bak_res.ok) {
            ExecSafe(BIN.RM, ['-f', stage_file], null, trace_id);
            let fail_res = Fail(ERR.E_SYSTEM_BUSY, sprintf("Backup current resource failed for [%s]: %s", list_type, bak_res.detail), trace_id);
            fail_res.data = {
                stage_file: stage_file,
                final_file: final_file,
                bak_file: bak_file,
                restore_attempted: false,
                restore_success: false,
                restore_failed: false,
                danger_state: false
            };
            return fail_res;
        }
    }

    let mv_res = ExecSafe(BIN.MV, ['-f', stage_file, final_file], null, trace_id);
    if (!mv_res.ok) {
        let restore_attempted = false;
        let restore_success = false;
        if (stat(bak_file)) {
            restore_attempted = true;
            let restore_res = ExecSafe(BIN.CP, ['-f', bak_file, final_file], null, trace_id);
            restore_success = restore_res.ok && stat(final_file);
        }
        ExecSafe(BIN.RM, ['-f', stage_file], null, trace_id);
        let fail_res = Fail(ERR.E_SYSTEM_BUSY, sprintf("Atomic resource deploy failed for [%s]: %s", list_type, mv_res.detail), trace_id);
        fail_res.data = {
            stage_file: stage_file,
            final_file: final_file,
            bak_file: bak_file,
            restore_attempted: restore_attempted,
            restore_success: restore_success,
            restore_failed: restore_attempted && !restore_success,
            danger_state: restore_attempted && !restore_success
        };
        return fail_res;
    }

    let final_valid = _validate_file_body(final_file);
    if (!final_valid.ok) {
        let restore_attempted = false;
        let restore_success = false;
        if (stat(bak_file)) {
            restore_attempted = true;
            let restore_res = ExecSafe(BIN.CP, ['-f', bak_file, final_file], null, trace_id);
            restore_success = restore_res.ok && stat(final_file);
        } else {
            ExecSafe(BIN.RM, ['-f', final_file], null, trace_id);
        }
        let fail_res = Fail(ERR.E_SYSTEM_BUSY, sprintf(
            "Deployed resource invalid for [%s]: %s (size=%d)",
            list_type, final_valid.error, final_valid.file_size || 0
        ), trace_id);
        fail_res.data = {
            stage_file: stage_file,
            final_file: final_file,
            bak_file: bak_file,
            restore_attempted: restore_attempted,
            restore_success: restore_success,
            restore_failed: restore_attempted && !restore_success,
            danger_state: restore_attempted && !restore_success
        };
        return fail_res;
    }

    return Success({ file_size: final_valid.file_size }, 200, trace_id);
}

/**
 * 核心业务：拉取并更新指定的物理规则资源
 * @param {string} trace_id - 贯穿始终的链路 ID
 * @param {string} list_type - 资源类型 (如 china_ip4)
 */
function task_update_resources(trace_id, list_type) {
    try {
        let res_info = RESOURCES[list_type];
        if (!res_info) {
            return Fail(ERR.E_CONFIG_FAULT, sprintf("Unknown resource target: %s", list_type), trace_id);
        }

        log(trace_id, 'INFO', 'RESOURCES', sprintf("Initializing update sequence for [%s]...", list_type));

        let u = cursor();
        u.load('flowproxy');
        let github_token = u.get('flowproxy', 'config', 'github_token');

        // ====================================================================
        // 第一阶段：通过 GitHub API 探测最新 Commit SHA 与版本号
        // ====================================================================
        let api_url = sprintf("https://api.github.com/repos/%s/commits?sha=%s&path=%s&per_page=1", res_info.repo, res_info.ref, res_info.file);
        let api_tmp = sprintf("%s/%s.github_api.tmp", PATH.RUNTIME, list_type);
        let extra_args = [];
        if (github_token) {
            push(extra_args, '-H', sprintf("Authorization: Bearer %s", github_token));
        }

        let api_fetch = fetch_with_policy(api_url, api_tmp, 'github_api', trace_id, {
            timeout_sec: LIMIT.DL_TIMEOUT,
            extra_args: extra_args
        });
        if (!api_fetch.ok) {
            ExecSafe(BIN.RM, ['-f', api_tmp], null, trace_id);
            return Fail(ERR.E_NETWORK_FAULT, sprintf(
                "Failed to fetch version info for [%s] via GitHub API (effective=%s, %s).",
                list_type, api_fetch.effective || "none", api_fetch.error || "unknown"
            ), trace_id);
        }

        let api_body = readfile(api_tmp);
        ExecSafe(BIN.RM, ['-f', api_tmp], null, trace_id);
        if (!api_body || length(api_body) === 0) {
            return Fail(ERR.E_NETWORK_FAULT, sprintf("Empty GitHub API response for [%s].", list_type), trace_id);
        }

        let api_json = json(api_body);
        if (!api_json || type(api_json) !== 'array' || length(api_json) === 0) {
            return Fail(ERR.E_NETWORK_FAULT, sprintf("Invalid JSON response from GitHub API for [%s].", list_type), trace_id);
        }

        let commit_sha = api_json[0].sha;
        let commit_msg = api_json[0].commit ? api_json[0].commit.message : "";

        let list_ver = "";
        let ver_match = match(commit_msg, /([0-9\-]+)/);
        if (ver_match && ver_match[1]) {
            list_ver = replace(ver_match[1], '-', '');
        }
        if (!list_ver || length(list_ver) === 0) {
            list_ver = substr(commit_sha, 0, 8);
        }

        // ====================================================================
        // 第二阶段：版本对齐，跳过无意义的重复下载
        // ====================================================================
        let ver_path = sprintf("%s/%s.ver", PATH.ASSETS, list_type);
        let local_ver = readfile(ver_path);

        if (local_ver) {
            local_ver = trim(local_ver);
            if (local_ver === list_ver) {
                log(trace_id, 'INFO', 'RESOURCES', sprintf("[%s] is already at the latest version: %s.", list_type, list_ver));
                return Success(with_changed(false, { version: list_ver }), 200, trace_id);
            }
        }

        log(trace_id, 'INFO', 'RESOURCES', sprintf("[%s] Version mismatch (Local: %s, Remote: %s). Initiating pull...", list_type, local_ver || "NONE", list_ver));

        // ====================================================================
        // 第三阶段：双源下载 (GitHub raw → jsDelivr fallback)
        // ====================================================================
        let temp_file = sprintf("%s/%s.tmp", PATH.RUNTIME, list_type);
        let dl_meta = _download_dual_source(res_info, commit_sha, temp_file, trace_id);

        if (!dl_meta.ok) {
            ExecSafe(BIN.RM, ['-f', temp_file], null, trace_id);
            return Fail(ERR.E_NETWORK_FAULT, sprintf(
                "Download failed for [%s]: %s (primary=%s, fallback=%s, http=%s, size=%d)",
                list_type,
                dl_meta.error || "download_failed",
                dl_meta.primary_error || "-",
                dl_meta.fallback_error || "-",
                dl_meta.http_code || "-",
                dl_meta.file_size || 0
            ), trace_id);
        }

        log(trace_id, 'INFO', 'RESOURCES', sprintf(
            "[%s] Download OK via %s (http=%s, size=%d, curl_exit=%d)",
            list_type, dl_meta.source, dl_meta.http_code, dl_meta.file_size, dl_meta.curl_exit
        ));

        // ====================================================================
        // 第四阶段：物理后处理 (Post-Processing) 与正式部署
        // ====================================================================
        let final_file = sprintf("%s/%s.txt", PATH.ASSETS, list_type);
        let stage_file = final_file + ".stage";
        ExecSafe(BIN.RM, ['-f', stage_file], null, trace_id);

        if (res_info.post_process) {
            log(trace_id, 'INFO', 'RESOURCES', sprintf("[%s] Engaging sed post-processing engine...", list_type));

            let sh_cmd = sprintf("sed -e 's/full://g' -e '/:/d' %s > %s", shell_escape(temp_file), shell_escape(stage_file));
            let proc_res = ExecSafe(BIN.SH, ['-c', sh_cmd], null, trace_id);
            ExecSafe(BIN.RM, ['-f', temp_file], null, trace_id);

            if (!proc_res.ok) {
                ExecSafe(BIN.RM, ['-f', stage_file], null, trace_id);
                return Fail(ERR.E_SYSTEM_BUSY, sprintf(
                    "Post-processing failed for [%s] (sed exit, file not deployed)",
                    list_type
                ), trace_id);
            }

            let deploy_res = _deploy_stage_atomic(stage_file, final_file, list_type, trace_id);
            if (!deploy_res.ok) return deploy_res;
            dl_meta.file_size = deploy_res.data.file_size;
        } else {
            let mv_res = ExecSafe(BIN.MV, ['-f', temp_file, stage_file], null, trace_id);
            if (!mv_res.ok) {
                ExecSafe(BIN.RM, ['-f', temp_file], null, trace_id);
                return Fail(ERR.E_SYSTEM_BUSY, sprintf("Deployment move failed for [%s].", list_type), trace_id);
            }
            let deploy_res = _deploy_stage_atomic(stage_file, final_file, list_type, trace_id);
            if (!deploy_res.ok) return deploy_res;
            dl_meta.file_size = deploy_res.data.file_size;
        }

        writefile(ver_path, list_ver + '\n');
        log(trace_id, 'INFO', 'RESOURCES', sprintf("[%s] Successfully armed with latest ruleset: %s", list_type, list_ver));

        return Success(with_changed(true, {
            version: list_ver,
            source: dl_meta.source,
            curl_exit: dl_meta.curl_exit,
            http_code: dl_meta.http_code,
            file_size: dl_meta.file_size
        }), 200, trace_id);

    } catch(e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'RESOURCES', sprintf("Exception breached in task_update_resources(%s): %s", list_type, err_msg));
        return Fail(ERR.E_SYSTEM_BUSY, err_msg, trace_id);
    }
}

function task_update_resources_summary(trace_id, payload) {
    payload = payload || {};
    let res = task_update_resources(trace_id, payload.target);
    if (!res.ok) return Fail(ERR.E_SYSTEM_BUSY, res.detail, trace_id);

    let data = res.data || {};
    let changed = !!data.changed;
    let msg = "";
    if (changed) {
        msg = sprintf("✅ 资源 [%s] 更新成功！当前版本: %s", payload.target, data.version);
        msg += "%0A[RESTART_PENDING]";
    } else {
        msg = sprintf("✅ 资源 [%s] 已是最新版本: %s", payload.target, data.version);
        msg += "%0A♻️ 服务无需重启";
    }
    return Success(with_changed(changed, { msg: msg, version: data.version }), 200, trace_id);
}

function task_update_resources_all(trace_id, payload) {
    let updated = [];
    let unchanged = [];
    let failed = [];
    let version_map = {};

    for (let i = 0; i < length(RESOURCE_TARGETS); i++) {
        let target = RESOURCE_TARGETS[i];
        let res = task_update_resources(trace_id, target);
        if (!res.ok) {
            push(failed, target);
            continue;
        }
        let data = res.data || {};
        version_map[target] = data.version || "";
        if (data.changed) push(updated, target);
        else push(unchanged, target);
    }

    if (length(updated) === 0 && length(unchanged) === 0 && length(failed) > 0) {
        return Fail(ERR.E_SYSTEM_BUSY, "all resources failed: " + join(",", failed), trace_id);
    }

    return Success(with_changed(length(updated) > 0, {
        updated: updated,
        unchanged: unchanged,
        failed: failed,
        versions: version_map,
        msg: length(updated) > 0 ? "resources updated" : "resources unchanged"
    }), 200, trace_id);
}

export {
    task_update_resources,
    task_update_resources_summary,
    task_update_resources_all,
    backup_resources,
    restore_resources
};
