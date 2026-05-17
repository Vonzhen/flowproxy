/**
 * FlowProxy | modules/resources.uc | v1.0 TProxy-Redirect Armor Edition
 * 职责：负责远端资源（境内外 IP、域名分流白名单）的异步拉取、版本校验与本地落盘。
 * 核心对齐：全量引入 ExecSafe 替代原生 shell 裸连，严格遵守 1.0 Result 通讯协议。
 */

'use strict';

// 1. [解构原生库] 遵守铁律 5
import { readfile, writefile } from 'fs';
import { cursor } from 'uci';

// 2. [引入基石法则] 遵守铁律 3
import { PATH, BIN, LIMIT } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe, shell_escape } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

// [资源武器库映射字典]
const RESOURCES = {
    'china_ip4':  { repo: '1715173329/IPCIDR-CHINA',  ref: 'master',  file: 'ipv4.txt',        post_process: false },
    'china_ip6':  { repo: '1715173329/IPCIDR-CHINA',  ref: 'master',  file: 'ipv6.txt',        post_process: false },
    'gfw_list':   { repo: 'Loyalsoldier/v2ray-rules-dat', ref: 'release', file: 'gfw.txt',         post_process: false },
    'china_list': { repo: 'Loyalsoldier/v2ray-rules-dat', ref: 'release', file: 'direct-list.txt', post_process: true }
};

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
        let curl_args = ['-sL', '-m', sprintf("%d", LIMIT.DL_TIMEOUT)];
        
        if (github_token) {
            push(curl_args, '-H', sprintf("Authorization: Bearer %s", github_token));
        }
        push(curl_args, api_url);

        let api_res = ExecSafe(BIN.CURL, curl_args, null, trace_id);
        if (!api_res.ok || !api_res.data || !api_res.data.stdout) {
            return Fail(ERR.E_NETWORK_FAULT, sprintf("Failed to fetch version info for [%s] via GitHub API.", list_type), trace_id);
        }

        let api_json = json(api_res.data.stdout);
        if (!api_json || type(api_json) !== 'array' || length(api_json) === 0) {
            return Fail(ERR.E_NETWORK_FAULT, sprintf("Invalid JSON response from GitHub API for [%s].", list_type), trace_id);
        }

        let commit_sha = api_json[0].sha;
        let commit_msg = api_json[0].commit ? api_json[0].commit.message : "";
        
        // 💡 架构战果：安全的正则版本提取，严格遵守铁律 2 (禁止复杂捕获组)
        let list_ver = "";
        let ver_match = match(commit_msg, /([0-9\-]+)/);
        if (ver_match && ver_match[1]) {
            list_ver = replace(ver_match[1], '-', '');
        }
        if (!list_ver || length(list_ver) === 0) {
            list_ver = substr(commit_sha, 0, 8); // 容错回退：使用 SHA 前 8 位作为版本
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
                return Success({ updated: false, version: list_ver }, 200, trace_id);
            }
        }

        log(trace_id, 'INFO', 'RESOURCES', sprintf("[%s] Version mismatch (Local: %s, Remote: %s). Initiating pull...", list_type, local_ver || "NONE", list_ver));

        // ====================================================================
        // 第三阶段：通过 JsDelivr 加速物理下载落盘
        // ====================================================================
        let dl_url = sprintf("https://fastly.jsdelivr.net/gh/%s@%s/%s", res_info.repo, commit_sha, res_info.file);
        let temp_file = sprintf("%s/%s.tmp", PATH.RUNTIME, list_type);
        
        let dl_args = ['-sL', '-m', sprintf("%d", LIMIT.DL_TIMEOUT), '-o', temp_file, dl_url];
        let dl_res = ExecSafe(BIN.CURL, dl_args, null, trace_id);

        if (!dl_res.ok) {
            ExecSafe(BIN.RM, ['-f', temp_file], null, trace_id); // 物理擦除残缺文件
            return Fail(ERR.E_NETWORK_FAULT, sprintf("Download sequence failed for [%s].", list_type), trace_id);
        }

        // ====================================================================
        // 第四阶段：物理后处理 (Post-Processing) 与正式部署
        // ====================================================================
        let final_file = sprintf("%s/%s.txt", PATH.ASSETS, list_type);
        
        if (res_info.post_process) {
            log(trace_id, 'INFO', 'RESOURCES', sprintf("[%s] Engaging sed post-processing engine...", list_type));
            
            // 💡 架构战果：禁止 Ucode 内存爆炸，利用底层 SH 极速清洗几十万条文本规则
            let sh_cmd = sprintf("sed -e 's/full://g' -e '/:/d' %s > %s", shell_escape(temp_file), shell_escape(final_file));
            let proc_res = ExecSafe(BIN.SH, ['-c', sh_cmd], null, trace_id);
            ExecSafe(BIN.RM, ['-f', temp_file], null, trace_id); // 销毁临时文件
            
            if (!proc_res.ok) {
                return Fail(ERR.E_SYSTEM_BUSY, sprintf("Post-processing pipeline crushed for [%s].", list_type), trace_id);
            }
        } else {
            let mv_res = ExecSafe(BIN.MV, ['-f', temp_file, final_file], null, trace_id);
            if (!mv_res.ok) {
                return Fail(ERR.E_SYSTEM_BUSY, sprintf("Deployment move failed for [%s].", list_type), trace_id);
            }
        }

        // 部署成功，写下最新烙印
        writefile(ver_path, list_ver + '\n');
        log(trace_id, 'INFO', 'RESOURCES', sprintf("[%s] Successfully armed with latest ruleset: %s", list_type, list_ver));

        // ⭐ 协议对齐：透传完整状态数据给 Worker
        return Success({ updated: true, version: list_ver }, 200, trace_id);

    } catch(e) {
        // 🚨 遵守铁律 6：隐式异常安全拦截
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'RESOURCES', sprintf("Exception breached in task_update_resources(%s): %s", list_type, err_msg));
        return Fail(ERR.E_SYSTEM_BUSY, err_msg, trace_id);
    }
}

// 🚨 遵守铁律 1: 绝对集中在文件末尾统一导出，捍卫零件主权
export { task_update_resources };
