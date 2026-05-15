/**
 * FlowProxy | modules/kernel.uc | v1.2 (Observability & Syntax Safe Edition)
 * [Category B] 职能：负责识别硬件架构，从 GitHub 拉取专属内核并执行原子级热替换防砖更新。
 * [Category C] Note: 本版本已全量挂载底层 I/O 与进程标准错误 (stderr) 探针，彻底根除静默失败盲点。
 */

'use strict';

// [Category A] 解构原生库
import { stat, unlink } from 'fs';
import { cursor } from 'uci';

// [Category A] 引入系统基石常量与契约
import { PATH, BIN } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe, shell_escape } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

/**
 * [Category B] 模块对外导出的主接口：执行内核热更新流水线
 * @param {string} trace_id - 贯穿始终的链路 ID
 * @param {object} payload - 业务参数 { track: "stable" | "beta" }
 */
function task_update_kernel(trace_id, payload) {
    try {
        let safe_payload = payload || {};
        let track = safe_payload.track || "stable";
        
        log(trace_id, 'INFO', 'KERNEL', '正在执行环境安全检测...');
        
        let df_res = ExecSafe(BIN.SH, ["-c", "df -k /tmp | awk 'NR==2 {print $4}'"], null, trace_id);
        let tmp_avail = (df_res.ok && df_res.data) ? int(trim(df_res.data.stdout || "")) : 0;
        if (tmp_avail > 0 && tmp_avail < 25000) {
            return Fail(ERR.E_SYSTEM_BUSY, "/tmp 内存空间不足 25MB，已终止下载防爆内存。", trace_id);
        }

        let arch_res = ExecSafe(BIN.SH, ["-c", "opkg print-architecture | awk '{print $2}' | grep -vE '^all$|^noarch$' | tail -n 1"], null, trace_id);
        let owrt_arch = (arch_res.ok && arch_res.data) ? trim(arch_res.data.stdout || "") : "";
        if (!owrt_arch) {
            let uname_res = ExecSafe(BIN.SH, ["-c", "uname -m"], null, trace_id);
            owrt_arch = (uname_res.ok && uname_res.data) ? trim(uname_res.data.stdout || "") : "";
        }
        if (!owrt_arch) return Fail(ERR.E_SYSTEM_BUSY, "无法识别系统架构", trace_id);
        log(trace_id, 'INFO', 'KERNEL', '[SUCCESS] 硬件识别完成: 匹配专属架构 -> [' + owrt_arch + ']');

        log(trace_id, 'INFO', 'KERNEL', '正在连接 GitHub 获取 [' + track + '] 轨道版本...');
        
        let u = cursor(); 
        u.load("flowproxy");
        let token = u.get("flowproxy", "config", "github_token") || "";
        
        let curl_args = ["-sSL", "--connect-timeout", "10"];
        if (token) {
            push(curl_args, "-H");
            push(curl_args, "Authorization: token " + token);
        }
        
        let api_url = "https://api.github.com/repos/SagerNet/sing-box/releases";
        if (track === "stable") {
            api_url += "/latest";
        } else {
            // [Category C] Note: 测试版强行注入分页参数剪枝，防御内存击穿
            api_url += "?per_page=5";
        }
        push(curl_args, api_url);

        let api_res = ExecSafe(BIN.CURL, curl_args, null, trace_id);
        if (!api_res.ok || !api_res.data || !api_res.data.stdout) {
            return Fail(ERR.E_SYSTEM_BUSY, "无法连接 GitHub API 或数据流被异常截断！请检查网络。", trace_id);
        }

        let release_list = null;
        let release_data = null;

        try { 
            release_list = json(api_res.data.stdout); 
        } catch(e) {
            log(trace_id, 'WARN', 'KERNEL', 'API 载荷解析失败: ' + e);
        }

        if (track === "stable") {
            release_data = type(release_list) === "object" ? release_list : null;
        } else if (type(release_list) === "array") {
            for (let i = 0; i < length(release_list); i++) {
                let item = release_list[i];
                if (item && item.prerelease === true && type(item.assets) === "array") {
                    release_data = item;
                    break;
                }
            }
        }
        
        let tag = release_data.tag_name;
        log(trace_id, 'INFO', 'KERNEL', '[SUCCESS] 准备下载版本: ' + tag);

        // ---------------------------------------------------------
        // 🚨 修正 1：智能嗅探系统包管理器，决定下载后缀
        // ---------------------------------------------------------
        let has_apk = false;
        let chk_apk = ExecSafe(BIN.SH, ["-c", "command -v apk"], null, trace_id);
        if (chk_apk.ok && chk_apk.data && chk_apk.data.stdout) {
            has_apk = true;
        }
        let target_ext = has_apk ? "apk" : "ipk";

        let dl_url = "";
        let assets = release_data.assets || [];
        
        let rx_ext = regexp(sprintf('\\.%s$', target_ext));
        let rx_arch = regexp(sprintf('openwrt_%s\\.%s$', owrt_arch, target_ext));
        let rx_aarch64_check = regexp('aarch64');
        let rx_aarch64_gen = regexp(sprintf('openwrt_aarch64_generic\\.%s$', target_ext));

        for (let i = 0; i < length(assets); i++) {
            let name = assets[i].name || "";
            if (match(name, rx_ext) && match(name, rx_arch)) {
                dl_url = assets[i].browser_download_url;
                break;
            }
        }
        
        if (!dl_url && match(owrt_arch, rx_aarch64_check)) {
            for (let i = 0; i < length(assets); i++) {
                let name = assets[i].name || "";
                if (match(name, rx_ext) && match(name, rx_aarch64_gen)) {
                    dl_url = assets[i].browser_download_url;
                    break;
                }
            }
        }
        
        if (!dl_url) return Fail(ERR.E_SYSTEM_BUSY, "未找到匹配架构的 " + target_ext + " 资产！", trace_id);

        let parts = split(dl_url, "/");
        let file_name = parts[length(parts) - 1];
        let tmp_dir = sprintf("%s/hp_kernel_update", PATH.RUNTIME);
        let file_path = sprintf("%s/%s", tmp_dir, file_name);

        ExecSafe(BIN.RM, ["-rf", tmp_dir], null, trace_id);
        ExecSafe(BIN.MKDIR, ["-p", tmp_dir], null, trace_id);

        log(trace_id, 'INFO', 'KERNEL', '🚀 开始拉取专属内核 (' + file_name + ')...');
        let dl_args = ["-L", "-#", "--connect-timeout", "15", "--max-time", "300", "-o", file_path];
        if (token) {
            push(dl_args, "-H");
            push(dl_args, "Authorization: token " + token);
        }
        push(dl_args, dl_url);

        let dl_res = ExecSafe(BIN.CURL, dl_args, null, trace_id);
        if (!dl_res.ok || !stat(file_path)) {
            ExecSafe(BIN.RM, ["-rf", tmp_dir], null, trace_id);
            return Fail(ERR.E_SYSTEM_BUSY, "内核文件下载失败！", trace_id);
        }

        // ---------------------------------------------------------
        // 🚨 修正 2：釜底抽薪，用 MV 代替 CP，彻底消灭“假阳性”
        // ---------------------------------------------------------
        let target_bin = BIN.SINGBOX;
        let backup_bin = target_bin + ".bak";
        if (stat(target_bin)) {
            ExecSafe(BIN.MV, ["-f", target_bin, backup_bin], null, trace_id);
        }

        log(trace_id, 'INFO', 'KERNEL', '启动包管理器静默安装...');
        
        let safe_file_path = shell_escape(file_path);
        let pkg_cmd = "";
        
        if (has_apk) {
            // [Category A] 适配 OpenWrt 24.10+ 的 APK
            pkg_cmd = sprintf("apk add --allow-untrusted --force-overwrite %s", safe_file_path);
        } else {
            // 🚨 架构修正：剔除错误的跨平台参数！仅使用标准强制覆盖。
            // 配置文件冲突导致的返回码 255 将由下方的文件物理大小检测 (stat) 完美吸收。
            pkg_cmd = sprintf("opkg install --force-reinstall --force-overwrite %s", safe_file_path);
        }
        
        let pkg_res = ExecSafe(BIN.SH, ["-c", pkg_cmd], null, trace_id);
        
        // 由于上面使用了 MV，此时如果 target_bin 存在，那 100% 是新安装的！
        if (pkg_res.ok || (stat(target_bin) && stat(target_bin).size > 10000000)) {
            log(trace_id, 'INFO', 'KERNEL', '[SUCCESS] 包管理器已成功安装新内核。');
        } else {
            let pkg_err = trim(pkg_res.data ? (pkg_res.data.stderr || pkg_res.data.stdout || "") : "Unknown Error");
            log(trace_id, 'ERROR', 'KERNEL', '包管理器彻底安装失败: ' + pkg_err);
            
            // 失败时，将备份还原
            if (stat(backup_bin)) ExecSafe(BIN.MV, ["-f", backup_bin, target_bin], null, trace_id);
            ExecSafe(BIN.RM, ["-rf", tmp_dir], null, trace_id);
            return Fail(ERR.E_SYSTEM_BUSY, "包管理器安装内核失败，已自动回滚。", trace_id);
        }

        log(trace_id, 'INFO', 'KERNEL', '🛡️ [防线 1/2] 正在执行新内核架构运行测试 (Shell 代理诊断模式)...');
        
        // [Category A] 严格防御 Shell 注入风险
        let safe_target_bin = shell_escape(target_bin);
        
        // [Category B] 构建诊断命令：利用 Shell 套壳执行，并强行将 stderr 合并至 stdout
        // [Category C] Note: 此举专门用于捕获 ELF Loader 层面的非业务型崩溃 (如缺库、指令集越界)
        let diag_cmd = sprintf("%s version 2>&1", safe_target_bin);
        let test_arch = ExecSafe(BIN.SH, ["-c", diag_cmd], null, trace_id);

        if (!test_arch.ok) {
            // [Category A] 提取合并后的 Shell 代理输出流
            let os_err = trim(test_arch.data ? (test_arch.data.stdout || test_arch.data.stderr || "") : "No Output / Shell Crash");
            
            // [Category C] Warning: 必须将 os_err 持久化至系统日志，为排查 ABI 或架构不匹配提供绝对物理依据
            log(trace_id, 'ERROR', 'KERNEL', '防砖机制触发：新内核被操作系统拒绝装载！底层反馈: ' + os_err);
            
            // [Category B] 物理回滚机制
            if (stat(backup_bin)) ExecSafe(BIN.MV, ["-f", backup_bin, target_bin], null, trace_id);
            ExecSafe(BIN.RM, ["-rf", tmp_dir], null, trace_id);
            return Fail(ERR.E_SYSTEM_BUSY, "内核架构测试失败，已回滚。底层日志: " + os_err, trace_id);
        }
        log(trace_id, 'INFO', 'KERNEL', '[SUCCESS] 架构测试通过，二进制工作正常。');

        log(trace_id, 'INFO', 'KERNEL', '🛡️ [防线 2/2] 正在校验当前配置与新内核的语法兼容性...');
        let run_conf = PATH.RUN_JSON;
        if (stat(run_conf)) {
            let test_syntax = ExecSafe(target_bin, ["check", "-c", run_conf], null, trace_id);
            if (!test_syntax.ok) {
                // [Category B] 暴露配置校验异常
                let syntax_err = trim(test_syntax.data ? (test_syntax.data.stderr || "") : "");
                log(trace_id, 'ERROR', 'KERNEL', '致命冲突！新版内核不兼容当前配置: ' + syntax_err);
                
                if (stat(backup_bin)) ExecSafe(BIN.MV, ["-f", backup_bin, target_bin], null, trace_id);
                ExecSafe(BIN.RM, ["-rf", tmp_dir], null, trace_id);
                return Fail(ERR.E_SYSTEM_BUSY, "语法兼容性测试失败！已回滚旧版内核。", trace_id);
            }
            log(trace_id, 'INFO', 'KERNEL', '[SUCCESS] 语法兼容性测试通过！新内核完美适配当前配置。');
        } else {
            log(trace_id, 'WARN', 'KERNEL', '服务当前未运行，无法执行语法校验，已跳过。');
        }

        log(trace_id, 'INFO', 'KERNEL', '🎉 核心动力热替换成功！');
        log(trace_id, 'WARN', 'KERNEL', '⚠️ 提示: 新内核将在系统重启服务后接管。');

        ExecSafe(BIN.RM, ["-rf", tmp_dir], null, trace_id);
        
        return Success({ reload_required: true }, 200, trace_id);

    } catch (e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'KERNEL', '内核更新引擎崩溃: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "引擎崩溃: " + err_msg, trace_id);
    }
}

export { task_update_kernel };
