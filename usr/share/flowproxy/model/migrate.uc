/**
 * FlowProxy | model/migrate.uc | v1.0
 * UCI 意图版本迁移器 (SSOT Aligned Edition)
 * 职责：检测旧版 UCI 配置文件中的废弃/不兼容字段，并无缝迁移至 1.0 标准。
 * 核心对齐：全量接入 Trace 和 Result，剥离隐式异常，确保升级过程不中断业务。
 */

'use strict';

// 🚨 铁律 5: 原生模块解构导入
import { cursor } from 'uci';

// 🚨 铁律 3: 绝对命名空间寻址
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { log } from 'flowproxy.core.logger';

const U_CONFIG = 'flowproxy';

/**
 * 执行旧版 UCI 字段的自动迁移升级
 * @param {string} trace_id - 全链路追踪 ID
 */
function run_migration(trace_id) {
    log(trace_id, 'INFO', 'MIGRATE', 'Starting UCI configuration migration check...');

    try {
        let u = cursor();
        u.load(U_CONFIG);
        let changes_made = false;

        // 举例：将旧版的 log_level 字段位置从 infra 迁移到 config
        let old_log_level = u.get(U_CONFIG, 'infra', 'log_level');
        if (old_log_level != null) {
            log(trace_id, 'INFO', 'MIGRATE', 'Migrating legacy field: infra.log_level -> config.log_level');
            u.set(U_CONFIG, 'config', 'log_level', old_log_level);
            u.delete(U_CONFIG, 'infra', 'log_level');
            changes_made = true;
        }

        // 举例：清理旧版 v0.8 遗留的无用字段 (如果有)
        // let legacy_field = u.get(U_CONFIG, 'routing', 'legacy_domain_rules'); ...

        if (changes_made) {
            u.commit(U_CONFIG);
            log(trace_id, 'INFO', 'MIGRATE', 'Migration successful. Changes committed to UCI.');
        } else {
            log(trace_id, 'INFO', 'MIGRATE', 'No migration needed. UCI is up to date.');
        }

        // ⭐ 协议对齐：返回标准 Success
        return Success(true, 200, trace_id);

    } catch(e) {
        // 🚨 铁律 6：隐式异常捕获转字符串
        let err_str = "" + e;
        log(trace_id, 'WARN', 'MIGRATE', 'Migration failed (Non-fatal): ' + err_str);
        
        // 迁移失败不应导致系统崩溃，返回 200，但附带错误信息
        return Success({ migrated: false, reason: err_str }, 200, trace_id);
    }
}

// 🚨 铁律 1: 文件末尾统一导出
export { run_migration };
