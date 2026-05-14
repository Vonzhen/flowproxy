/**
 * FlowProxy | storage/metadata.uc | v1.0
 * 职责：存放非配置类状态数据（如资源版本号、上次更新时间等）。
 */

'use strict';

// 1. [解构原生库] 遵守铁律 5
import { readfile, writefile, rename } from 'fs';

// 2. [引入基石法则] 遵守铁律 3
import { PATH } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';

const FILE_PATH = sprintf("%s/metadata.json", PATH.ASSETS);
const TMP_PATH = sprintf("%s/metadata.json.tmp", PATH.ASSETS);

let _cache = null;

function _load() {
    if (_cache !== null) return;
    try {
        let content = readfile(FILE_PATH);
        if (content) {
            _cache = json(content) || {};
        } else {
            _cache = {};
        }
    } catch (e) {
        _cache = {};
    }
}

function _save() {
    if (_cache === null) return false;
    try {
        let data_str = sprintf("%.J", _cache);
        writefile(TMP_PATH, data_str);
        rename(TMP_PATH, FILE_PATH);
        return true;
    } catch (e) {
        // 🚨 遵守铁律 6 (即使内部消化也需规范捕获)
        let err_msg = "" + e;
        return false;
    }
}

/**
 * 模块对外导出的主接口：元数据管理器
 */
const Metadata = {
    get: function(payload, trace_id) {
        try {
            if (!payload || !payload.namespace || !payload.key) {
                return Fail(ERR.E_SYSTEM_BUSY, "Validation Failed: namespace and key are required", trace_id);
            }

            _load();

            let ns = payload.namespace;
            let k = payload.key;
            
            if (!_cache[ns] || _cache[ns][k] === undefined) {
                return Success({ value: null }, 200, trace_id); // ⭐ 协议对齐
            }

            return Success({ value: _cache[ns][k] }, 200, trace_id); // ⭐ 协议对齐
        } catch(e) {
            let err_msg = "" + e;
            return Fail(ERR.E_SYSTEM_BUSY, "Metadata Get Crash: " + err_msg, trace_id);
        }
    },

    set: function(payload, trace_id) {
        try {
            if (!payload || !payload.namespace || !payload.key || payload.value === undefined) {
                return Fail(ERR.E_SYSTEM_BUSY, "Validation Failed: namespace, key and value are required", trace_id);
            }

            _load();

            let ns = payload.namespace;
            let k = payload.key;
            let v = payload.value;

            if (!_cache[ns]) {
                _cache[ns] = {};
            }

            _cache[ns][k] = v;

            if (!_save()) {
                return Fail(ERR.E_SYSTEM_BUSY, "IO Write Failed: unable to persist metadata", trace_id);
            }

            return Success({ namespace: ns, key: k, value: v }, 200, trace_id); // ⭐ 协议对齐
        } catch(e) {
            let err_msg = "" + e;
            return Fail(ERR.E_SYSTEM_BUSY, "Metadata Set Crash: " + err_msg, trace_id);
        }
    }
};

// 🚨 遵守铁律 1: 绝对集中在文件末尾导出
export { Metadata };
