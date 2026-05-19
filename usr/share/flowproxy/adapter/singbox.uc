/**
 * FlowProxy | adapter/singbox.uc | v1.0
 * 配置物理翻译器 (SSOT Aligned Edition)
 * 架构角色：执行流水线 Step 2 (Model -> JSON)。
 * 核心对齐：全量接入 Result 协议，注入 Trace 追踪机制，增加黑匣子观测。
 * 核心特性：深度递归清洗器，剔除所有 null 属性，还原纯净 JSON。
 */

'use strict';

// 🚨 铁律 3: 绝对命名空间寻址
import { cursor } from 'uci';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { log } from 'flowproxy.core.logger';

// 递归清洗空对象，保证内核不报错 (业务逻辑 100% 保留)
function clean_obj(obj) {
    if (type(obj) === 'array') {
        let ret = [];
        for (let i = 0; i < length(obj); i++) {
            if (obj[i] != null) {
                push(ret, clean_obj(obj[i]));
            }
        }
        return ret;
    } else if (type(obj) === 'object') {
        let ret = {};
        for (let k in obj) {
            if (obj[k] != null) {
                ret[k] = clean_obj(obj[k]);
            }
        }
        return ret;
    }
    return obj; // 基础类型直接返回
}

const Adapter = {
    /**
     * 将 FlowModel 翻译为 Sing-box JSON 字符串
     * @param {object} flow_model - 抽象数据模型
     * @param {object} kernel_caps - 内核能力探测参数 (备用)
     * @param {string} trace_id - 贯穿链路的 Trace ID
     */
    translate: function(flow_model, kernel_caps, trace_id) {
        log(trace_id, 'INFO', 'ADAPTER', 'Translating FlowModel to Sing-box JSON...');

        try {
            // ⭐ 协议对齐：防御性边界检查
            if (!flow_model || type(flow_model) !== 'object') {
                log(trace_id, 'CRIT', 'ADAPTER', 'Invalid flow_model input object.');
                return Fail(ERR.E_CONFIG_FAULT, "Adapter Error: Invalid flow_model input", trace_id);
            }

            let u = cursor();
            u.load('flowproxy');
            // 🚨 安全硬化：获取是否允许局域网连接意图。未开启则强行收敛至本机环回地址
            let allow_lan = u.get('flowproxy', 'config', 'allow_lan') === '1';
            let safe_listen_addr = allow_lan ? '::' : '127.0.0.1';

            let config = {};

            if (flow_model.log) {
                config.log = {
                    disabled: flow_model.log.disabled || false,
                    level: flow_model.log.level || 'warn',
                    output: flow_model.log.output_path,
                    timestamp: true
                };
            }
            
            if (flow_model.ntp) config.ntp = flow_model.ntp;

            if (flow_model.dns) {
                config.dns = {
                    servers: flow_model.dns.servers || [],
                    rules: flow_model.dns.rules || [],
                    final: flow_model.dns.final || 'default-dns',
                    strategy: flow_model.dns.strategy,
                    disable_cache: flow_model.dns.disable_cache || false,
                    disable_expire: flow_model.dns.disable_expire || false,
                    client_subnet: flow_model.dns.client_subnet
                };
            }

            config.inbounds = (type(flow_model.inbounds) === 'array') ? flow_model.inbounds : [];
            
            // 🚨 收敛接管面：遍历入站节点，对高危端口实施物理隔离
            for (let i = 0; i < length(config.inbounds); i++) {
                if (config.inbounds[i].tag === 'mixed-in') {
                    log(trace_id, 'INFO', 'ADAPTER', sprintf('Hardening mixed-in exposure: binding to %s', safe_listen_addr));
                    config.inbounds[i].listen = safe_listen_addr;
                }
            }

            let final_outbounds = [];
            if (type(flow_model.outbounds) === 'array') {
                for (let i = 0; i < length(flow_model.outbounds); i++) push(final_outbounds, flow_model.outbounds[i]);
            }
            if (type(flow_model.endpoints) === 'array') {
                for (let i = 0; i < length(flow_model.endpoints); i++) push(final_outbounds, flow_model.endpoints[i]);
            }
            config.outbounds = final_outbounds;

            if (flow_model.route) {
                config.route = {
                    rules: flow_model.route.rules || [],
                    rule_set: flow_model.route.rule_set || [],
                    auto_detect_interface: flow_model.route.auto_detect_interface,
                    final: flow_model.route.final || 'direct-out'
                };
                if (flow_model.route.default_domain_resolver) {
                    config.route.default_domain_resolver = flow_model.route.default_domain_resolver;
                }
            }

            if (flow_model.experimental) config.experimental = flow_model.experimental;

            // 终极清洗：剥离所有 null，产出完美 JSON
            let final_json = sprintf("%.J", clean_obj(config));

            log(trace_id, 'INFO', 'ADAPTER', 'Translation complete. JSON generated successfully.');

            return Success(final_json, 200, trace_id);

        } catch(e) {
            let err_str = "" + e;
            log(trace_id, 'CRIT', 'ADAPTER', 'Translation Crash: ' + err_str);
            return Fail(ERR.E_CONFIG_FAULT, "Adapter Translation Exception: " + err_str, trace_id);
        }
    }
};

// 🚨 铁律 1: 文件末尾统一导出
export { Adapter };
