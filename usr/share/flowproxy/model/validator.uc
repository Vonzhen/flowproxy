/**
 * FlowProxy | model/validator.uc | v1.0
 * 流水线逻辑校验器 (SSOT Aligned Edition)
 * 职责：执行流水线逻辑质检，拦截非法 Model，保护下游物理转换器。
 * 核心对齐：剥离私有正则字典，全量接入 Result 错误字典协议。
 */

'use strict';

// 🚨 铁律 3: 绝对命名空间寻址
import { REGEX } from 'flowproxy.core.types';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';

function is_valid_port(port) {
    if (type(port) !== 'int' && type(port) !== 'double') return false;
    return port > 0 && port <= 65535;
}

function is_valid_uuid(uuid) {
    if (type(uuid) !== 'string') return false;
    return match(uuid, REGEX.UUID) !== null;
}

function is_valid_host(host) {
    if (type(host) !== 'string' || length(host) === 0) return false;
    if (match(host, /[ \t\/\\#\?]/)) return false;
    return true;
}

function scan_inbounds(inbounds, errors) {
    if (!inbounds || length(inbounds) === 0) {
        push(errors, "Model missing critical component: inbounds array is empty.");
        return;
    }

    let port_map = {};
    for (let i = 0; i < length(inbounds); i++) {
        let inb = inbounds[i];
        if (inb.listen_port) {
            if (!is_valid_port(inb.listen_port)) {
                push(errors, sprintf("Inbound [%s] has invalid port: %s", inb.tag, inb.listen_port));
            } else {
                let p_key = inb.listen_port + "";
                if (port_map[p_key]) {
                    push(errors, sprintf("Port collision detected: Port %s is shared by [%s] and [%s].", p_key, port_map[p_key], inb.tag));
                } else {
                    port_map[p_key] = inb.tag;
                }
            }
        }
    }
}

function scan_endpoints(endpoints, errors, valid_tags) {
    for (let i = 0; i < length(endpoints); i++) {
        let ep = endpoints[i];
        valid_tags[ep.tag] = true; 

        if (ep.type !== 'wireguard') {
            if (!is_valid_host(ep.server)) push(errors, sprintf("Endpoint [%s] missing or invalid server address.", ep.tag));
            if (!is_valid_port(ep.server_port)) push(errors, sprintf("Endpoint [%s] invalid port.", ep.tag));
        }

        switch (ep.type) {
            case 'vless':
            case 'vmess':
            case 'tuic':
                if (!is_valid_uuid(ep.uuid)) push(errors, sprintf("Endpoint [%s] missing or malformed UUID.", ep.tag));
                break;
            case 'trojan':
            case 'shadowsocks':
                if (type(ep.password) !== 'string' || length(ep.password) === 0) push(errors, sprintf("Endpoint [%s] missing password.", ep.tag));
                break;
        }
    }
}

function scan_topology_references(outbounds, routing, errors, valid_tags) {
    valid_tags['direct-out'] = true;
    valid_tags['block-out'] = true;

    for (let i = 0; i < length(outbounds); i++) {
        let out = outbounds[i];
        if (out.tag) valid_tags[out.tag] = true;

        if (out.type === 'urltest' || out.type === 'selector') {
            if (!out.outbounds || length(out.outbounds) === 0) {
                push(errors, sprintf("Group [%s] is empty.", out.tag));
            } else {
                for (let j = 0; j < length(out.outbounds); j++) {
                    let child_tag = out.outbounds[j];
                    if (!valid_tags[child_tag]) push(errors, sprintf("Group [%s] references non-existent node: %s", out.tag, child_tag));
                }
            }
        }
    }
}

/**
 * 校验 FlowModel 逻辑完整性
 * @param {object} flow_model - 抽象数据模型
 * @param {string} trace_id - 贯穿链路的 Trace ID
 */
function validate_model(flow_model, trace_id) {
    let errors = [];
    let valid_tags = {}; 

    if (!flow_model || type(flow_model) !== 'object') {
        // ⭐ 协议对齐：透传 trace_id
        return Fail(ERR.E_CONFIG_FAULT, "Invalid FlowModel type or model is null.", trace_id);
    }

    // 意志闭环：如果模型标记为禁用，则跳过后续业务校验，直接放行
    if (flow_model.enabled === false) {
        return Success(true, 200, trace_id);
    }

    scan_inbounds(flow_model.inbounds, errors);
    scan_endpoints(flow_model.endpoints || [], errors, valid_tags);
    scan_topology_references(flow_model.outbounds || [], flow_model.route, errors, valid_tags);

    if (length(errors) > 0) {
        // ⭐ 协议对齐：透传 trace_id
        return Fail(ERR.E_CONFIG_FAULT, join(" | ", errors), trace_id);
    }

    // ⭐ 协议对齐：透传 trace_id 与状态码 200
    return Success(true, 200, trace_id);
}

// 🚨 铁律 1: 文件末尾统一导出
export { validate_model };
