/**
 * FlowProxy | adapter/singbox/outbounds/registry.uc
 * Explicit sing-box outbound adapter registry. Do not use runtime directory scans.
 */

'use strict';

import { apply as apply_anytls } from 'flowproxy.adapter.singbox.outbounds.anytls';
import { apply as apply_tuic } from 'flowproxy.adapter.singbox.outbounds.tuic';
import { apply as apply_hysteria2 } from 'flowproxy.adapter.singbox.outbounds.hysteria2';
import { apply as apply_trojan } from 'flowproxy.adapter.singbox.outbounds.trojan';
import { apply as apply_shadowsocks } from 'flowproxy.adapter.singbox.outbounds.shadowsocks';
import { apply as apply_vless } from 'flowproxy.adapter.singbox.outbounds.vless';
import { apply as apply_vmess } from 'flowproxy.adapter.singbox.outbounds.vmess';

let REGISTRY = {};

function register(type_name, adapter) {
    REGISTRY[type_name] = adapter;
}

register("anytls", apply_anytls);
register("tuic", apply_tuic);
register("hysteria2", apply_hysteria2);
register("trojan", apply_trojan);
register("shadowsocks", apply_shadowsocks);
register("vless", apply_vless);
register("vmess", apply_vmess);

function apply(node, ep) {
    if (!node || !ep) return false;

    let adapter = REGISTRY[node.type];
    if (!adapter) return false;

    return adapter(node, ep) ? true : false;
}

export { apply, register };
