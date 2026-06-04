/**
 * FlowProxy | system/network/gc.uc | v2.0
 * Role: global dataplane garbage collection before any plane assembly.
 */

'use strict';

import { cursor } from 'uci';
import { access, readfile } from 'fs';

import { BIN, DATAPLANE, PATH } from 'flowproxy.core.constants';
import { ERR } from 'flowproxy.core.error';
import { Success, Fail } from 'flowproxy.core.result';
import { ExecSafe, shell_escape } from 'flowproxy.core.utils';
import { log } from 'flowproxy.core.logger';

const MODE_MARKER = sprintf("%s/dataplane.mode", PATH.RUNTIME);

function _cmd_stdout(cmd, trace_id) {
    let res = ExecSafe(BIN.SH, ['-c', cmd], null, trace_id);
    if (!res.ok || !res.data) return sprintf("(failed: %s)", res.detail || "unknown");
    return trim(res.data.stdout || "");
}

function _detect_mode() {
    if (access(PATH.RUN_JSON)) {
        try {
            let cfg = json(readfile(PATH.RUN_JSON) || "{}");
            let inbounds = (cfg && type(cfg.inbounds) === 'array') ? cfg.inbounds : [];
            for (let i = 0; i < length(inbounds); i++) {
                if (inbounds[i].type === 'tun') return "tun";
                if (inbounds[i].type === 'redirect' || inbounds[i].type === 'tproxy') return "redirect_tproxy";
            }
        } catch (e) {}
    }
    if (access(MODE_MARKER)) {
        try {
            let marker = json(readfile(MODE_MARKER) || "{}");
            if (marker && marker.mode) return marker.mode;
        } catch (e) {}
    }
    return "none";
}

function _singbox_running(trace_id) {
    let res = ExecSafe(BIN.SH, ['-c', sprintf("ps w 2>/dev/null | grep '[s]ing-box' | grep ' run ' | grep -- %s >/dev/null", shell_escape(PATH.RUN_JSON))], null, trace_id);
    return res.ok;
}

function _is_explicit_stop(trace_id) {
    return index(trace_id || "", "init_stop:") === 0;
}

function _reason(opts) {
    opts = (type(opts) === 'object') ? opts : {};
    return opts.reason || "unknown";
}

function gc_all(trace_id, opts) {
    try {
        let reason = _reason(opts);
        log(trace_id, 'INFO', 'NETWORK_GC', 'Executing global dataplane GC reason=' + reason);
        let mode = _detect_mode();
        let singbox_running = _singbox_running(trace_id);
        let explicit_stop = _is_explicit_stop(trace_id);
        log(trace_id, 'INFO', 'NETWORK_GC', sprintf(
            'GC context: mode=%s singbox_running=%s explicit_stop=%s',
            mode, singbox_running ? "true" : "false", explicit_stop ? "true" : "false"
        ));
        log(trace_id, 'INFO', 'NETWORK_GC', 'ip rule before GC: ' + _cmd_stdout('ip rule show 2>/dev/null', trace_id));
        log(trace_id, 'INFO', 'NETWORK_GC', 'ip -6 rule before GC: ' + _cmd_stdout('ip -6 rule show 2>/dev/null', trace_id));

        ExecSafe(BIN.SH, ['-c', sprintf('nft delete table %s 2>/dev/null || true', DATAPLANE.NFT_TABLE)], null, trace_id);

        let net_res = ExecSafe(BIN.SH, ['-c', 'ls /sys/class/net/ 2>/dev/null | grep "^singtun"'], null, trace_id);
        let deleted_tun = [];
        let skipped_tun = [];
        if (net_res.ok && net_res.data && net_res.data.stdout) {
            let tun_devices = split(net_res.data.stdout, '\n');
            for (let i = 0; i < length(tun_devices); i++) {
                let dev = trim(tun_devices[i]);
                if (dev && length(dev) > 0) {
                    if (mode === "tun" && (singbox_running || !explicit_stop)) {
                        push(skipped_tun, dev);
                        continue;
                    }
                    let safe_dev = shell_escape(dev);
                    ExecSafe(BIN.SH, ['-c', sprintf('ip link set %s down 2>/dev/null || true', safe_dev)], null, trace_id);
                    ExecSafe(BIN.SH, ['-c', sprintf('ip tuntap del mode tun name %s 2>/dev/null || true', safe_dev)], null, trace_id);
                    push(deleted_tun, dev);
                }
            }
        }
        log(trace_id, 'INFO', 'NETWORK_GC', sprintf(
            'TUN device GC: deleted=[%s] skipped=[%s]',
            join(", ", deleted_tun),
            join(", ", skipped_tun)
        ));

        let u = cursor();
        u.load("flowproxy");
        let tproxy_mark = u.get("flowproxy", "infra", "tproxy_mark") || "101";
        let tun_mark = u.get("flowproxy", "infra", "tun_mark") || "102";
        let self_mark = u.get("flowproxy", "infra", "self_mark") || "100";

        let marks = [tproxy_mark, tun_mark, self_mark];
        for (let i = 0; i < length(marks); i++) {
            let m = marks[i];
            log(trace_id, 'INFO', 'NETWORK_GC', sprintf(
                'Preparing mark/table cleanup: mark=%s route_before=[%s] route6_before=[%s]',
                m,
                _cmd_stdout(sprintf('ip route show table %s 2>/dev/null', shell_escape(m)), trace_id),
                _cmd_stdout(sprintf('ip -6 route show table %s 2>/dev/null', shell_escape(m)), trace_id)
            ));
            let sh_clean_v4 = sprintf('while ip rule del fwmark %s table %s 2>/dev/null; do :; done; ip route flush table %s 2>/dev/null || true', m, m, m);
            let sh_clean_v6 = sprintf('while ip -6 rule del fwmark %s table %s 2>/dev/null; do :; done; ip -6 route flush table %s 2>/dev/null || true', m, m, m);

            ExecSafe(BIN.SH, ['-c', sh_clean_v4], null, trace_id);
            ExecSafe(BIN.SH, ['-c', sh_clean_v6], null, trace_id);
            log(trace_id, 'INFO', 'NETWORK_GC', sprintf(
                'Completed mark/table cleanup: mark=%s route_after=[%s] route6_after=[%s]',
                m,
                _cmd_stdout(sprintf('ip route show table %s 2>/dev/null', shell_escape(m)), trace_id),
                _cmd_stdout(sprintf('ip -6 route show table %s 2>/dev/null', shell_escape(m)), trace_id)
            ));
        }
        log(trace_id, 'INFO', 'NETWORK_GC', 'ip rule after GC: ' + _cmd_stdout('ip rule show 2>/dev/null', trace_id));
        log(trace_id, 'INFO', 'NETWORK_GC', 'ip -6 rule after GC: ' + _cmd_stdout('ip -6 rule show 2>/dev/null', trace_id));

        log(trace_id, 'INFO', 'NETWORK_GC', 'Purging stale dataplane markers and runtime sockets...');
        ExecSafe(BIN.RM, ['-f', sprintf('%s/dataplane.mode', PATH.RUNTIME)], null, trace_id);
        ExecSafe(BIN.SH, ['-c', 'rm -f /var/run/flowproxy/*.socket /var/run/flowproxy/*.sock /var/run/flowproxy/*.state 2>/dev/null || true'], null, trace_id);

        return Success(true, 200, trace_id);
    } catch(e) {
        let err_msg = "" + e;
        log(trace_id, 'CRIT', 'NETWORK_GC', 'GC Exception: ' + err_msg);
        return Fail(ERR.E_SYSTEM_BUSY, "Network GC Exception: " + err_msg, trace_id);
    }
}

export { gc_all };
