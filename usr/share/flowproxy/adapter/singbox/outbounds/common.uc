/**
 * FlowProxy | adapter/singbox/outbounds/common.uc
 * Common sing-box outbound tail builders.
 *
 * Phase 6.6B: transport and multiplex extraction only. Keep behavior identical.
 */

'use strict';

function strToInt(val) { return (val != null && val !== "") ? int(val) : null; }
function strToBool(val) { return (val != null && val !== "") ? (val === '1' || val === 'true') : null; }
function strToTime(val) { 
    if (val !=null && val !=="") {
       return match(val,/^[0-9]+$/) ? val + "s" : val;
    }
    return null;
}

function apply_transport(ep, node) {
    if (node.transport && node.transport !== 'tcp') {
        let tp = { 
            type: node.transport, 
            host: node.http_host || node.httpupgrade_host, 
            path: node.http_path || node.ws_path, 
            method: node.http_method, 
            service_name: node.grpc_servicename, 
            idle_timeout: strToTime(node.http_idle_timeout), 
            ping_timeout: strToTime(node.http_ping_timeout), 
            permit_without_stream: strToBool(node.grpc_permit_without_stream) 
        };

        // Preserve existing WebSocket Host header behavior.
        if (node.ws_host) { tp.headers = { "Host": node.ws_host }; }
        if (node.websocket_early_data) {
            tp.max_early_data = strToInt(node.websocket_early_data) || 2048;
            tp.early_data_header_name = node.websocket_early_data_header || "Sec-WebSocket-Protocol";
        }
        ep.transport = tp;
    }
}

function apply_multiplex(ep, node) {
    if (node.multiplex === '1') {
        ep.multiplex = { enabled: true, protocol: node.multiplex_protocol, max_connections: strToInt(node.multiplex_max_connections), min_streams: strToInt(node.multiplex_min_streams), max_streams: strToInt(node.multiplex_max_streams), padding: strToBool(node.multiplex_padding) };
    }
}

export { apply_transport, apply_multiplex };
