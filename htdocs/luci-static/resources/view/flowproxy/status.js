'use strict';
'require form';
'require rpc';
'require uci';
'require view';

const callSystemStatus = rpc.declare({
    object: 'flowproxy.system',
    method: 'status',
    expect: { '': {} }
});

const callUrltestStatus = rpc.declare({
    object: 'flowproxy.system',
    method: 'get_urltest_status',
    expect: { '': {} }
});

const URLTEST_REFRESH_MS = 30000;
let urltestRefreshTimer = null;

function valueOrUnknown(v) {
    if (v === null || v === undefined || v === '')
        return _('unknown');
    if (typeof v === 'boolean')
        return v ? _('yes') : _('no');
    return String(v);
}

function normalizeStatus(ret) {
    if (!ret)
        return {};
    if (ret.data)
        return ret.data;
    return ret;
}

function statusTone(value, okValue) {
    if (value === okValue || value === true)
        return 'ok';
    if (value === false || value === 'broken' || value === 'invalid' || value === 'not running' || value === 'api unavailable')
        return 'bad';
    if (value === 'degraded')
        return 'warn';
    return 'muted';
}

function displayStatus(value) {
    let labels = {
        'api unavailable': _('api unavailable'),
        broken: _('broken'),
        degraded: _('degraded'),
        healthy: _('healthy'),
        invalid: _('invalid'),
        none: _('none'),
        'not running': _('not running'),
        running: _('running'),
        unknown: _('unknown')
    };

    return labels[value] || valueOrUnknown(value);
}

function pill(text, tone) {
    let colors = {
        ok: 'background:#d4edda;color:#155724;',
        warn: 'background:#fff3cd;color:#856404;',
        bad: 'background:#f8d7da;color:#721c24;',
        muted: 'background:#e2e3e5;color:#383d41;'
    };

    return E('span', {
        'style': (colors[tone] || colors.muted) + 'display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;'
    }, [ valueOrUnknown(text) ]);
}

function kv(label, value, tone) {
    return E('div', {
        'style': 'display:flex;justify-content:space-between;gap:12px;padding:5px 0;border-bottom:1px solid #eee;'
    }, [
        E('span', { 'style': 'color:#666;' }, [ label ]),
        tone ? pill(value, tone) : E('strong', { 'style': 'text-align:right;' }, [ valueOrUnknown(value) ])
    ]);
}

function card(title, rows) {
    return E('div', {
        'class': 'fp-dashboard-card'
    }, [
        E('div', { 'style': 'font-weight:700;margin-bottom:8px;' }, [ title ]),
        E('div', {}, rows)
    ]);
}

function sectionBlock(title, rows) {
    return E('div', {
        'class': 'fp-dashboard-section'
    }, [
        E('div', { 'style': 'font-weight:700;margin-bottom:8px;' }, [ title ]),
        E('div', {}, rows)
    ]);
}

function sectionLabel(section_id, fallback) {
    if (!section_id)
        return fallback || _('unknown');
    if (section_id === 'direct-out')
        return _('Direct');
    if (section_id === 'block-out')
        return _('Block');
    if (section_id === 'nil')
        return _('Disable');

    return uci.get('flowproxy', section_id, 'label') || fallback || section_id;
}

function countSections(type) {
    let total = 0;
    let enabled = 0;

    uci.sections('flowproxy', type, (res) => {
        total++;
        if (res.enabled !== '0')
            enabled++;
    });

    return { total: total, enabled: enabled };
}

function urltestItem(urltestStatus, id) {
    let data = normalizeStatus(urltestStatus);
    let items = data && data.items ? data.items : {};
    if (!id)
        return null;
    return items[id] || items['cfg-' + id + '-out'] || null;
}

function latencyTone(latency) {
    let value = Number(latency);
    if (!isFinite(value))
        return 'muted';
    if (value <= 400)
        return 'ok';
    if (value <= 1000)
        return 'warn';
    return 'bad';
}

function latencyPill(urltestStatus, id) {
    let item = urltestItem(urltestStatus, id);
    if (!item)
        return null;
    if (item.status === 'ok' && item.latency != null)
        return pill(item.latency + 'ms', latencyTone(item.latency));
    if (item.status === 'timeout')
        return pill(_('Timeout'), 'muted');
    return null;
}

function labelWithLatency(section_id, fallback, urltestStatus) {
    let children = [ E('span', {}, [ sectionLabel(section_id, fallback) ]) ];
    let latency = latencyPill(urltestStatus, section_id);
    if (latency)
        children.push(E('span', { 'style': 'margin-left:6px;' }, [ latency ]));
    return E('span', {}, children);
}

function table(headers, rows) {
    return E('div', { 'style': 'overflow:auto;margin-top:8px;' }, [
        E('table', {
            'class': 'table',
            'style': 'width:100%;border-collapse:collapse;'
        }, [
            E('thead', {}, [
                E('tr', {}, headers.map((header) => E('th', {
                    'style': 'text-align:left;padding:6px 8px;background:#f1f3f5;border-bottom:1px solid #ddd;white-space:nowrap;'
                }, [ header ])))
            ]),
            E('tbody', {}, rows.length ? rows : [
                E('tr', {}, [
                    E('td', {
                        'colspan': headers.length,
                        'style': 'padding:8px;color:#777;'
                    }, [ _('No data') ])
                ])
            ])
        ])
    ]);
}

function defaultRow(label, detail, right) {
    let left = [ E('strong', {}, [ valueOrUnknown(label) ]) ];
    if (detail)
        left.push(E('span', { 'style': 'margin-left:10px;color:#30385f;' }, [ valueOrUnknown(detail) ]));

    return E('div', {
        'style': 'display:flex;justify-content:space-between;gap:10px;align-items:center;padding:8px;border-radius:6px;background:#e9f7ef;margin:6px 0 12px 0;'
    }, [
        E('span', { 'style': 'min-width:0;overflow-wrap:anywhere;' }, left),
        E('span', { 'style': 'text-align:right;' }, right ? [ right ] : [])
    ]);
}

function routeTargetNode(rule, urltestStatus) {
    if (!rule)
        return E('span', {}, [ _('unknown') ]);
    if (rule.action === 'reject')
        return E('span', {}, [ _('Reject / Block') ]);
    if (rule.action === 'hijack-dns')
        return E('span', {}, [ _('Hijack DNS') ]);
    if (rule.action && rule.action !== 'route')
        return E('span', {}, [ rule.action ]);

    return labelWithLatency(rule.outbound, rule.outbound, urltestStatus);
}

function routingRuleRows(urltestStatus) {
    let rows = [];

    uci.sections('flowproxy', 'routing_rule', (rule) => {
        let enabled = rule.enabled !== '0';
        rows.push(E('tr', {}, [
            E('td', { 'style': 'padding:6px 8px;border-bottom:1px solid #eee;' }, [
                rule.label || rule['.name'] || _('unknown')
            ]),
            E('td', { 'style': 'padding:6px 8px;border-bottom:1px solid #eee;' }, [
                pill(enabled ? _('enabled') : _('disabled'), enabled ? 'ok' : 'muted')
            ]),
            E('td', { 'style': 'padding:6px 8px;border-bottom:1px solid #eee;' }, [
                routeTargetNode(rule, urltestStatus)
            ])
        ]));
    });

    return rows;
}

function dnsServerRows(urltestStatus) {
    let rows = [];

    uci.sections('flowproxy', 'dns_server', (server) => {
        rows.push(E('tr', {}, [
            E('td', { 'style': 'padding:6px 8px;border-bottom:1px solid #eee;' }, [
                server.label || server['.name'] || _('unknown')
            ]),
            E('td', { 'style': 'padding:6px 8px;border-bottom:1px solid #eee;' }, [
                labelWithLatency(server.outbound, server.outbound, urltestStatus)
            ])
        ]));
    });

    return rows;
}

function dnsTarget(rule) {
    if (!rule)
        return _('unknown');
    if (rule.action === 'reject')
        return _('Reject / Block');
    if (rule.action === 'predefined')
        return _('Predefined');
    if (rule.action && rule.action !== 'route' && rule.action !== 'evaluate')
        return rule.action;

    return sectionLabel(rule.server, rule.server);
}

function dnsRuleRows() {
    let rows = [];

    uci.sections('flowproxy', 'dns_rule', (rule) => {
        let enabled = rule.enabled !== '0';
        rows.push(E('tr', {}, [
            E('td', { 'style': 'padding:6px 8px;border-bottom:1px solid #eee;' }, [
                rule.label || rule['.name'] || _('unknown')
            ]),
            E('td', { 'style': 'padding:6px 8px;border-bottom:1px solid #eee;' }, [
                pill(enabled ? _('enabled') : _('disabled'), enabled ? 'ok' : 'muted')
            ]),
            E('td', { 'style': 'padding:6px 8px;border-bottom:1px solid #eee;' }, [
                dnsTarget(rule)
            ])
        ]));
    });

    return rows;
}

function dashboardStyle() {
    return [
        '.fp-dashboard-shell{width:100%;max-width:1680px;margin:0 auto 20px auto;box-sizing:border-box;}',
        '.fp-dashboard-shell *{box-sizing:border-box;}',
        '.fp-dashboard-top{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;align-items:start;}',
        '.fp-dashboard-runtime{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;align-items:start;margin-top:12px;}',
        '.fp-dashboard-card,.fp-dashboard-section{border:1px solid #ddd;border-radius:6px;padding:12px;background:#fff;min-width:0;}',
        '.fp-dashboard-card{height:100%;}',
        '.fp-dashboard-section{width:100%;}',
        '.fp-dashboard-card strong,.fp-dashboard-section td,.fp-dashboard-section th{overflow-wrap:anywhere;}',
        '.fp-dashboard-section table{table-layout:auto;}',
        '@media (max-width:1100px){.fp-dashboard-top{grid-template-columns:repeat(2,minmax(0,1fr));}.fp-dashboard-runtime{grid-template-columns:1fr;}}',
        '@media (max-width:680px){.fp-dashboard-top{grid-template-columns:1fr;}}'
    ].join('\n');
}

function runtimeBlocks(urltestStatus) {
    let defaultOutbound = uci.get('flowproxy', 'routing', 'default_outbound') || '';
    let defaultDns = uci.get('flowproxy', 'dns', 'default_server') || uci.get('flowproxy', 'routing', 'default_outbound_dns') || '';
    let routingRules = countSections('routing_rule');
    let dnsRules = countSections('dns_rule');
    let dnsServers = countSections('dns_server');
    let defaultDnsOutbound = uci.get('flowproxy', defaultDns, 'outbound') || '';

    return [
        sectionBlock(_('Routing Runtime'), [
            E('div', { 'style': 'font-weight:600;' }, [ _('Default outbound') ]),
            defaultRow(sectionLabel(defaultOutbound, defaultOutbound), null, latencyPill(urltestStatus, defaultOutbound)),
            E('div', { 'style': 'font-weight:600;margin-top:10px;' }, [ _('Routing Rules Summary') ]),
            table([
                _('rule name'),
                _('enabled'),
                _('outbound')
            ], routingRuleRows(urltestStatus)),
            E('div', { 'style': 'padding-top:8px;color:#666;text-align:right;' }, [
                _('%d rules total - %d enabled').format(routingRules.total, routingRules.enabled)
            ]),
            E('div', { 'style': 'padding-top:8px;text-align:right;' }, [
                E('a', {
                    'class': 'btn cbi-button cbi-button-neutral',
                    'href': L.url('admin/services/flowproxy/client')
                }, [ _('View in Client') ])
            ])
        ]),
        sectionBlock(_('DNS Runtime'), [
            E('div', { 'style': 'font-weight:600;' }, [ _('Default DNS') ]),
            defaultRow(sectionLabel(defaultDns, defaultDns), sectionLabel(defaultDnsOutbound, defaultDnsOutbound), latencyPill(urltestStatus, defaultDnsOutbound)),
            E('div', { 'style': 'font-weight:600;margin-top:10px;' }, [ _('DNS Servers') ]),
            table([
                _('server name'),
                _('outbound')
            ], dnsServerRows(urltestStatus)),
            E('div', { 'style': 'font-weight:600;margin-top:10px;' }, [ _('DNS Rules Summary') ]),
            table([
                _('rule name'),
                _('enabled'),
                _('server/outbound')
            ], dnsRuleRows()),
            E('div', { 'style': 'padding-top:8px;color:#666;text-align:right;' }, [
                _('%d DNS servers total - %d DNS rules total').format(dnsServers.total, dnsRules.total)
            ]),
            E('div', { 'style': 'padding-top:8px;text-align:right;' }, [
                E('a', {
                    'class': 'btn cbi-button cbi-button-neutral',
                    'href': L.url('admin/services/flowproxy/client')
                }, [ _('View in Client') ])
            ])
        ])
    ];
}

function updateRuntimeUrltest(urltestStatus) {
    let runtime = document.getElementById('flowproxy-dashboard-runtime');
    if (!runtime)
        return false;

    runtime.textContent = '';
    runtimeBlocks(urltestStatus).forEach((node) => runtime.appendChild(node));

    return true;
}

function startUrltestRefresh() {
    if (urltestRefreshTimer)
        window.clearInterval(urltestRefreshTimer);

    urltestRefreshTimer = window.setInterval(() => {
        if (!document.getElementById('flowproxy-dashboard-runtime')) {
            window.clearInterval(urltestRefreshTimer);
            urltestRefreshTimer = null;
            return;
        }

        if (document.hidden)
            return;

        L.resolveDefault(callUrltestStatus(), {}).then(updateRuntimeUrltest);
    }, URLTEST_REFRESH_MS);
}

function renderDashboard(sysStatus, urltestStatus) {
    let sys_status = normalizeStatus(sysStatus);

    let apiUnavailable = !sys_status || (!sys_status.process && typeof sys_status.enabled === 'undefined');
    let health = apiUnavailable ? {} : (sys_status.health || {});
    let diagnostic = apiUnavailable ? {} : (sys_status.diagnostic || {});
    let processRunning = !apiUnavailable && sys_status.process ? sys_status.process.running : null;
    let runJsonValid = !apiUnavailable && sys_status.config ? sys_status.config.valid : null;
    let runningMode = health.mode || (health.dataplane && health.dataplane.mode) || health.failed_mode || 'unknown';
    let healthState = health.state || (apiUnavailable ? 'api unavailable' : 'unknown');
    let failed = Array.isArray(health.failed) ? health.failed : [];
    let missing = health.missing && Array.isArray(health.missing.items) ? health.missing.items : [];

    let defaultOutbound = uci.get('flowproxy', 'routing', 'default_outbound') || '';
    let defaultDns = uci.get('flowproxy', 'dns', 'default_server') || uci.get('flowproxy', 'routing', 'default_outbound_dns') || '';

    let lastApply = diagnostic.last_apply ||
        diagnostic.last_apply_result ||
        diagnostic.last_job ||
        diagnostic.apply_id ||
        diagnostic.last_error ||
        'unknown';

    return E('div', { 'class': 'cbi-section fp-dashboard-shell' }, [
        E('style', {}, [ dashboardStyle() ]),
        E('h2', { 'style': 'margin-top:0;' }, [ _('Dashboard') ]),
        E('div', { 'class': 'fp-dashboard-top' }, [
            card(_('Desired State'), [
                kv(_('proxy_mode'), uci.get('flowproxy', 'config', 'proxy_mode')),
                kv(_('routing_mode'), uci.get('flowproxy', 'config', 'routing_mode')),
                kv(_('default_outbound'), sectionLabel(defaultOutbound, defaultOutbound)),
                kv(_('default_dns'), sectionLabel(defaultDns, defaultDns)),
                kv(_('enabled'), apiUnavailable ? _('unknown') : !!sys_status.enabled, apiUnavailable ? 'muted' : (sys_status.enabled ? 'ok' : 'muted'))
            ]),
            card(_('Running State'), [
                kv(_('sing-box process'), apiUnavailable ? _('api unavailable') : (processRunning ? _('running') : _('not running')), apiUnavailable ? 'bad' : (processRunning ? 'ok' : 'bad')),
                kv(_('run.json valid'), apiUnavailable ? _('unknown') : runJsonValid, statusTone(runJsonValid, true)),
                kv(_('running mode'), displayStatus(runningMode)),
                kv(_('mixed port'), apiUnavailable ? _('unknown') : (sys_status.ports && sys_status.ports.mixed)),
                kv(_('dns port'), apiUnavailable ? _('unknown') : (sys_status.ports && sys_status.ports.dns))
            ]),
            card(_('Health'), [
                kv(_('overall'), displayStatus(healthState), statusTone(healthState, 'healthy')),
                kv(_('dataplane'), displayStatus((health.dataplane && health.dataplane.mode) || runningMode)),
                kv(_('failed checks'), failed.length ? failed.length : _('none'), failed.length ? 'warn' : 'ok'),
                kv(_('warnings'), missing.length ? missing.length : _('none'), missing.length ? 'warn' : 'ok'),
                kv(_('last observed'), diagnostic.last_observed_at || diagnostic.updated_at || _('unknown'))
            ]),
            card(_('Last Apply'), [
                kv(_('last result'), displayStatus(lastApply)),
                kv(_('updated_at'), diagnostic.updated_at || _('unknown')),
                kv(_('degraded_reason'), diagnostic.degraded_reason || _('none')),
                kv(_('next action'), displayStatus(diagnostic.next_action || 'unknown'))
            ])
        ]),
        E('div', { 'id': 'flowproxy-dashboard-runtime', 'class': 'fp-dashboard-runtime' }, runtimeBlocks(urltestStatus))
    ]);
}

return view.extend({
    load() {
        return Promise.all([
            uci.load('flowproxy'),
            L.resolveDefault(callSystemStatus(), {}),
            L.resolveDefault(callUrltestStatus(), {})
        ]);
    },

    render(data) {
        let m = new form.Map('flowproxy');
        let s = m.section(form.NamedSection, 'config', 'flowproxy');
        s.anonymous = true;

        let o = s.option(form.DummyValue, '_dashboard');
        o.render = function() {
            let dashboard = renderDashboard(data[1], data[2]);
            startUrltestRefresh();
            return dashboard;
        };

        return m.render();
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
