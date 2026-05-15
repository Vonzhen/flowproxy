/*
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2022-2025 ImmortalWrt.org
 */

'use strict';
'require form';
'require network';
'require poll';
// 🚨 架构洗牌：彻底移除 'require rpc'，视图层无权直接建立 Ubus 信道
'require uci';
'require validation';
'require view';
'require fs';

'require flowproxy as fp';
'require tools.firewall as fwtool';
'require tools.widgets as widgets';
'require flowproxy.observer as observer';

// 🚨 架构洗牌：原有的 callSystemStatus、callReadDomainList 等 rpc.declare 已被彻底抹除。
// 视图层只需纯粹地向 SDK (fp) 索要数据。

/**
 * 获取底层网关状态 (接入 1.0 SDK)
 */
function getServiceStatus() {
    return fp.rpc_call('flowproxy.system', 'status', {}).then((data) => {
        let isRunning = false;
        let version = '';
        // SDK 返回的已经是解包后的纯净 Result.data
        if (data && data.process) isRunning = data.process.running;
        if (data && data.version) version = data.version.singbox || '';
        return { isRunning, version };
    }).catch(() => {
        // 若后端崩溃，SDK 拦截器已弹出告警并记录 Trace ID。
        // 此处只需做静态 UI 降级，防止 poll 轮询渲染导致 DOM 树崩溃。
        return { isRunning: false, version: 'RPC Error' };
    });
}

function renderStatus(isRunning, version) {
    let spanTemp = '<em><span style="color:%s"><strong>%s (sing-box v%s) %s</strong></span></em>';
    let renderHTML;
    if (isRunning)
        renderHTML = spanTemp.format('green', _('FlowProxy'), version, _('RUNNING'));
    else
        renderHTML = spanTemp.format('red', _('FlowProxy'), version, _('NOT RUNNING'));

    return renderHTML;
}

let stubValidator = {
    factory: validation,
    apply(type, value, args) {
        if (value != null)
            this.value = value;

        return validation.types[type].apply(this, args);
    },
    assert(condition) {
        return !!condition;
    }
};

return view.extend({
    load() {
        return Promise.all([
            uci.load('flowproxy'),
            fp.getBuiltinFeatures(),
            network.getHostHints()
        ]).then(responses => {
            /* 🌟 核心防御：如果配置里没有 assets 节点，直接内存注册，防止页面空白 */
            if (!uci.get('flowproxy', 'assets')) {
                // ⭐ 统一类型和名字均为 assets，绝不与 config 节抢名字
                uci.add('flowproxy', 'assets', 'assets');
            }
            return responses;
        });
    },

    render(data) {
        let m, s, o, ss, so;

        let features = data[1],
            hosts = data[2]?.hosts;

        /* Cache all configured proxy nodes, they will be called multiple times */
        let proxy_nodes = {};
        uci.sections(data[0], 'node', (res) => {
            let nodeaddr = ((res.type === 'direct') ? res.override_address : res.address) || '',
                nodeport = ((res.type === 'direct') ? res.override_port : res.port) || '';

            proxy_nodes[res['.name']] =
                String.format('[%s] %s', res.type, res.label || ((stubValidator.apply('ip6addr', nodeaddr) ?
                    String.format('[%s]', nodeaddr) : nodeaddr) + ':' + nodeport));
        });

        m = new form.Map('flowproxy', _('FlowProxy'),
            _('The modern ImmortalWrt proxy platform for ARM64/AMD64.'));

        s = m.section(form.TypedSection);
        s.render = function () {
            poll.add(function () {
                return L.resolveDefault(getServiceStatus()).then((res) => {
                    let view = document.getElementById('service_status');
                    view.innerHTML = renderStatus(res.isRunning, features.version);
                });
            });

            return E('div', { class: 'cbi-section', id: 'status_bar' }, [
                E('p', { id: 'service_status' }, _('Collecting data...'))
            ]);
        }

        s = m.section(form.NamedSection, 'config', 'flowproxy');

        s.tab('routing', _('Routing Settings'));

        o = s.taboption('routing', form.ListValue, 'main_node', _('Main node'));
        o.value('nil', _('Disable'));
        o.value('urltest', _('URLTest'));
        for (let i in proxy_nodes)
            o.value(i, proxy_nodes[i]);
        o.default = 'nil';
        o.depends({'routing_mode': 'custom', '!reverse': true});
        o.rmempty = false;

        o = s.taboption('routing', fp.CBIStaticList, 'main_urltest_nodes', _('URLTest nodes'),
            _('List of nodes to test.'));
        for (let i in proxy_nodes)
            o.value(i, proxy_nodes[i]);
        o.depends('main_node', 'urltest');
        o.rmempty = false;

        o = s.taboption('routing', form.Value, 'main_urltest_interval', _('Test interval'),
            _('The test interval in seconds.'));
        o.datatype = 'uinteger';
        o.placeholder = '180';
        o.depends('main_node', 'urltest');

        o = s.taboption('routing', form.Value, 'main_urltest_tolerance', _('Test tolerance'),
            _('The test tolerance in milliseconds.'));
        o.datatype = 'uinteger';
        o.placeholder = '50';
        o.depends('main_node', 'urltest');

        o = s.taboption('routing', form.ListValue, 'main_udp_node', _('Main UDP node'));
        o.value('nil', _('Disable'));
        o.value('same', _('Same as main node'));
        o.value('urltest', _('URLTest'));
        for (let i in proxy_nodes)
            o.value(i, proxy_nodes[i]);
        o.default = 'nil';
        o.depends({'routing_mode': /^((?!custom).)+$/, 'proxy_mode': /^((?!redirect$).)+$/});
        o.rmempty = false;

        o = s.taboption('routing', fp.CBIStaticList, 'main_udp_urltest_nodes', _('URLTest nodes'),
            _('List of nodes to test.'));
        for (let i in proxy_nodes)
            o.value(i, proxy_nodes[i]);
        o.depends('main_udp_node', 'urltest');
        o.rmempty = false;

        o = s.taboption('routing', form.Value, 'main_udp_urltest_interval', _('Test interval'),
            _('The test interval in seconds.'));
        o.datatype = 'uinteger';
        o.placeholder = '180';
        o.depends('main_udp_node', 'urltest');

        o = s.taboption('routing', form.Value, 'main_udp_urltest_tolerance', _('Test tolerance'),
            _('The test tolerance in milliseconds.'));
        o.datatype = 'uinteger';
        o.placeholder = '50';
        o.depends('main_udp_node', 'urltest');

        o = s.taboption('routing', form.Value, 'dns_server', _('DNS server'),
            _('Support UDP, TCP, DoH, DoQ, DoT. TCP protocol will be used if not specified.'));
        o.value('wan', _('WAN DNS (read from interface)'));
        o.value('1.1.1.1', _('CloudFlare Public DNS (1.1.1.1)'));
        o.value('208.67.222.222', _('Cisco Public DNS (208.67.222.222)'));
        o.value('8.8.8.8', _('Google Public DNS (8.8.8.8)'));
        o.value('', '---');
        o.value('223.5.5.5', _('Aliyun Public DNS (223.5.5.5)'));
        o.value('119.29.29.29', _('Tencent Public DNS (119.29.29.29)'));
        o.value('117.50.10.10', _('ThreatBook Public DNS (117.50.10.10)'));
        o.default = '8.8.8.8';
        o.rmempty = false;
        o.depends({'routing_mode': 'custom', '!reverse': true});
        o.validate = function(section_id, value) {
            if (section_id && !['wan'].includes(value)) {
                if (!value)
                    return _('Expecting: %s').format(_('non-empty value'));

                let ipv6_support = this.section.formvalue(section_id, 'ipv6_support');
                try {
                    let url = new URL(value.replace(/^.*:\/\//, 'http://'));
                    if (stubValidator.apply('hostname', url.hostname))
                        return true;
                    else if (stubValidator.apply('ip4addr', url.hostname))
                        return true;
                    else if ((ipv6_support === '1') && stubValidator.apply('ip6addr', url.hostname.match(/^\[(.+)\]$/)?.[1]))
                        return true;
                    else
                        return _('Expecting: %s').format(_('valid DNS server address'));
                } catch(e) {}

                if (!stubValidator.apply((ipv6_support === '1') ? 'ipaddr' : 'ip4addr', value))
                    return _('Expecting: %s').format(_('valid DNS server address'));
            }

            return true;
        }

        o = s.taboption('routing', form.Value, 'china_dns_server', _('China DNS server'),
            _('The dns server for resolving China domains. Support UDP, TCP, DoH, DoQ, DoT.'));
        o.value('wan', _('WAN DNS (read from interface)'));
        o.value('223.5.5.5', _('Aliyun Public DNS (223.5.5.5)'));
        o.value('210.2.4.8', _('CNNIC Public DNS (210.2.4.8)'));
        o.value('119.29.29.29', _('Tencent Public DNS (119.29.29.29)'));
        o.value('117.50.10.10', _('ThreatBook Public DNS (117.50.10.10)'));
        o.depends('routing_mode', 'bypass_mainland_china');
        o.default = '223.5.5.5';
        o.rmempty = false;
        o.validate = function(section_id, value) {
            if (section_id && !['wan'].includes(value)) {
                if (!value)
                    return _('Expecting: %s').format(_('non-empty value'));

                try {
                    let url = new URL(value.replace(/^.*:\/\//, 'http://'));
                    if (stubValidator.apply('hostname', url.hostname))
                        return true;
                    else if (stubValidator.apply('ip4addr', url.hostname))
                        return true;
                    else if (stubValidator.apply('ip6addr', url.hostname.match(/^\[(.+)\]$/)?.[1]))
                        return true;
                    else
                        return _('Expecting: %s').format(_('valid DNS server address'));
                } catch(e) {}

                if (!stubValidator.apply('ipaddr', value))
                    return _('Expecting: %s').format(_('valid DNS server address'));
            }

            return true;
        }

        o = s.taboption('routing', form.ListValue, 'routing_mode', _('Routing mode'));
        o.value('custom', _('Custom routing'));
        o.value('global', _('Global'));
        o.default = 'Custom routing';
        o.rmempty = false;
        o.onchange = function(ev, section_id, value) {
            if (section_id && value === 'custom')
                this.map.save(null, true);
        }

        o = s.taboption('routing', form.Value, 'routing_port', _('Routing ports'),
            _('Specify target ports to be proxied. Multiple ports must be separated by commas.'));
        o.value('', _('All ports'));
        o.value('common', _('Common ports only (bypass P2P traffic)'));
        o.validate = function(section_id, value) {
            if (section_id && value && value !== 'common') {

                let ports = [];
                for (let i of value.split(',')) {
                    if (!stubValidator.apply('port', i) && !stubValidator.apply('portrange', i))
                        return _('Expecting: %s').format(_('valid port value'));
                    if (ports.includes(i))
                        return _('Port %s alrealy exists!').format(i);
                    ports = ports.concat(i);
                }
            }

            return true;
        }

        o = s.taboption('routing', form.ListValue, 'proxy_mode', _('Proxy mode'));
        o.value('redirect', _('Redirect TCP'));
        if (features.fp_has_tproxy)
            o.value('redirect_tproxy', _('Redirect TCP + TProxy UDP'));
        if (features.fp_has_ip_full && features.fp_has_tun) {
            o.value('redirect_tun', _('Redirect TCP + Tun UDP'));
            o.value('tun', _('Tun TCP/UDP'));
        } else {
            o.description = _('To enable Tun support, you need to install <code>ip-full</code> and <code>kmod-tun</code>');
        }
        o.default = 'redirect_tproxy';
        o.rmempty = false;

        o = s.taboption('routing', form.Flag, 'ipv6_support', _('IPv6 support'));
        o.default = o.enabled;
        o.rmempty = false;

        /* Custom routing settings start */
        /* Routing settings start */
        // [Category B] 路由高级配置面板：现已提升为全局唯一路由配置核心
        o = s.taboption('routing', form.SectionValue, '_routing', form.NamedSection, 'routing', 'flowproxy');
                      
        ss = o.subsection;
        so = ss.option(form.ListValue, 'tcpip_stack', _('TCP/IP stack'),
            _('TCP/IP stack.'));
        if (features.with_gvisor) {
            so.value('mixed', _('Mixed'));
            so.value('gvisor', _('gVisor'));
        }
        so.value('system', _('System'));
        so.default = 'system';
        so.depends('flowproxy.config.proxy_mode', 'redirect_tun');
        so.depends('flowproxy.config.proxy_mode', 'tun');
        so.rmempty = false;
        so.onchange = function(ev, section_id, value) {
            let desc = ev.target.nextElementSibling;
            if (value === 'mixed')
                desc.innerHTML = _('Mixed <code>system</code> TCP stack and <code>gVisor</code> UDP stack.')
            else if (value === 'gvisor')
                desc.innerHTML = _('Based on google/gvisor.');
            else if (value === 'system')
                desc.innerHTML = _('Less compatibility and sometimes better performance.');
        }

        so = ss.option(form.Flag, 'endpoint_independent_nat', _('Enable endpoint-independent NAT'),
            _('Performance may degrade slightly, so it is not recommended to enable on when it is not needed.'));
        so.default = so.enabled;
        so.depends('tcpip_stack', 'mixed');
        so.depends('tcpip_stack', 'gvisor');
        so.rmempty = false;

        so = ss.option(form.Value, 'udp_timeout', _('UDP NAT expiration time'),
            _('In seconds.'));
        so.datatype = 'uinteger';
        so.placeholder = '300';
        so.depends('flowproxy.config.proxy_mode', 'redirect_tproxy');
        so.depends('flowproxy.config.proxy_mode', 'redirect_tun');
        so.depends('flowproxy.config.proxy_mode', 'tun');

        so = ss.option(form.Flag, 'bypass_cn_traffic', _('Bypass CN traffic'),
            _('Bypass mainland China traffic via firewall rules by default.'));
        so.rmempty = false;

        so = ss.option(form.ListValue, 'domain_strategy', _('Domain strategy'),
            _('If set, the requested domain name will be resolved to IP before routing.'));
        for (let i in fp.dns_strategy)
            so.value(i, fp.dns_strategy[i]);

        so = ss.option(form.Flag, 'sniff_override', _('Override destination'),
            _('Override the connection destination address with the sniffed domain.'));
        so.default = so.enabled;
        so.rmempty = false;

        so = ss.option(form.ListValue, 'default_outbound', _('Default outbound'),
            _('Default outbound for connections not matched by any routing rules.'));
        so.load = function(section_id) {
            delete this.keylist;
            delete this.vallist;

            this.value('nil', _('Disable (the service)'));
            this.value('direct-out', _('Direct'));
            this.value('block-out', _('Block'));
            uci.sections(data[0], 'routing_node', (res) => {
                if (res.enabled === '1')
                    this.value(res['.name'], res.label);
            });

            return this.super('load', section_id);
        }
        so.default = 'nil';
        so.rmempty = false;

        so = ss.option(form.ListValue, 'default_outbound_dns', _('Default outbound DNS'),
            _('Default DNS server for resolving domain name in the server address.'));
        so.load = function(section_id) {
            delete this.keylist;
            delete this.vallist;

            this.value('default-dns', _('Default DNS (issued by WAN)'));
            this.value('system-dns', _('System DNS'));
            uci.sections(data[0], 'dns_server', (res) => {
                if (res.enabled === '1')
                    this.value(res['.name'], res.label);
            });

            return this.super('load', section_id);
        }
        so.default = 'default-dns';
        so.rmempty = false;
        /* Routing settings end */

        /* Routing nodes start */
        s.tab('routing_node', _('Routing Nodes'));
        o = s.taboption('routing_node', form.SectionValue, '_routing_node', form.GridSection, 'routing_node');
        o.depends('routing_mode', 'custom');

        ss = o.subsection;
        ss.addremove = true;
        ss.rowcolors = true;
        ss.sortable = true;
        ss.nodescriptions = true;
        ss.modaltitle = L.bind(fp.loadModalTitle, this, _('Routing node'), _('Add a routing node'), data[0]);
        ss.sectiontitle = L.bind(fp.loadDefaultLabel, this, data[0]);
        ss.renderSectionAdd = L.bind(fp.renderSectionAdd, this, ss);

        so = ss.option(form.Value, 'label', _('Label'));
        so.load = L.bind(fp.loadDefaultLabel, this, data[0]);
        so.validate = L.bind(fp.validateUniqueValue, this, data[0], 'routing_node', 'label');
        so.modalonly = true;

        so = ss.option(form.Flag, 'enabled', _('Enable'));
        so.default = so.enabled;
        so.rmempty = false;
        so.editable = true;

        so = ss.option(form.ListValue, 'node', _('Node'),
            _('Outbound node'));
        so.value('urltest', _('URLTest'));
        for (let i in proxy_nodes)
            so.value(i, proxy_nodes[i]);
        so.validate = L.bind(fp.validateUniqueValue, this, data[0], 'routing_node', 'node');
        so.editable = true;

        so = ss.option(form.ListValue, 'domain_resolver', _('Domain resolver'),
            _('For resolving domain name in the server address.'));
        so.load = function(section_id) {
            delete this.keylist;
            delete this.vallist;

            this.value('', _('Default'));
            this.value('default-dns', _('Default DNS (issued by WAN)'));
            this.value('system-dns', _('System DNS'));
            uci.sections(data[0], 'dns_server', (res) => {
                if (res.enabled === '1')
                    this.value(res['.name'], res.label);
            });

            return this.super('load', section_id);
        }
        so.depends({'node': 'urltest', '!reverse': true});
        so.modalonly = true;

        so = ss.option(form.ListValue, 'domain_strategy', _('Domain strategy'),
            _('The domain strategy for resolving the domain name in the address.'));
        for (let i in fp.dns_strategy)
            so.value(i, fp.dns_strategy[i]);
        so.depends({'node': 'urltest', '!reverse': true});
        so.modalonly = true;

        so = ss.option(widgets.DeviceSelect, 'bind_interface', _('Bind interface'),
            _('The network interface to bind to.'));
        so.multiple = false;
        so.noaliases = true;
        so.depends({'outbound': '', 'node': /^((?!urltest$).)+$/});
        so.modalonly = true;

        so = ss.option(form.ListValue, 'outbound', _('Outbound'),
            _('The tag of the upstream outbound.<br/>Other dial fields will be ignored when enabled.'));
        so.load = function(section_id) {
            delete this.keylist;
            delete this.vallist;

            this.value('', _('Direct'));
            uci.sections(data[0], 'routing_node', (res) => {
                if (res['.name'] !== section_id && res.enabled === '1')
                    this.value(res['.name'], res.label);
            });

            return this.super('load', section_id);
        }
        so.validate = function(section_id, value) {
            if (section_id && value) {
                let node = this.section.formvalue(section_id, 'node');

                let conflict = false;
                uci.sections(data[0], 'routing_node', (res) => {
                    if (res['.name'] !== section_id) {
                        if (res.outbound === section_id && res['.name'] == value)
                            conflict = true;
                        else if (res.node === 'urltest' && res.urltest_nodes?.includes(node) && res['.name'] == value)
                            conflict = true;
                    }
                });
                if (conflict)
                    return _('Recursive outbound detected!');
            }

            return true;
        }
        so.depends({'node': 'urltest', '!reverse': true});
        so.editable = true;

        so = ss.option(fp.CBIStaticList, 'urltest_nodes', _('URLTest nodes'),
            _('List of nodes to test.'));
        for (let i in proxy_nodes)
            so.value(i, proxy_nodes[i]);
        so.depends('node', 'urltest');
        so.validate = function(section_id) {
            let value = this.section.formvalue(section_id, 'urltest_nodes');
            if (section_id && !value.length)
                return _('Expecting: %s').format(_('non-empty value'));

            return true;
        }
        so.modalonly = true;

        so = ss.option(form.Value, 'urltest_url', _('Test URL'),
            _('The URL to test.'));
        so.placeholder = 'https://www.gstatic.com/generate_204';
        so.validate = function(section_id, value) {
            if (section_id && value) {
                try {
                    let url = new URL(value);
                    if (!url.hostname)
                        return _('Expecting: %s').format(_('valid URL'));
                }
                catch(e) {
                    return _('Expecting: %s').format(_('valid URL'));
                }
            }

            return true;
        }
        so.depends('node', 'urltest');
        so.modalonly = true;

        so = ss.option(form.Value, 'urltest_interval', _('Test interval'),
            _('The test interval in seconds.'));
        so.datatype = 'uinteger';
        so.placeholder = '180';
        so.validate = function(section_id, value) {
            if (section_id && value) {
                let idle_timeout = this.section.formvalue(section_id, 'idle_timeout') || '1800';
                if (parseInt(value) > parseInt(idle_timeout))
                    return _('Test interval must be less or equal than idle timeout.');
            }

            return true;
        }
        so.depends('node', 'urltest');
        so.modalonly = true;

        so = ss.option(form.Value, 'urltest_tolerance', _('Test tolerance'),
            _('The test tolerance in milliseconds.'));
        so.datatype = 'uinteger';
        so.placeholder = '50';
        so.depends('node', 'urltest');
        so.modalonly = true;

        so = ss.option(form.Value, 'urltest_idle_timeout', _('Idle timeout'),
            _('The idle timeout in seconds.'));
        so.datatype = 'uinteger';
        so.placeholder = '1800';
        so.depends('node', 'urltest');
        so.modalonly = true;

        so = ss.option(form.Flag, 'urltest_interrupt_exist_connections', _('Interrupt existing connections'),
            _('Interrupt existing connections when the selected outbound has changed.'));
        so.depends('node', 'urltest');
        so.modalonly = true;
        /* Routing nodes end */

        /* Routing rules start */
        s.tab('routing_rule', _('Routing Rules'));
        o = s.taboption('routing_rule', form.SectionValue, '_routing_rule', form.GridSection, 'routing_rule');
        o.depends('routing_mode', 'custom');

        ss = o.subsection;
        ss.addremove = true;
        ss.rowcolors = true;
        ss.sortable = true;
        ss.nodescriptions = true;
        ss.modaltitle = L.bind(fp.loadModalTitle, this, _('Routing rule'), _('Add a routing rule'), data[0]);
        ss.sectiontitle = L.bind(fp.loadDefaultLabel, this, data[0]);
        ss.renderSectionAdd = L.bind(fp.renderSectionAdd, this, ss);

        ss.tab('field_other', _('Other fields'));
        ss.tab('field_host', _('Host/IP fields'));
        ss.tab('field_port', _('Port fields'));
        ss.tab('fields_process', _('Process fields'));

        so = ss.taboption('field_other', form.Value, 'label', _('Label'));
        so.load = L.bind(fp.loadDefaultLabel, this, data[0]);
        so.validate = L.bind(fp.validateUniqueValue, this, data[0], 'routing_rule', 'label');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Flag, 'enabled', _('Enable'));
        so.default = so.enabled;
        so.rmempty = false;
        so.editable = true;

        so = ss.taboption('field_other', form.ListValue, 'mode', _('Mode'),
            _('The default rule uses the following matching logic:<br/>' +
                '<code>(domain || domain_suffix || domain_keyword || domain_regex || ip_cidr || ip_is_private)</code> &&<br/>' +
                '<code>(port || port_range)</code> &&<br/>' +
                '<code>(source_ip_cidr || source_ip_is_private)</code> &&<br/>' +
                '<code>(source_port || source_port_range)</code> &&<br/>' +
                '<code>other fields</code>.<br/>' +
                'Additionally, included rule sets can be considered merged rather than as a single rule sub-item.'));
        so.value('default', _('Default'));
        so.default = 'default';
        so.rmempty = false;
        so.readonly = true;

        so = ss.taboption('field_other', form.ListValue, 'ip_version', _('IP version'),
            _('4 or 6. Not limited if empty.'));
        so.value('4', _('IPv4'));
        so.value('6', _('IPv6'));
        so.value('', _('Both'));
        so.modalonly = true;

        so = ss.taboption('field_other', form.MultiValue, 'protocol', _('Protocol'),
            _('Sniffed protocol, see <a target="_blank" href="https://sing-box.sagernet.org/configuration/route/sniff/">Sniff</a> for details.'));
        so.value('bittorrent', _('BitTorrent'));
        so.value('dns', _('DNS'));
        so.value('dtls', _('DTLS'));
        so.value('http', _('HTTP'));
        so.value('quic', _('QUIC'));
        so.value('rdp', _('RDP'));
        so.value('ssh', _('SSH'));
        so.value('stun', _('STUN'));
        so.value('tls', _('TLS'));

        so = ss.taboption('field_other', form.Value, 'client', _('Client'),
            _('Sniffed client type (QUIC client type or SSH client name).'));
        so.value('chromium', _('Chromium / Cronet'));
        so.value('firefox', _('Firefox / uquic firefox'));
        so.value('quic-go', _('quic-go / uquic chrome'));
        so.value('safari', _('Safari / Apple Network API'));
        so.depends('protocol', 'quic');
        so.depends('protocol', 'ssh');
        so.modalonly = true;

        so = ss.taboption('field_other', form.ListValue, 'network', _('Network'));
        so.value('tcp', _('TCP'));
        so.value('udp', _('UDP'));
        so.value('', _('Both'));

        so = ss.taboption('field_other', form.DynamicList, 'user', _('User'),
            _('Match user name.'));
        so.modalonly = true;

        so = ss.taboption('field_other', fp.CBIStaticList, 'rule_set', _('Rule set'),
            _('Match rule set.'));
        so.load = function(section_id) {
            delete this.keylist;
            delete this.vallist;

            uci.sections(data[0], 'ruleset', (res) => {
                if (res.enabled === '1')
                    this.value(res['.name'], res.label);
            });

            return this.super('load', section_id);
        }
        so.modalonly = true;

        so = ss.taboption('field_other', form.Flag, 'rule_set_ip_cidr_match_source', _('Rule set IP CIDR as source IP'),
            _('Make IP CIDR in rule set used to match the source IP.'));
        so.modalonly = true;

        so = ss.taboption('field_other', form.Flag, 'invert', _('Invert'),
            _('Invert match result.'));
        so.modalonly = true;

        so = ss.taboption('field_other', form.ListValue, 'action', _('Action'));
        so.value('route', _('Route'));
        so.value('route-options', _('Route options'));
        so.value('reject', _('Reject'));
        so.value('resolve', _('Resolve'));
        so.default = 'route';
        so.rmempty = false;
        so.editable = true;

        so = ss.taboption('field_other', form.ListValue, 'outbound', _('Outbound'),
            _('Tag of the target outbound.'));
        so.load = function(section_id) {
            delete this.keylist;
            delete this.vallist;

            this.value('direct-out', _('Direct'));
            uci.sections(data[0], 'routing_node', (res) => {
                if (res.enabled === '1')
                    this.value(res['.name'], res.label);
            });

            return this.super('load', section_id);
        }
        so.rmempty = false;
        so.depends('action', 'route');
        so.editable = true;

        so = ss.taboption('field_other', form.Value, 'override_address', _('Override address'),
            _('Override the connection destination address.'));
        so.datatype = 'ipaddr';
        so.depends('action', 'route');
        so.depends('action', 'route-options');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Value, 'override_port', _('Override port'),
            _('Override the connection destination port.'));
        so.datatype = 'port';
        so.depends('action', 'route');
        so.depends('action', 'route-options');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Flag, 'udp_disable_domain_unmapping', _('Disable UDP domain unmapping'),
            _('If enabled, for UDP proxy requests addressed to a domain, the original packet address will be sent in the response instead of the mapped domain.'));
        so.depends('action', 'route');
        so.depends('action', 'route-options');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Flag, 'udp_connect', _('connect UDP connections'),
            _('If enabled, attempts to connect UDP connection to the destination instead of listen.'));
        so.depends('action', 'route');
        so.depends('action', 'route-options');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Value, 'udp_timeout', _('UDP timeout'),
            _('Timeout for UDP connections.<br/>Setting a larger value than the UDP timeout in inbounds will have no effect.'));
        so.datatype = 'uinteger';
        so.depends('action', 'route');
        so.depends('action', 'route-options');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Flag, 'tls_record_fragment', _('TLS record fragment'),
            _('Fragment TLS handshake into multiple TLS records.'));
        so.depends('action', 'route');
        so.depends('action', 'route-options');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Flag, 'tls_fragment', _('TLS fragment'),
            _('Fragment TLS handshakes. Due to poor performance, try <code>%s</code> first.').format(
                _('TLS record fragment')));
        so.depends('action', 'route');
        so.depends('action', 'route-options');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Value, 'tls_fragment_fallback_delay', _('Fragment fallback delay'),
            _('The fallback value in milliseconds used when TLS segmentation cannot automatically determine the wait time.'));
        so.datatype = 'uinteger';
        so.placeholder = '500';
        so.depends('tls_fragment', '1');
        so.modalonly = true;

        so = ss.taboption('field_other', form.ListValue, 'resolve_server', _('DNS server'),
            _('Specifies DNS server tag to use instead of selecting through DNS routing.'));
        so.load = function(section_id) {
            delete this.keylist;
            delete this.vallist;

            this.value('', _('Default'));
            this.value('default-dns', _('Default DNS (issued by WAN)'));
            this.value('system-dns', _('System DNS'));
            uci.sections(data[0], 'dns_server', (res) => {
                if (res.enabled === '1')
                    this.value(res['.name'], res.label);
            });

            return this.super('load', section_id);
        }
        so.depends('action', 'resolve');
        so.modalonly = true;

        so = ss.taboption('field_other', form.ListValue, 'reject_method', _('Method'));
        so.value('default', _('Reply with TCP RST / ICMP port unreachable'));
        so.value('drop', _('Drop packets'));
        so.depends('action', 'reject');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Flag, 'reject_no_drop', _('Don\'t drop packets'),
            _('<code>%s</code> will be temporarily overwritten to <code>%s</code> after 50 triggers in 30s if not enabled.').format(
                _('Method'), _('Drop packets')));
        so.depends('reject_method', 'default');
        so.modalonly = true;

        so = ss.taboption('field_other', form.ListValue, 'resolve_strategy', _('Resolve strategy'),
            _('Domain strategy for resolving the domain names.'));
        for (let i in fp.dns_strategy)
            so.value(i, fp.dns_strategy[i]);
        so.depends('action', 'resolve');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Flag, 'resolve_disable_cache', _('Disable DNS cache'),
            _('Disable DNS cache in this query.'));
        so.depends('action', 'resolve');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Value, 'resolve_rewrite_ttl', _('Rewrite TTL'),
            _('Rewrite TTL in DNS responses.'));
        so.datatype = 'uinteger';
        so.depends('action', 'resolve');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Value, 'resolve_client_subnet', _('EDNS Client subnet'),
            _('Append a <code>edns0-subnet</code> OPT extra record with the specified IP prefix to every query by default.<br/>' +
                'If value is an IP address instead of prefix, <code>/32</code> or <code>/128</code> will be appended automatically.'));
        so.datatype = 'or(cidr, ipaddr)';
        so.depends('action', 'resolve');
        so.modalonly = true;

        so = ss.taboption('field_host', form.DynamicList, 'domain', _('Domain name'),
            _('Match full domain.'));
        so.datatype = 'hostname';
        so.modalonly = true;

        so = ss.taboption('field_host', form.DynamicList, 'domain_suffix', _('Domain suffix'),
            _('Match domain suffix.'));
        so.modalonly = true;

        so = ss.taboption('field_host', form.DynamicList, 'domain_keyword', _('Domain keyword'),
            _('Match domain using keyword.'));
        so.modalonly = true;

        so = ss.taboption('field_host', form.DynamicList, 'domain_regex', _('Domain regex'),
            _('Match domain using regular expression.'));
        so.modalonly = true;

        so = ss.taboption('field_host', form.DynamicList, 'source_ip_cidr', _('Source IP CIDR'),
            _('Match source IP CIDR.'));
        so.datatype = 'or(cidr, ipaddr)';
        so.modalonly = true;

        so = ss.taboption('field_host', form.Flag, 'source_ip_is_private', _('Match private source IP'));
        so.modalonly = true;

        so = ss.taboption('field_host', form.DynamicList, 'ip_cidr', _('IP CIDR'),
            _('Match IP CIDR.'));
        so.datatype = 'or(cidr, ipaddr)';
        so.modalonly = true;

        so = ss.taboption('field_host', form.Flag, 'ip_is_private', _('Match private IP'));
        so.modalonly = true;

        so = ss.taboption('field_port', form.DynamicList, 'source_port', _('Source port'),
            _('Match source port.'));
        so.datatype = 'port';
        so.modalonly = true;

        so = ss.taboption('field_port', form.DynamicList, 'source_port_range', _('Source port range'),
            _('Match source port range. Format as START:/:END/START:END.'));
        so.validate = fp.validatePortRange;
        so.modalonly = true;

        so = ss.taboption('field_port', form.DynamicList, 'port', _('Port'),
            _('Match port.'));
        so.datatype = 'port';
        so.modalonly = true;

        so = ss.taboption('field_port', form.DynamicList, 'port_range', _('Port range'),
            _('Match port range. Format as START:/:END/START:END.'));
        so.validate = fp.validatePortRange;
        so.modalonly = true;

        so = ss.taboption('fields_process', form.DynamicList, 'process_name', _('Process name'),
            _('Match process name.'));
        so.modalonly = true;

        so = ss.taboption('fields_process', form.DynamicList, 'process_path', _('Process path'),
            _('Match process path.'));
        so.modalonly = true;

        so = ss.taboption('fields_process', form.DynamicList, 'process_path_regex', _('Process path (regex)'),
            _('Match process path using regular expression.'));
        so.modalonly = true;
        /* Routing rules end */

        /* DNS settings start */
        s.tab('dns', _('DNS Settings'));
        o = s.taboption('dns', form.SectionValue, '_dns', form.NamedSection, 'dns', 'flowproxy');
        o.depends('routing_mode', 'custom');

        ss = o.subsection;
        so.default = '0';
        so.rmempty = false;
        so = ss.option(form.ListValue, 'default_strategy', _('Default DNS strategy'),
            _('The DNS strategy for resolving the domain name in the address.'));
        for (let i in fp.dns_strategy)
            so.value(i, fp.dns_strategy[i]);

        so = ss.option(form.ListValue, 'default_server', _('Default DNS server'));
        so.load = function(section_id) {
            delete this.keylist;
            delete this.vallist;

            this.value('default-dns', _('Default DNS (issued by WAN)'));
            this.value('system-dns', _('System DNS'));
            uci.sections(data[0], 'dns_server', (res) => {
                if (res.enabled === '1')
                    this.value(res['.name'], res.label);
            });

            return this.super('load', section_id);
        }
        so.default = 'default-dns';
        so.rmempty = false;

        so = ss.option(form.Flag, 'disable_cache', _('Disable DNS cache'));

        so = ss.option(form.Flag, 'disable_cache_expire', _('Disable cache expire'));
        so.depends('disable_cache', '0');

        so = ss.option(form.Flag, 'independent_cache', _('Independent cache per server'),
            _('Make each DNS server\'s cache independent for special purposes. If enabled, will slightly degrade performance.'));
        so.depends('disable_cache', '0');

        so = ss.option(form.Value, 'client_subnet', _('EDNS Client subnet'),
            _('Append a <code>edns0-subnet</code> OPT extra record with the specified IP prefix to every query by default.<br/>' +
                'If value is an IP address instead of prefix, <code>/32</code> or <code>/128</code> will be appended automatically.'));
        so.datatype = 'or(cidr, ipaddr)';

        so = ss.option(form.Flag, 'cache_file_store_rdrc', _('Store RDRC'),
            _('Store rejected DNS response cache.<br/>' +
                'The check results of <code>Address filter DNS rule items</code> will be cached until expiration.'));

        so = ss.option(form.Value, 'cache_file_rdrc_timeout', _('RDRC timeout'),
            _('Timeout of rejected DNS response cache in seconds. <code>604800 (7d)</code> is used by default.'));
        so.datatype = 'uinteger';
        so.depends('cache_file_store_rdrc', '1');
        /* DNS settings end */

        /* DNS servers start */
        s.tab('dns_server', _('DNS Servers'));
        o = s.taboption('dns_server', form.SectionValue, '_dns_server', form.GridSection, 'dns_server');
        o.depends('routing_mode', 'custom');

        ss = o.subsection;
        ss.addremove = true;
        ss.rowcolors = true;
        ss.sortable = true;
        ss.nodescriptions = true;
        ss.modaltitle = L.bind(fp.loadModalTitle, this, _('DNS server'), _('Add a DNS server'), data[0]);
        ss.sectiontitle = L.bind(fp.loadDefaultLabel, this, data[0]);
        ss.renderSectionAdd = L.bind(fp.renderSectionAdd, this, ss);

        so = ss.option(form.Value, 'label', _('Label'));
        so.load = L.bind(fp.loadDefaultLabel, this, data[0]);
        so.validate = L.bind(fp.validateUniqueValue, this, data[0], 'dns_server', 'label');
        so.modalonly = true;

        so = ss.option(form.Flag, 'enabled', _('Enable'));
        so.default = so.enabled;
        so.rmempty = false;
        so.editable = true;

        so = ss.option(form.ListValue, 'type', _('Type'));
        so.value('udp', _('UDP'));
        so.value('tcp', _('TCP'));
        so.value('tls', _('TLS'));
        so.value('https', _('HTTPS'));
        so.value('h3', _('HTTP/3'));
        so.value('quic', _('QUIC'));
        so.default = 'udp';
        so.rmempty = false;

        so = ss.option(form.Value, 'server', _('Address'),
            _('The address of the dns server.'));
        so.datatype = 'or(hostname, ipaddr)';
        so.rmempty = false;

        so = ss.option(form.Value, 'server_port', _('Port'),
            _('The port of the DNS server.'));
        so.placeholder = 'auto';
        so.datatype = 'port';

        so = ss.option(form.Value, 'path', _('Path'),
            _('The path of the DNS server.'));
        so.placeholder = '/dns-query';
        so.depends('type', 'https');
        so.depends('type', 'h3');
        so.modalonly = true;

        so = ss.option(form.DynamicList, 'headers', _('Headers'),
            _('Additional headers to be sent to the DNS server.'));
        so.depends('type', 'https');
        so.depends('type', 'h3');
        so.modalonly = true;

        so = ss.option(form.Value, 'tls_sni', _('TLS SNI'),
            _('Used to verify the hostname on the returned certificates.'));
        so.depends('type', 'tls');
        so.depends('type', 'https');
        so.depends('type', 'h3');
        so.depends('type', 'quic');
        so.modalonly = true;

        so = ss.option(form.ListValue, 'address_resolver', _('Address resolver'),
            _('Tag of a another server to resolve the domain name in the address. Required if address contains domain.'));
        so.load = function(section_id) {
            delete this.keylist;
            delete this.vallist;

            this.value('', _('None'));
            this.value('default-dns', _('Default DNS (issued by WAN)'));
            this.value('system-dns', _('System DNS'));
            uci.sections(data[0], 'dns_server', (res) => {
                if (res['.name'] !== section_id && res.enabled === '1')
                    this.value(res['.name'], res.label);
            });

            return this.super('load', section_id);
        }
        so.validate = function(section_id, value) {
            if (section_id && value) {
                let conflict = false;
                uci.sections(data[0], 'dns_server', (res) => {
                    if (res['.name'] !== section_id)
                        if (res.address_resolver === section_id && res['.name'] == value)
                            conflict = true;
                });
                if (conflict)
                    return _('Recursive resolver detected!');
            }

            return true;
        }
        so.modalonly = true;

        so = ss.option(form.ListValue, 'address_strategy', _('Address strategy'),
            _('The domain strategy for resolving the domain name in the address.'));
        for (let i in fp.dns_strategy)
            so.value(i, fp.dns_strategy[i]);
        so.depends({'address_resolver': '', '!reverse': true});
        so.modalonly = true;

        so = ss.option(form.ListValue, 'outbound', _('Outbound'),
            _('Tag of an outbound for connecting to the dns server.'));
        so.load = function(section_id) {
            delete this.keylist;
            delete this.vallist;

            this.value('direct-out', _('Direct'));
            uci.sections(data[0], 'routing_node', (res) => {
                if (res.enabled === '1')
                    this.value(res['.name'], res.label);
            });

            return this.super('load', section_id);
        }
        so.default = 'direct-out';
        so.rmempty = false;
        so.editable = true;
        /* DNS servers end */

        /* DNS rules start */
        s.tab('dns_rule', _('DNS Rules'));

        // 🌟 新增：显式的全透明提示横幅
        o = s.taboption('dns_rule', form.DummyValue, '_dns_transparent_notice', '');
        o.depends('routing_mode', 'custom');
        o.rawhtml = true;
        o.default = '<div style="padding: 12px 15px; margin-bottom: 15px; background-color: #e8f4f8; border-left: 4px solid #17a2b8; border-radius: 4px; color: #333; line-height: 1.5;"><b>💡 Sing-box 1.14 以上版本专属特性 (全透明模式)：</b><br/>已支持 evaluate 评估规则动作。建议点击下方按钮生成<b>【智能分流底包】</b>，并在其上方添加您的自定义规则（例如指定去广告）。</div>';

        // 🌟 魔法按钮：直接显示，无需开关前提
        o = s.taboption('dns_rule', form.DummyValue, '_magic_st_btn', _('快速向导'));
        o.depends('routing_mode', 'custom');
        o.description = '一键导入智能分流模板作为基础底包。';
        o.renderWidget = function(section_id) {
            return E('button', {
                'class': 'btn cbi-button cbi-button-apply',
                'click': function(ev) {
                    ev.preventDefault();
                    if (!confirm('⚠️ 确定要生成智能分流底包吗？\n生成后，请务必将这 3 条新规则移动至列表的最下方（即最后执行）！')) return;

                    L.require('fs').then(fs => {
                        let cmd = `
                            uci -q delete flowproxy.dns_rule_st_eval
                            uci -q delete flowproxy.dns_rule_st_route
                            uci -q delete flowproxy.dns_rule_st_resp
                            uci add flowproxy dns_rule
                            uci rename flowproxy.@dns_rule[-1]="dns_rule_st_eval"
                            uci set flowproxy.dns_rule_st_eval.label="评估"
                            uci set flowproxy.dns_rule_st_eval.enabled="1"
                            uci set flowproxy.dns_rule_st_eval.action="evaluate"
                            uci set flowproxy.dns_rule_st_eval.server="main-dns"
                            
                            uci add flowproxy dns_rule
                            uci rename flowproxy.@dns_rule[-1]="dns_rule_st_route"
                            uci set flowproxy.dns_rule_st_route.label="判断"
                            uci set flowproxy.dns_rule_st_route.enabled="1"
                            uci set flowproxy.dns_rule_st_route.action="route"
                            uci set flowproxy.dns_rule_st_route.match_response="1"
                            uci add_list flowproxy.dns_rule_st_route.rule_set="geoipcn"
                            uci set flowproxy.dns_rule_st_route.server="default-dns"
                            
                            uci add flowproxy dns_rule
                            uci rename flowproxy.@dns_rule[-1]="dns_rule_st_resp"
                            uci set flowproxy.dns_rule_st_resp.label="响应"
                            uci set flowproxy.dns_rule_st_resp.enabled="1"
                            uci set flowproxy.dns_rule_st_resp.action="route"
                            uci set flowproxy.dns_rule_st_route.server="default-dns"
                            
                            uci commit flowproxy
                        `;
                        fs.exec_direct('sh', ['-c', cmd]).then(() => {
                            alert('✅ 模板生成成功！页面即将刷新。');
                            location.reload();
                        });
                    });
                }
            }, '一键生成 evaluate 模板');
        };

        o = s.taboption('dns_rule', form.SectionValue, '_dns_rule', form.GridSection, 'dns_rule');
        o.depends('routing_mode', 'custom');

        ss = o.subsection;
        ss.addremove = true;
        ss.rowcolors = true;
        ss.sortable = true;
        ss.nodescriptions = true;
        ss.modaltitle = L.bind(fp.loadModalTitle, this, _('DNS rule'), _('Add a DNS rule'), data[0]);
        ss.sectiontitle = L.bind(fp.loadDefaultLabel, this, data[0]);
        ss.renderSectionAdd = L.bind(fp.renderSectionAdd, this, ss);

        ss.tab('field_other', _('Other fields'));
        ss.tab('field_host', _('Host/IP fields'));
        ss.tab('field_port', _('Port fields'));
        ss.tab('fields_process', _('Process fields'));

        so = ss.taboption('field_other', form.Value, 'label', _('Label'));
        so.load = L.bind(fp.loadDefaultLabel, this, data[0]);
        so.validate = L.bind(fp.validateUniqueValue, this, data[0], 'dns_rule', 'label');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Flag, 'enabled', _('Enable'));
        so.default = so.enabled;
        so.rmempty = false;
        so.editable = true;

        so = ss.taboption('field_other', form.ListValue, 'mode', _('Mode'),
            _('The default rule uses the following matching logic:<br/>' +
                '<code>(domain || domain_suffix || domain_keyword || domain_regex)</code> &&<br/>' +
                '<code>(port || port_range)</code> &&<br/>' +
                '<code>(source_ip_cidr || source_ip_is_private)</code> &&<br/>' +
                '<code>(source_port || source_port_range)</code> &&<br/>' +
                '<code>other fields</code>.<br/>' +
                'Additionally, included rule sets can be considered merged rather than as a single rule sub-item.'));
        so.value('default', _('Default'));
        so.default = 'default';
        so.rmempty = false;
        so.readonly = true;
        so.modalonly = true;

        so = ss.taboption('field_other', form.ListValue, 'ip_version', _('IP version'));
        so.value('4', _('IPv4'));
        so.value('6', _('IPv6'));
        so.value('', _('Both'));
        so.modalonly = true;

        so = ss.taboption('field_other', form.DynamicList, 'query_type', _('Query type'),
            _('Match query type.'));
        so.modalonly = true;

        so = ss.taboption('field_other', form.ListValue, 'network', _('Network'));
        so.value('tcp', _('TCP'));
        so.value('udp', _('UDP'));
        so.value('', _('Both'));

        so = ss.taboption('field_other', form.MultiValue, 'protocol', _('Protocol'),
            _('Sniffed protocol, see <a target="_blank" href="https://sing-box.sagernet.org/configuration/route/sniff/">Sniff</a> for details.'));
        so.value('bittorrent', _('BitTorrent'));
        so.value('dtls', _('DTLS'));
        so.value('http', _('HTTP'));
        so.value('quic', _('QUIC'));
        so.value('rdp', _('RDP'));
        so.value('ssh', _('SSH'));
        so.value('stun', _('STUN'));
        so.value('tls', _('TLS'));

        so = ss.taboption('field_other', form.DynamicList, 'user', _('User'),
            _('Match user name.'));
        so.modalonly = true;

        so = ss.taboption('field_other', fp.CBIStaticList, 'rule_set', _('Rule set'),
            _('Match rule set.'));
        so.load = function(section_id) {
            delete this.keylist;
            delete this.vallist;

            uci.sections(data[0], 'ruleset', (res) => {
                if (res.enabled === '1')
                    this.value(res['.name'], res.label);
            });

            return this.super('load', section_id);
        }
        so.modalonly = true;

        so = ss.taboption('field_other', form.Flag, 'rule_set_ip_cidr_match_source', _('Rule set IP CIDR as source IP'),
            _('Make IP CIDR in rule sets match the source IP.'));
        so.modalonly = true;

        so = ss.taboption('field_other', form.Flag, 'rule_set_ip_cidr_accept_empty', _('Accept empty query response'),
            _('Make IP CIDR in rule-sets accept empty query response.'));
        so.modalonly = true;

        so = ss.taboption('field_other', form.Flag, 'invert', _('Invert'),
            _('Invert match result.'));
        so.modalonly = true;

        // 🌟 动作核心扩展：加入 evaluate 和 respond
        so = ss.taboption('field_other', form.ListValue, 'action', _('Action'));
        so.value('route', _('Route'));
        so.value('evaluate', _('Evaluate'));
        so.value('respond', _('Respond'));
        so.value('route-options', _('Route options'));
        so.value('reject', _('Reject'));
        so.value('predefined', _('Predefined'));
        so.default = 'route';
        so.rmempty = false;
        so.editable = true;

        // 🌟 新增：Match response (仅在 route 时显示)
        so = ss.taboption('field_other', form.Flag, 'match_response', _('Match response (匹配响应)'),
            _('开启后，将根据上级 <code>evaluate</code> 动作返回结果的 IP 进行目标匹配。<br/>通常配合 Rule Set (如 geoipcn) 使用。'));
        so.depends('action', 'route');
        so.modalonly = true;

        so = ss.taboption('field_other', form.ListValue, 'server', _('Server'),
            _('Tag of the target dns server.'));
        so.load = function(section_id) {
            delete this.keylist;
            delete this.vallist;

            this.value('default-dns', _('Default DNS (issued by WAN)'));
            this.value('system-dns', _('System DNS'));
            uci.sections(data[0], 'dns_server', (res) => {
                if (res.enabled === '1')
                    this.value(res['.name'], res.label);
            });

            return this.super('load', section_id);
        }
        so.rmempty = false;
        so.editable = true;
        so.depends('action', 'route');
        so.depends('action', 'evaluate'); // 让 evaluate 也能选服务器

        so = ss.taboption('field_other', form.ListValue, 'domain_strategy', _('Domain strategy'),
            _('Set domain strategy for this query.'));
        for (let i in fp.dns_strategy)
            so.value(i, fp.dns_strategy[i]);
        so.depends('action', 'route');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Flag, 'dns_disable_cache', _('Disable dns cache'),
            _('Disable cache and save cache in this query.'));
        so.depends('action', 'route');
        so.depends('action', 'route-options');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Value, 'rewrite_ttl', _('Rewrite TTL'),
            _('Rewrite TTL in DNS responses.'));
        so.datatype = 'uinteger';
        so.depends('action', 'route');
        so.depends('action', 'route-options');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Value, 'client_subnet', _('EDNS Client subnet'),
            _('Append a <code>edns0-subnet</code> OPT extra record with the specified IP prefix to every query by default.<br/>' +
                'If value is an IP address instead of prefix, <code>/32</code> or <code>/128</code> will be appended automatically.'));
        so.datatype = 'or(cidr, ipaddr)';
        so.depends('action', 'route');
        so.depends('action', 'route-options');
        so.modalonly = true;

        so = ss.taboption('field_other', form.ListValue, 'reject_method', _('Method'));
        so.value('default', _('Reply with REFUSED'));
        so.value('drop', _('Drop requests'));
        so.default = 'default';
        so.depends('action', 'reject');
        so.modalonly = true;

        so = ss.taboption('field_other', form.Flag, 'reject_no_drop', _('Don\'t drop requests'),
            _('<code>%s</code> will be temporarily overwritten to <code>%s</code> after 50 triggers in 30s if not enabled.').format(
                _('Method'), _('Drop requests')));
        so.depends('reject_method', 'default');
        so.modalonly = true;

        so = ss.taboption('field_other', form.ListValue, 'predefined_rcode', _('RCode'),
            _('The response code.'));
        so.value('NOERROR');
        so.value('FORMERR');
        so.value('SERVFAIL');
        so.value('NXDOMAIN');
        so.value('NOTIMP');
        so.value('REFUSED');
        so.default = 'NOERROR';
        so.depends('action', 'predefined');
        so.modalonly = true;

        so = ss.taboption('field_other', form.DynamicList, 'predefined_answer', _('Answer'),
            _('List of text DNS record to respond as answers.'));
        so.depends('action', 'predefined');
        so.modalonly = true;

        so = ss.taboption('field_other', form.DynamicList, 'predefined_ns', _('NS'),
            _('List of text DNS record to respond as name servers.'));
        so.depends('action', 'predefined');
        so.modalonly = true;

        so = ss.taboption('field_other', form.DynamicList, 'predefined_extra', _('Extra records'),
            _('List of text DNS record to respond as extra records.'));
        so.depends('action', 'predefined');
        so.modalonly = true;

        so = ss.taboption('field_host', form.DynamicList, 'domain', _('Domain name'),
            _('Match full domain.'));
        so.datatype = 'hostname';
        so.modalonly = true;

        so = ss.taboption('field_host', form.DynamicList, 'domain_suffix', _('Domain suffix'),
            _('Match domain suffix.'));
        so.modalonly = true;

        so = ss.taboption('field_host', form.DynamicList, 'domain_keyword', _('Domain keyword'),
            _('Match domain using keyword.'));
        so.modalonly = true;

        so = ss.taboption('field_host', form.DynamicList, 'domain_regex', _('Domain regex'),
            _('Match domain using regular expression.'));
        so.modalonly = true;

        so = ss.taboption('field_host', form.DynamicList, 'source_ip_cidr', _('Source IP CIDR'),
            _('Match source IP CIDR.'));
        so.datatype = 'or(cidr, ipaddr)';
        so.modalonly = true;

        so = ss.taboption('field_host', form.Flag, 'source_ip_is_private', _('Match private source IP'));
        so.modalonly = true;

        so = ss.taboption('field_host', form.DynamicList, 'ip_cidr', _('IP CIDR'),
            _('Match IP CIDR with query response. Current rule will be skipped if not match.'));
        so.datatype = 'or(cidr, ipaddr)';
        so.modalonly = true;

        so = ss.taboption('field_host', form.Flag, 'ip_is_private', _('Match private IP'),
            _('Match private IP with query response.'));
        so.modalonly = true;

        so = ss.taboption('field_port', form.DynamicList, 'source_port', _('Source port'),
            _('Match source port.'));
        so.datatype = 'port';
        so.modalonly = true;

        so = ss.taboption('field_port', form.DynamicList, 'source_port_range', _('Source port range'),
            _('Match source port range. Format as START:/:END/START:END.'));
        so.validate = fp.validatePortRange;
        so.modalonly = true;

        so = ss.taboption('field_port', form.DynamicList, 'port', _('Port'),
            _('Match port.'));
        so.datatype = 'port';
        so.modalonly = true;

        so = ss.taboption('field_port', form.DynamicList, 'port_range', _('Port range'),
            _('Match port range. Format as START:/:END/START:END.'));
        so.validate = fp.validatePortRange;
        so.modalonly = true;

        so = ss.taboption('fields_process', form.DynamicList, 'process_name', _('Process name'),
            _('Match process name.'));
        so.modalonly = true;

        so = ss.taboption('fields_process', form.DynamicList, 'process_path', _('Process path'),
            _('Match process path.'));
        so.modalonly = true;

        so = ss.taboption('fields_process', form.DynamicList, 'process_path_regex', _('Process path (regex)'),
            _('Match process path using regular expression.'));
        so.modalonly = true;
        /* DNS rules end */
        
        /* Rule Assets settings start */
        s.tab('assets', _('规则集设置'));
        // ⭐ 终极修复：把最后那个 'flowproxy' 换成 'assets'！
        o = s.taboption('assets', form.SectionValue, '_assets', form.NamedSection, 'assets', 'assets');
        ss = o.subsection;

        /* -- 基础配置区块 -- */
        so = ss.option(form.DummyValue, '_header_1', '');
        so.rawhtml = true;
        so.default = '<div style="padding: 8px 15px; margin-top: 10px; margin-bottom: 20px; background-color: #f8f9fa; border-left: 4px solid #17a2b8; border-radius: 4px; font-weight: bold; color: #333; font-size: 15px;">⚙️ 基础配置</div>';

        so = ss.option(form.Value, 'base_url', _('镜像源 URL'), '公有库下载源，推荐使用 jsDelivr 或国内加速源。');
        so.default = 'https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing';
        so.placeholder = 'https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing';

        so = ss.option(form.Value, 'private_repo', _('私有库 URL'), '用于下载自定义 SRS 的私有直链前缀（可选）。');
        so.placeholder = 'https://raw.githubusercontent.com/YourName/Repo/main';

        so = ss.option(form.Flag, 'auto_update', _('自动更新开关'), '开启后将按设定的时间自动在后台检查更新。');
        so.rmempty = false;
        // ⭐ 已经彻底删除了错误的 so.write，直接走系统默认保存链路

        so = ss.option(form.ListValue, 'update_time', _('每日更新时间'), '设定自动更新在每天的几点执行。');
        for (let i = 0; i < 24; i++) so.value(i, i + ':00');
        so.default = '4';
        so.depends('auto_update', '1');
        // ⭐ 已经彻底删除了错误的 so.write

        so = ss.option(form.DummyValue, '_tg_notice', '');
        so.rawhtml = true;
        so.default = '<div style="margin-top: 15px; padding: 10px; background-color: #e8f4f8; border-left: 4px solid #17a2b8; color: #333; font-size: 13px;">💡 <b>如需Telegram 自动化通知，请前往 <b>「服务状态」->「内核管理」</b> 页面下方，进行全局 TG 机器人配置。</div>';

        /* -- 手动入库区块 -- */
        so = ss.option(form.DummyValue, '_header_2', '');
        so.rawhtml = true;
        so.default = '<div style="padding: 8px 15px; margin-top: 30px; margin-bottom: 20px; background-color: #f8f9fa; border-left: 4px solid #007bff; border-radius: 4px; font-weight: bold; color: #333; font-size: 15px;">📥 批量入库引擎</div>';

        so = ss.option(form.DummyValue, '_manual_pull_ui', _('规则集名称'));
        so.description = '支持同时输入多个规则集名称，请用<b>逗号或换行</b>分隔。<br/>脚本会自动从配置的源批量拉取资产文件。';
        so.renderWidget = function(section_id, option_index, cfgvalue) {
            return E('div', { 'style': 'display:flex; align-items:flex-start;' }, [
                E('textarea', {
                    'id': 'manual_rule_name_input',
                    'class': 'cbi-input-textarea',
                    'placeholder': 'geosite-google\ngeoip-netflix\ngeosite-cn',
                    'style': 'flex: 1; max-width: 350px; min-height: 80px; padding: 8px;'
                }),
                E('button', {
                    'class': 'cbi-button cbi-button-apply',
                    'style': 'margin-left: 15px; margin-top: 5px;',
                    'click': function(ev) {
                        ev.preventDefault();
                        let val = document.getElementById('manual_rule_name_input').value.trim();
                        if (!val) { alert('请输入要下载的规则集名称！'); return; }

                        let clean_args = val.replace(/[\n,]/g, ' ').replace(/\s+/g, ' ');
                        // ⭐ 核心防线接管：彻底告别 shell，向 Job Observer 发送合法契约
                        observer.execute('update_assets', { action: 'download', target: clean_args }, '📥 正在执行批量入库任务...');
                    }
                }, '批量入库')
            ]);
        };

        /* -- 维护容灾区块 -- */
        so = ss.option(form.DummyValue, '_header_3', '');
        so.rawhtml = true;
        so.default = '<div style="padding: 8px 15px; margin-top: 30px; margin-bottom: 20px; background-color: #f8f9fa; border-left: 4px solid #dc3545; border-radius: 4px; font-weight: bold; color: #333; font-size: 15px;">🛠️ 维护与容灾</div>';

        so = ss.option(form.DummyValue, '_maintenance_ui', _('高级操作'));
        so.description = '<b>全量更新：</b>自动扫描当前 FlowProxy 正在使用的规则集并执行按需更新。<br/><b>安全回滚：</b>遇到更新后中断，一键恢复至上一个版本的稳定规则集。';
        so.renderWidget = function(section_id, option_index, cfgvalue) {
            return E('div', { 'style': 'display:flex; gap:15px;' }, [
                E('button', {
                    'class': 'cbi-button cbi-button-action',
                    'style': 'background-color: #28a745; color: #fff; border-color: #28a745; padding: 6px 15px;',
                    'click': function(ev) {
                        ev.preventDefault();
                        // ⭐ 核心防线接管：向 Job Observer 发送全量巡检契约
                        observer.execute('update_assets', { action: 'update', target: 'manual' }, '🔄 正在执行全量规则巡检...');
                    }
                }, '🔄 全量规则集更新'),
                E('button', {
                    'class': 'cbi-button cbi-button-remove',
                    'style': 'padding: 6px 15px;',
                    'click': function(ev) {
                        ev.preventDefault();
                        if(confirm('⚠️ 危险操作：\n\n确定要执行紧急安全回滚吗？\n这将覆盖当前所有的规则集，恢复到上一次的安全备份，并重启 FlowProxy 服务！')) {
                            // ⭐ 核心防线接管：触发灾难回滚任务
                            observer.execute('system_rollback', { action: 'restore', target: 'assets' }, '🛡️ 正在执行紧急安全回滚...');
                        }
                    }
                }, '🛡️ 紧急安全回滚')
            ]);
        };
        /* Rule Assets settings end */

        /* Rule set settings start */
        s.tab('ruleset', _('Rule Set'));
        o = s.taboption('ruleset', form.SectionValue, '_ruleset', form.GridSection, 'ruleset');
        o.depends('routing_mode', 'custom');

        ss = o.subsection;
        ss.addremove = true;
        ss.rowcolors = true;
        ss.sortable = true;
        ss.nodescriptions = true;
        ss.modaltitle = L.bind(fp.loadModalTitle, this, _('Rule set'), _('Add a rule set'), data[0]);
        ss.sectiontitle = L.bind(fp.loadDefaultLabel, this, data[0]);
        ss.renderSectionAdd = L.bind(fp.renderSectionAdd, this, ss);

        so = ss.option(form.Value, 'label', _('Label'));
        so.load = L.bind(fp.loadDefaultLabel, this, data[0]);
        so.validate = L.bind(fp.validateUniqueValue, this, data[0], 'ruleset', 'label');
        so.modalonly = true;

        so = ss.option(form.Flag, 'enabled', _('Enable'));
        so.default = so.enabled;
        so.rmempty = false;
        so.editable = true;

        so = ss.option(form.ListValue, 'type', _('Type'));
        so.value('local', _('Local'));
        so.value('remote', _('Remote'));
        so.default = 'remote';
        so.rmempty = false;

        so = ss.option(form.ListValue, 'format', _('Format'));
        so.value('binary', _('Binary file'));
        so.value('source', _('Source file'));
        so.default = 'binary';
        so.rmempty = false;

        so = ss.option(form.Value, 'path', _('Path'));
        so.datatype = 'file';
        so.placeholder = '/etc/flowproxy/ruleset/example.json';
        so.rmempty = false;
        so.depends('type', 'local');
        so.modalonly = true;

        so = ss.option(form.Value, 'url', _('Rule set URL'));
        so.validate = function(section_id, value) {
            if (section_id) {
                if (!value)
                    return _('Expecting: %s').format(_('non-empty value'));

                try {
                    let url = new URL(value);
                    if (!url.hostname)
                        return _('Expecting: %s').format(_('valid URL'));
                }
                catch(e) {
                    return _('Expecting: %s').format(_('valid URL'));
                }
            }

            return true;
        }
        so.rmempty = false;
        so.depends('type', 'remote');
        so.modalonly = true;

        so = ss.option(form.ListValue, 'outbound', _('Outbound'),
            _('Tag of the outbound to download rule set.'));
        so.load = function(section_id) {
            delete this.keylist;
            delete this.vallist;

            this.value('', _('Default'));
            this.value('direct-out', _('Direct'));
            uci.sections(data[0], 'routing_node', (res) => {
                if (res.enabled === '1')
                    this.value(res['.name'], res.label);
            });

            return this.super('load', section_id);
        }
        so.depends('type', 'remote');

        so = ss.option(form.Value, 'update_interval', _('Update interval'),
            _('Update interval of rule set.'));
        so.placeholder = '1d';
        so.depends('type', 'remote');
        /* Rule set settings end */

        /* ACL settings start */
        s.tab('control', _('Access Control'));

        o = s.taboption('control', form.SectionValue, '_control', form.NamedSection, 'control', 'flowproxy');
        ss = o.subsection;

        /* Interface control start */
        ss.tab('interface', _('Interface Control'));

        so = ss.taboption('interface', widgets.DeviceSelect, 'listen_interfaces', _('Listen interfaces'),
            _('Only process traffic from specific interfaces. Leave empty for all.'));
        so.multiple = true;
        so.noaliases = true;

        so = ss.taboption('interface', widgets.DeviceSelect, 'bind_interface', _('Bind interface'),
            _('Bind outbound traffic to specific interface. Leave empty to auto detect.'));
        so.multiple = false;
        so.noaliases = true;
        /* Interface control end */

        /* LAN IP policy start */
        ss.tab('lan_ip_policy', _('LAN IP Policy'));

        so = ss.taboption('lan_ip_policy', form.ListValue, 'lan_proxy_mode', _('Proxy filter mode'));
        so.value('disabled', _('Disable'));
        so.value('listed_only', _('Proxy listed only'));
        so.value('except_listed', _('Proxy all except listed'));
        so.default = 'disabled';
        so.rmempty = false;

        so = fwtool.addIPOption(ss, 'lan_ip_policy', 'lan_direct_ipv4_ips', _('Direct IPv4 IP-s'), null, 'ipv4', hosts, true);
        so.depends('lan_proxy_mode', 'except_listed');

        so = fwtool.addIPOption(ss, 'lan_ip_policy', 'lan_direct_ipv6_ips', _('Direct IPv6 IP-s'), null, 'ipv6', hosts, true);
        so.depends({'lan_proxy_mode': 'except_listed', 'flowproxy.config.ipv6_support': '1'});

        so = fwtool.addMACOption(ss, 'lan_ip_policy', 'lan_direct_mac_addrs', _('Direct MAC-s'), null, hosts);
        so.depends('lan_proxy_mode', 'except_listed');

        so = fwtool.addIPOption(ss, 'lan_ip_policy', 'lan_proxy_ipv4_ips', _('Proxy IPv4 IP-s'), null, 'ipv4', hosts, true);
        so.depends('lan_proxy_mode', 'listed_only');

        so = fwtool.addIPOption(ss, 'lan_ip_policy', 'lan_proxy_ipv6_ips', _('Proxy IPv6 IP-s'), null, 'ipv6', hosts, true);
        so.depends({'lan_proxy_mode': 'listed_only', 'flowproxy.config.ipv6_support': '1'});

        so = fwtool.addMACOption(ss, 'lan_ip_policy', 'lan_proxy_mac_addrs', _('Proxy MAC-s'), null, hosts);
        so.depends('lan_proxy_mode', 'listed_only');

        so = fwtool.addIPOption(ss, 'lan_ip_policy', 'lan_gaming_mode_ipv4_ips', _('Gaming mode IPv4 IP-s'), null, 'ipv4', hosts, true);

        so = fwtool.addIPOption(ss, 'lan_ip_policy', 'lan_gaming_mode_ipv6_ips', _('Gaming mode IPv6 IP-s'), null, 'ipv6', hosts, true);
        so.depends('flowproxy.config.ipv6_support', '1');

        so = fwtool.addMACOption(ss, 'lan_ip_policy', 'lan_gaming_mode_mac_addrs', _('Gaming mode MAC-s'), null, hosts);

        so = fwtool.addIPOption(ss, 'lan_ip_policy', 'lan_global_proxy_ipv4_ips', _('Global proxy IPv4 IP-s'), null, 'ipv4', hosts, true);
        so.depends({'flowproxy.config.routing_mode': 'custom', '!reverse': true});

        so = fwtool.addIPOption(ss, 'lan_ip_policy', 'lan_global_proxy_ipv6_ips', _('Global proxy IPv6 IP-s'), null, 'ipv6', hosts, true);
        so.depends({'flowproxy.config.routing_mode': /^((?!custom).)+$/, 'flowproxy.config.ipv6_support': '1'});

        so = fwtool.addMACOption(ss, 'lan_ip_policy', 'lan_global_proxy_mac_addrs', _('Global proxy MAC-s'), null, hosts);
        so.depends({'flowproxy.config.routing_mode': 'custom', '!reverse': true});
        /* LAN IP policy end */

        /* WAN IP policy start */
        ss.tab('wan_ip_policy', _('WAN IP Policy'));

        so = ss.taboption('wan_ip_policy', form.DynamicList, 'wan_proxy_ipv4_ips', _('Proxy IPv4 IP-s'));
        so.datatype = 'or(ip4addr, cidr4)';

        so = ss.taboption('wan_ip_policy', form.DynamicList, 'wan_proxy_ipv6_ips', _('Proxy IPv6 IP-s'));
        so.datatype = 'or(ip6addr, cidr6)';
        so.depends('flowproxy.config.ipv6_support', '1');

        so = ss.taboption('wan_ip_policy', form.DynamicList, 'wan_direct_ipv4_ips', _('Direct IPv4 IP-s'));
        so.datatype = 'or(ip4addr, cidr4)';

        so = ss.taboption('wan_ip_policy', form.DynamicList, 'wan_direct_ipv6_ips', _('Direct IPv6 IP-s'));
        so.datatype = 'or(ip6addr, cidr6)';
        so.depends('flowproxy.config.ipv6_support', '1');
        /* WAN IP policy end */

        /* Proxy domain list start */
        ss.tab('proxy_domain_list', _('Proxy Domain List'));
        so = ss.taboption('proxy_domain_list', form.TextValue, '_proxy_domain_list');
        so.rows = 10; so.monospace = true; so.datatype = 'hostname'; so.depends({'flowproxy.config.routing_mode': 'custom', '!reverse': true});
        
        // 接入 1.0 SDK 读写管线
        so.load = function() { 
            return fp.rpc_call('flowproxy.system', 'acllist_read', { type: 'proxy_list' })
                .then(data => data.content || '')
                .catch(() => ''); // 若文件读取越权或异常，SDK 会弹窗，此处 UI 优雅降级为空
        };
        
        so.write = function(_section_id, value) { 
            return fp.rpc_call('flowproxy.system', 'acllist_write', { type: 'proxy_list', content: value }); 
        };
        
        so.remove = function() {
            let routing_mode = this.section.formvalue('config', 'routing_mode');
            if (routing_mode !== 'custom') {
                return fp.rpc_call('flowproxy.system', 'acllist_write', { type: 'proxy_list', content: '' });
            }
            return true;
        };
        so.validate = function(section_id, value) {
            if (section_id && value)
                for (let i of value.split('\n'))
                    if (i && !stubValidator.apply('hostname', i)) return _('Expecting: %s').format(_('valid hostname'));
            return true;
        }
        /* Proxy domain list end */

        /* Direct domain list start */
        ss.tab('direct_domain_list', _('Direct Domain List'));
        so = ss.taboption('direct_domain_list', form.TextValue, '_direct_domain_list');
        so.rows = 10; so.monospace = true; so.datatype = 'hostname'; so.depends({'flowproxy.config.routing_mode': 'custom', '!reverse': true});
        
        // 接入 1.0 SDK 读写管线
        so.load = function() { 
            return fp.rpc_call('flowproxy.system', 'acllist_read', { type: 'direct_list' })
                .then(data => data.content || '')
                .catch(() => '');
        };
        
        so.write = function(_section_id, value) { 
            return fp.rpc_call('flowproxy.system', 'acllist_write', { type: 'direct_list', content: value }); 
        };
        
        so.remove = function() {
            let routing_mode = this.section.formvalue('config', 'routing_mode');
            if (routing_mode !== 'custom') {
                return fp.rpc_call('flowproxy.system', 'acllist_write', { type: 'direct_list', content: '' });
            }
            return true;
        };
        so.validate = function(section_id, value) {
            if (section_id && value)
                for (let i of value.split('\n'))
                    if (i && !stubValidator.apply('hostname', i)) return _('Expecting: %s').format(_('valid hostname'));
            return true;
        }
        /* Direct domain list end */
        /* ACL settings end */

        /* ========================================================= */
        /* Infra 架构设置区块 - 开始 */
        /* ========================================================= */
        s.tab('infra', _('底层架构 (Infra)'));
        
        // 绑定到 UCI 中的 config infra 'infra' 节
        o = s.taboption('infra', form.SectionValue, '_infra', form.NamedSection, 'infra', 'infra');
        ss = o.subsection;

        /* -- API 控制器设置 -- */
        so = ss.option(form.DummyValue, '_header_api', '');
        so.rawhtml = true;
        so.default = '<div style="padding: 8px 15px; margin-top: 10px; margin-bottom: 20px; background-color: #f8f9fa; border-left: 4px solid #17a2b8; border-radius: 4px; font-weight: bold; color: #333; font-size: 15px;">🔌 面板 API 控制器</div>';

        so = ss.option(form.Value, 'clash_api_port', _('API 监听端口'), _('Zashboard 面板与核心通信的 RESTful API 端口。默认 9090。<br/><b>注意：</b>若在此处修改，需同步在 Zashboard 面板的设置中更改连接端口。'));
        so.datatype = 'port';
        so.placeholder = '9090';
        so.rmempty = false;

        so = ss.option(form.Value, 'clash_api_host', _('API 监听地址'), _('默认 0.0.0.0 允许局域网内所有设备访问面板 API。'));
        so.datatype = 'ipaddr';
        so.placeholder = '0.0.0.0';
        so.rmempty = false;

        /* -- 时间同步设置 -- */
        so = ss.option(form.DummyValue, '_header_ntp', '');
        so.rawhtml = true;
        so.default = '<div style="padding: 8px 15px; margin-top: 30px; margin-bottom: 20px; background-color: #f8f9fa; border-left: 4px solid #ffc107; border-radius: 4px; font-weight: bold; color: #333; font-size: 15px;">⏱️ 时钟同步设置</div>';

        so = ss.option(form.Value, 'ntp_server', _('NTP 服务器'), _('独立的时间同步服务器地址。配置后，Sing-box 内核将接管自身的时间同步，防止因设备时间不准导致 TLS 握手失败。'));
        so.datatype = 'or(hostname, ipaddr)';
        so.placeholder = 'time.apple.com';

        /* -- 核心入站端口设置 -- */
        so = ss.option(form.DummyValue, '_header_ports', '');
        so.rawhtml = true;
        so.default = '<div style="padding: 8px 15px; margin-top: 30px; margin-bottom: 20px; background-color: #f8f9fa; border-left: 4px solid #6c757d; border-radius: 4px; font-weight: bold; color: #333; font-size: 15px;">⚙️ 底层入站端口 (Inbounds)</div>';

        so = ss.option(form.Value, 'mixed_port', _('Mixed 混合端口'), _('HTTP/Socks5 混合代理入站端口。'));
        so.datatype = 'port';
        so.placeholder = '5330';
        
        so = ss.option(form.Value, 'redirect_port', _('Redirect 端口'), _('TCP 透明代理重定向入站端口。'));
        so.datatype = 'port';
        so.placeholder = '5331';

        so = ss.option(form.Value, 'tproxy_port', _('TProxy 端口'), _('UDP 透明代理入站端口。'));
        so.datatype = 'port';
        so.placeholder = '5332';

        so = ss.option(form.Value, 'dns_port', _('DNS 劫持端口'), _('DNS 流量劫持入站端口。'));
        so.datatype = 'port';
        so.placeholder = '5333';

        /* -- TUN 网卡设置 -- */
        so = ss.option(form.DummyValue, '_header_tun', '');
        so.rawhtml = true;
        so.default = '<div style="padding: 8px 15px; margin-top: 30px; margin-bottom: 20px; background-color: #f8f9fa; border-left: 4px solid #28a745; border-radius: 4px; font-weight: bold; color: #333; font-size: 15px;">🖧 TUN 虚拟网卡设置</div>';

        so = ss.option(form.Value, 'tun_name', _('TUN 网卡名称'));
        so.placeholder = 'singtun0';

        so = ss.option(form.Value, 'tun_addr4', _('IPv4 地址'), _('TUN 接口的虚拟 IPv4 网段。'));
        so.datatype = 'cidr4';
        so.placeholder = '172.19.0.1/30';

        so = ss.option(form.Value, 'tun_addr6', _('IPv6 地址'), _('TUN 接口的虚拟 IPv6 网段。'));
        so.datatype = 'cidr6';
        so.placeholder = 'fdfe:dcba:9876::1/126';

        so = ss.option(form.Value, 'tun_mtu', _('TUN MTU'), _('最大传输单元。'));
        so.datatype = 'uinteger';
        so.placeholder = '9000';
        /* ========================================================= */
        /* Infra 架构设置区块 - 结束 */
        /* ========================================================= */
        
        /* ========================================================= */
        /* Zashboard 内嵌注入点 - 开始 (在 Access Control 之后) */
        /* ========================================================= */
        s.tab('zashboard', _('面板'));

        o = s.taboption('zashboard', form.DummyValue, '_dash');
        o.rawhtml = true;
        o.default = '<div style="margin: -10px -15px; padding-bottom: 20px;"><iframe src="' + window.location.protocol + '//' + window.location.hostname + '/zashboard/" style="width: 100%; height: 85vh; border: none; border-radius: 4px; background: transparent;"></iframe></div>';
        /* ========================================================= */
        /* Zashboard 内嵌注入点 - 结束 */
        /* ========================================================= */

        return m.render();
    }
});
