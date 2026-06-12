# --- [ FlowProxy | OpenWrt Native Makefile | v1.3 ] ---
# Defines package metadata, dependencies, install layout, and lifecycle hooks.
include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-flowproxy
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_MAINTAINER:=FlowProxy-Team
PKG_LICENSE:=GPL-3.0
PKG_ARCH:=all

include $(INCLUDE_DIR)/package.mk

FLOWPROXY_DEPS:=+luci-base +rpcd +rpcd-mod-ucode +ucode +ucode-mod-uci +ucode-mod-fs +ucode-mod-math +curl +ca-bundle +sing-box +ip-full +nftables +kmod-tun +kmod-nft-tproxy +kmod-nft-nat +kmod-inet-diag

define Package/luci-app-flowproxy
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=FlowProxy - Modern sing-box Control Plane
  DEPENDS:=$(FLOWPROXY_DEPS)
endef

define Package/luci-app-flowproxy/conffiles
/etc/config/flowproxy
endef

define Package/luci-app-flowproxy/preinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
    fp_cleanup_runtime() {
        local mark
        local dns_dirty=0
        local pids
        local pid

        [ -f /etc/init.d/flowproxy ] && /etc/init.d/flowproxy stop 2>/dev/null || true
        ubus call service delete '{"name":"flowproxy","instance":"main"}' >/dev/null 2>&1 || true

        pids=$$(ps w 2>/dev/null | grep '[s]ing-box' | grep '/var/run/flowproxy/sing-box-run.json' | awk '{print $$1}')
        for pid in $$pids; do
            kill -TERM "$$pid" 2>/dev/null || true
        done

        nft delete table inet flowproxy 2>/dev/null || true
        for mark in $$(uci -q get flowproxy.infra.self_mark 2>/dev/null) $$(uci -q get flowproxy.infra.tproxy_mark 2>/dev/null) $$(uci -q get flowproxy.infra.tun_mark 2>/dev/null) 100 101 102; do
            [ -n "$$mark" ] || continue
            while ip rule del fwmark "$$mark" table "$$mark" 2>/dev/null; do :; done
            while ip -6 rule del fwmark "$$mark" table "$$mark" 2>/dev/null; do :; done
            ip route flush table "$$mark" 2>/dev/null || true
            ip -6 route flush table "$$mark" 2>/dev/null || true
        done

        for dev in $$(ls /sys/class/net 2>/dev/null | grep '^singtun'); do
            ip link set "$$dev" down 2>/dev/null || true
            ip tuntap del mode tun name "$$dev" 2>/dev/null || true
        done

        [ -e /tmp/dnsmasq.d/dnsmasq-flowproxy.d ] && dns_dirty=1
        [ -e /tmp/dnsmasq.d/dnsmasq-flowproxy.conf ] && dns_dirty=1
        [ -e /etc/dnsmasq.d/dnsmasq-flowproxy.d ] && dns_dirty=1
        [ -e /etc/dnsmasq.d/dnsmasq-flowproxy.conf ] && dns_dirty=1
        rm -rf /tmp/dnsmasq.d/dnsmasq-flowproxy.d 2>/dev/null || true
        rm -f /tmp/dnsmasq.d/dnsmasq-flowproxy.conf 2>/dev/null || true
        rm -rf /etc/dnsmasq.d/dnsmasq-flowproxy.d 2>/dev/null || true
        rm -f /etc/dnsmasq.d/dnsmasq-flowproxy.conf 2>/dev/null || true
        uci -q del_list "dhcp.@dnsmasq[0].confdir=/tmp/dnsmasq.d/dnsmasq-flowproxy.d" 2>/dev/null && dns_dirty=1
        uci -q del_list "dhcp.@dnsmasq[0].confdir=/tmp/dnsmasq.d/dnsmasq-flowproxy.conf" 2>/dev/null && dns_dirty=1
        uci -q del_list "dhcp.@dnsmasq[0].confdir=/etc/dnsmasq.d/dnsmasq-flowproxy.d" 2>/dev/null && dns_dirty=1
        uci -q del_list "dhcp.@dnsmasq[0].confdir=/etc/dnsmasq.d/dnsmasq-flowproxy.conf" 2>/dev/null && dns_dirty=1
        [ "$$dns_dirty" = "1" ] && uci commit dhcp 2>/dev/null || true
        [ "$$dns_dirty" = "1" ] && /etc/init.d/dnsmasq restart >/dev/null 2>&1 || true

        rm -rf /var/run/flowproxy 2>/dev/null || true
        rm -f /var/run/flowproxy.pid /tmp/flowproxy.fail_count 2>/dev/null || true
        rm -f /usr/share/ucode/flowproxy 2>/dev/null || true
        rm -f /tmp/luci-indexcache 2>/dev/null || true
        rm -rf /tmp/luci-modulecache/ 2>/dev/null || true
    }

    fp_cleanup_runtime
    rm -rf /www/zashboard 2>/dev/null
fi
exit 0
endef

define Build/Compile
	po2lmo ./po/zh_Hans/flowproxy.po $(PKG_BUILD_DIR)/flowproxy.zh-cn.lmo
endef

define Package/luci-app-flowproxy/install
	$(CP) ./root/* $(1)/

	$(INSTALL_DIR) $(1)/usr/share/flowproxy
	$(CP) ./usr/share/flowproxy/* $(1)/usr/share/flowproxy/

	$(INSTALL_DIR) $(1)/etc/flowproxy
	$(INSTALL_DIR) $(1)/etc/flowproxy/resources
	$(INSTALL_DIR) $(1)/etc/flowproxy/ruleset
	$(INSTALL_DIR) $(1)/etc/flowproxy/run
	[ -d ./etc/flowproxy ] && $(CP) ./etc/flowproxy/* $(1)/etc/flowproxy/ 2>/dev/null || true

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./etc/init.d/flowproxy $(1)/etc/init.d/flowproxy
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./etc/config/flowproxy $(1)/etc/config/flowproxy

	$(INSTALL_DIR) $(1)/usr/share/rpcd/ucode
	$(CP) ./usr/share/rpcd/ucode/* $(1)/usr/share/rpcd/ucode/

	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(CP) ./usr/share/rpcd/acl.d/* $(1)/usr/share/rpcd/acl.d/

	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d
	$(CP) ./usr/share/luci/menu.d/* $(1)/usr/share/luci/menu.d/

	$(INSTALL_DIR) $(1)/www/luci-static/resources
	$(CP) ./htdocs/luci-static/resources/* $(1)/www/luci-static/resources/

	$(INSTALL_DIR) $(1)/www/zashboard
	$(CP) ./www/zashboard/* $(1)/www/zashboard/

	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/flowproxy.zh-cn.lmo $(1)/usr/lib/lua/luci/i18n/
endef

define Package/luci-app-flowproxy/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
    fp_log() {
        logger -t flowproxy-install "$$*" 2>/dev/null || echo "flowproxy-install: $$*"
    }

    fp_pkg_installed() {
        opkg status "$$1" 2>/dev/null | grep -q "Status: install ok installed"
    }

    fp_install_missing_deps() {
        command -v opkg >/dev/null 2>&1 || return 0

        local missing=""
        local pkg
        for pkg in luci-base rpcd rpcd-mod-ucode ucode ucode-mod-uci ucode-mod-fs ucode-mod-math curl ca-bundle sing-box ip-full nftables kmod-tun kmod-nft-tproxy kmod-nft-nat kmod-inet-diag; do
            fp_pkg_installed "$$pkg" || missing="$$missing $$pkg"
        done

        [ -n "$$missing" ] || return 0

        fp_log "missing dependencies:$$missing"
        opkg update >/tmp/flowproxy-opkg-update.log 2>&1 || {
            fp_log "opkg update failed; leaving dependency resolution to the administrator"
            return 0
        }

        opkg install $$missing >/tmp/flowproxy-opkg-install.log 2>&1 || {
            fp_log "opkg install failed for:$$missing"
            return 0
        }

        fp_log "installed missing dependencies:$$missing"
        return 0
    }

    fp_install_missing_deps

    if [ -f /etc/init.d/flowproxy ]; then
        chmod 0755 /etc/init.d/flowproxy
        /etc/init.d/flowproxy enable
    fi
    chmod 0755 /usr/share/flowproxy/runtime/worker.uc 2>/dev/null

    [ -f "/etc/uci-defaults/99_flowproxy" ] && sh "/etc/uci-defaults/99_flowproxy"

    rm -f /usr/libexec/rpcd/flowproxy
    mkdir -p /usr/share/ucode
    ln -sfn /usr/share/flowproxy /usr/share/ucode/flowproxy

    rm -f /tmp/luci-indexcache
    rm -rf /tmp/luci-modulecache/
    killall -HUP rpcd 2>/dev/null

    for bin in ucode sing-box nft ip curl; do
        command -v "$$bin" >/dev/null 2>&1 || fp_log "environment check failed: missing binary $$bin"
    done
    [ -L /usr/share/ucode/flowproxy ] || fp_log "environment check failed: /usr/share/ucode/flowproxy symlink missing"
    mkdir -p /var/run/flowproxy/logs /var/run/flowproxy/jobs 2>/dev/null
    [ -w /var/run/flowproxy/logs ] || fp_log "environment check failed: log dir not writable"
    [ -w /var/run/flowproxy/jobs ] || fp_log "environment check failed: job dir not writable"
    nft list table inet flowproxy >/dev/null 2>&1 && fp_log "environment check warning: stale nft table inet flowproxy still exists"
    [ -e /tmp/dnsmasq.d/dnsmasq-flowproxy.d ] && fp_log "environment check warning: stale dnsmasq-flowproxy.d still exists"
    [ -e /tmp/dnsmasq.d/dnsmasq-flowproxy.conf ] && fp_log "environment check warning: stale dnsmasq-flowproxy.conf still exists"
    [ -e /etc/dnsmasq.d/dnsmasq-flowproxy.d ] && fp_log "environment check warning: stale persistent dnsmasq-flowproxy.d still exists"
    [ -e /etc/dnsmasq.d/dnsmasq-flowproxy.conf ] && fp_log "environment check warning: stale persistent dnsmasq-flowproxy.conf still exists"
fi
exit 0
endef

define Package/luci-app-flowproxy/prerm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
    fp_cleanup_runtime() {
        local mark
        local dns_dirty=0
        local pids
        local pid

        ubus call service delete '{"name":"flowproxy","instance":"main"}' >/dev/null 2>&1 || true

        pids=$$(ps w 2>/dev/null | grep '[s]ing-box' | grep '/var/run/flowproxy/sing-box-run.json' | awk '{print $$1}')
        for pid in $$pids; do
            kill -TERM "$$pid" 2>/dev/null || true
        done

        nft delete table inet flowproxy 2>/dev/null || true
        for mark in $$(uci -q get flowproxy.infra.self_mark 2>/dev/null) $$(uci -q get flowproxy.infra.tproxy_mark 2>/dev/null) $$(uci -q get flowproxy.infra.tun_mark 2>/dev/null) 100 101 102; do
            [ -n "$$mark" ] || continue
            while ip rule del fwmark "$$mark" table "$$mark" 2>/dev/null; do :; done
            while ip -6 rule del fwmark "$$mark" table "$$mark" 2>/dev/null; do :; done
            ip route flush table "$$mark" 2>/dev/null || true
            ip -6 route flush table "$$mark" 2>/dev/null || true
        done

        for dev in $$(ls /sys/class/net 2>/dev/null | grep '^singtun'); do
            ip link set "$$dev" down 2>/dev/null || true
            ip tuntap del mode tun name "$$dev" 2>/dev/null || true
        done

        [ -e /tmp/dnsmasq.d/dnsmasq-flowproxy.d ] && dns_dirty=1
        [ -e /tmp/dnsmasq.d/dnsmasq-flowproxy.conf ] && dns_dirty=1
        [ -e /etc/dnsmasq.d/dnsmasq-flowproxy.d ] && dns_dirty=1
        [ -e /etc/dnsmasq.d/dnsmasq-flowproxy.conf ] && dns_dirty=1
        rm -rf /tmp/dnsmasq.d/dnsmasq-flowproxy.d 2>/dev/null || true
        rm -f /tmp/dnsmasq.d/dnsmasq-flowproxy.conf 2>/dev/null || true
        rm -rf /etc/dnsmasq.d/dnsmasq-flowproxy.d 2>/dev/null || true
        rm -f /etc/dnsmasq.d/dnsmasq-flowproxy.conf 2>/dev/null || true
        uci -q del_list "dhcp.@dnsmasq[0].confdir=/tmp/dnsmasq.d/dnsmasq-flowproxy.d" 2>/dev/null && dns_dirty=1
        uci -q del_list "dhcp.@dnsmasq[0].confdir=/tmp/dnsmasq.d/dnsmasq-flowproxy.conf" 2>/dev/null && dns_dirty=1
        uci -q del_list "dhcp.@dnsmasq[0].confdir=/etc/dnsmasq.d/dnsmasq-flowproxy.d" 2>/dev/null && dns_dirty=1
        uci -q del_list "dhcp.@dnsmasq[0].confdir=/etc/dnsmasq.d/dnsmasq-flowproxy.conf" 2>/dev/null && dns_dirty=1
        [ "$$dns_dirty" = "1" ] && uci commit dhcp 2>/dev/null || true
        [ "$$dns_dirty" = "1" ] && /etc/init.d/dnsmasq restart >/dev/null 2>&1 || true

        touch /etc/crontabs/root 2>/dev/null || true
        sed -i '/# FlowProxy-Cron/d' /etc/crontabs/root 2>/dev/null || true
        sed -i '/# FlowProxy-Watchdog/d' /etc/crontabs/root 2>/dev/null || true
        /etc/init.d/cron restart >/dev/null 2>&1 || true

        rm -rf /var/run/flowproxy 2>/dev/null || true
        rm -f /var/run/flowproxy.pid /tmp/flowproxy.fail_count 2>/dev/null || true
        rm -f /tmp/luci-indexcache 2>/dev/null || true
        rm -rf /tmp/luci-modulecache/ 2>/dev/null || true
    }

    if [ -f /etc/init.d/flowproxy ]; then
        /etc/init.d/flowproxy stop 2>/dev/null
        /etc/init.d/flowproxy disable 2>/dev/null
    fi
    fp_cleanup_runtime
    rm -f /usr/share/ucode/flowproxy
fi
exit 0
endef

$(eval $(call BuildPackage,luci-app-flowproxy))
