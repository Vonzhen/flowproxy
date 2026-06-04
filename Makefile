# --- [ FlowProxy | OpenWrt Native Makefile | v1.2 ] ---
# [Category B] 鑱岃兘锛氬畾涔?OpenWrt 杞欢鍖呭厓鏁版嵁銆佷緷璧栨爲涓庢爣鍑嗗畨瑁呴挬瀛?
include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-flowproxy
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

# [Category A] 瀹氫箟鍖呮灦鏋勪笌鏍稿績婧?PKG_MAINTAINER:=FlowProxy-Team
PKG_LICENSE:=GPL-3.0
PKG_ARCH:=all

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-flowproxy
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=FlowProxy - Modern sing-box Control Plane
  DEPENDS:=+luci-base +rpcd +rpcd-mod-ucode +ucode +ucode-mod-uci +ucode-mod-fs +ucode-mod-math +curl +ca-bundle +sing-box +ip-full +nftables +kmod-tun +kmod-nft-tproxy +kmod-nft-nat +kmod-inet-diag +coreutils-timeout
endef

# [Category B] 鍓嶇疆瀹夎骞查锛氭懅姣侀仐鐣欑墿鐞嗚祫浜э紝闃叉 opkg 瑕嗗啓闃绘柇
define Package/luci-app-flowproxy/preinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
    rm -rf /www/zashboard 2>/dev/null
fi
exit 0
endef

define Package/luci-app-flowproxy/conffiles
/etc/config/flowproxy
endef

# [Category B] 鍦ㄧ紪璇戞湡璋冪敤瀹夸富宸ュ叿閾捐浆鎹?I18N 婧愭枃浠?# [Category C] Note: 淇鐐?C - 寮哄埗杈撳嚭鐩爣鍚庣紑涓?zh-cn 閫傞厤 LuCI i18n
define Build/Compile
	po2lmo ./po/zh_Hans/flowproxy.po $(PKG_BUILD_DIR)/flowproxy.zh-cn.lmo
endef

define Package/luci-app-flowproxy/install
	# 鐗╃悊鎷疯礉鍩虹鐩綍鏄犲皠
	$(CP) ./root/* $(1)/
	
	$(INSTALL_DIR) $(1)/usr/share/flowproxy
	$(CP) ./usr/share/flowproxy/* $(1)/usr/share/flowproxy/

    # 馃毃 鏋舵瀯淇锛氬己琛屾祰绛戞墍鏈夎繍琛屾椂闇€瑕佺殑鍩虹璁炬柦绌虹洰褰曪紙鏃犺 Git 鏄惁鎻愪氦锛?    $(INSTALL_DIR) $(1)/etc/flowproxy
	$(INSTALL_DIR) $(1)/etc/flowproxy/resources
	$(INSTALL_DIR) $(1)/etc/flowproxy/ruleset
	$(INSTALL_DIR) $(1)/etc/flowproxy/run
	
	# 瀹归敊鎷疯礉锛氬鏋滄簮鐮佷腑纭疄瀛樻斁浜?china_ip.txt 绛夊疄浣撴枃浠讹紝鍒欐嫹璐濓紱濡傛灉娌℃湁锛屼篃涓嶆姤閿?	[ -d ./etc/flowproxy ] && $(CP) ./etc/flowproxy/* $(1)/etc/flowproxy/ 2>/dev/null || true

	# SSOT锛氱敓鍛藉懆鏈熶笌 UCI 鐪熺浉婧愶紙涓?scripts/build.sh 瀵归綈锛?	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./etc/init.d/flowproxy $(1)/etc/init.d/flowproxy
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./etc/config/flowproxy $(1)/etc/config/flowproxy
	
	# [Category B] 淇鐐?A & B - 鏄犲皠 Ubus 瀹堟姢杩涚▼渚濊禆鐨勫師鐢?Ucode 鎻掍欢鐩綍涓?ACL 瑙勫垯
	$(INSTALL_DIR) $(1)/usr/share/rpcd/ucode
	$(CP) ./usr/share/rpcd/ucode/* $(1)/usr/share/rpcd/ucode/
	
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(CP) ./usr/share/rpcd/acl.d/* $(1)/usr/share/rpcd/acl.d/
	
	# LuCI 鍓嶇璧勬簮鏄犲皠
	$(INSTALL_DIR) $(1)/www/luci-static/resources/flowproxy
	$(CP) ./htdocs/luci-static/resources/flowproxy/* $(1)/www/luci-static/resources/flowproxy/
	
	# 鐙珛闈㈡澘 (Zashboard) 鏄犲皠
	$(INSTALL_DIR) $(1)/www/zashboard
	$(CP) ./www/zashboard/* $(1)/www/zashboard/
	
	# 鏄犲皠缂栬瘧鐢熸垚鐨勪簩杩涘埗璇█鍖?	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/flowproxy.zh-cn.lmo $(1)/usr/lib/lua/luci/i18n/
endef

# [Category B] 鍚庣疆鐢熷懡鍛ㄦ湡骞查锛氬鐞嗘潈闄愭彁鏉冧笌寮傛鐜灏辩华
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
        for pkg in luci-base rpcd rpcd-mod-ucode ucode ucode-mod-uci ucode-mod-fs ucode-mod-math curl ca-bundle sing-box ip-full nftables kmod-tun kmod-nft-tproxy kmod-nft-nat kmod-inet-diag coreutils-timeout; do
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
    chmod 0755 /usr/share/flowproxy/runtime/worker.uc
    
    # Run uci-defaults after install
    [ -f "/etc/uci-defaults/99_flowproxy" ] && sh "/etc/uci-defaults/99_flowproxy"
    
    # 鍘嗗彶杞摼娓呯悊涓庣儹閲嶈浇閫氱煡
    rm -f /usr/libexec/rpcd/flowproxy
    
    # Ensure ucode search path bridge
    mkdir -p /usr/share/ucode
    ln -sfn /usr/share/flowproxy /usr/share/ucode/flowproxy
    
    killall -HUP rpcd 2>/dev/null
fi
exit 0
endef

# [Category B] 鍗歌浇鍓嶇疆骞查锛氬畨鍏ㄥ墺绂昏祫婧愪笌鐗╃悊杞摼
define Package/luci-app-flowproxy/prerm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	# 鍋滄鏈嶅姟骞跺彇娑堝紑鏈鸿嚜鍚?	if [ -f /etc/init.d/flowproxy ]; then
		/etc/init.d/flowproxy stop 2>/dev/null
		/etc/init.d/flowproxy disable 2>/dev/null
	fi
	
	# 馃毃 瀹夊叏鍗歌浇锛氶攢姣佹垜浠湪 postinst 涓垱寤虹殑 Ucode 寮曟搸瀵诲潃杞摼
	rm -f /usr/share/ucode/flowproxy
fi
exit 0
endef

$(eval $(call BuildPackage,luci-app-flowproxy))
