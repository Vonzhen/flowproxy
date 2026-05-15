# --- [ FlowProxy | OpenWrt Native Makefile | v1.2 ] ---
# [Category B] 职能：定义 OpenWrt 软件包元数据、依赖树与标准安装钩子

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-flowproxy
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

# [Category A] 定义包架构与核心源
PKG_MAINTAINER:=FlowProxy-Team
PKG_LICENSE:=GPL-3.0
PKG_ARCH:=all

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-flowproxy
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=FlowProxy - Modern sing-box Control Plane
  DEPENDS:=+ucode +ucode-mod-uci +ucode-mod-fs +ucode-mod-math +curl +ca-bundle +kmod-tun
endef

# [Category B] 前置安装干预：摧毁遗留物理资产，防止 opkg 覆写阻断
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

# [Category B] 在编译期调用宿主工具链转换 I18N 源文件
# [Category C] Note: 修复点 C - 强制输出目标后缀为 zh-cn 适配 LuCI i18n
define Build/Compile
	po2lmo ./po/zh_Hans/flowproxy.po $(PKG_BUILD_DIR)/flowproxy.zh-cn.lmo
endef

define Package/luci-app-flowproxy/install
	# 物理拷贝基础目录映射
	$(CP) ./root/* $(1)/
	
	$(INSTALL_DIR) $(1)/usr/share/flowproxy
	$(CP) ./usr/share/flowproxy/* $(1)/usr/share/flowproxy/

    # 🚨 架构修复：强行浇筑所有运行时需要的基础设施空目录（无视 Git 是否提交）
    $(INSTALL_DIR) $(1)/etc/flowproxy
	$(INSTALL_DIR) $(1)/etc/flowproxy/resources
	$(INSTALL_DIR) $(1)/etc/flowproxy/ruleset
	$(INSTALL_DIR) $(1)/etc/flowproxy/run
	
	# 容错拷贝：如果源码中确实存放了 china_ip.txt 等实体文件，则拷贝；如果没有，也不报错
	[ -d ./etc/flowproxy ] && $(CP) ./etc/flowproxy/* $(1)/etc/flowproxy/ 2>/dev/null || true
	
	# [Category B] 修复点 A & B - 映射 Ubus 守护进程依赖的原生 Ucode 插件目录与 ACL 规则
	$(INSTALL_DIR) $(1)/usr/share/rpcd/ucode
	$(CP) ./usr/share/rpcd/ucode/* $(1)/usr/share/rpcd/ucode/
	
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d
	$(CP) ./usr/share/rpcd/acl.d/* $(1)/usr/share/rpcd/acl.d/
	
	# LuCI 前端资源映射
	$(INSTALL_DIR) $(1)/www/luci-static/resources/flowproxy
	$(CP) ./htdocs/luci-static/resources/flowproxy/* $(1)/www/luci-static/resources/flowproxy/
	
	# 独立面板 (Zashboard) 映射
	$(INSTALL_DIR) $(1)/www/zashboard
	$(CP) ./www/zashboard/* $(1)/www/zashboard/
	
	# 映射编译生成的二进制语言包
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/flowproxy.zh-cn.lmo $(1)/usr/lib/lua/luci/i18n/
endef

# [Category B] 后置生命周期干预：处理权限提权与异步环境就绪
define Package/luci-app-flowproxy/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
    chmod 0755 /etc/init.d/flowproxy
    chmod 0755 /usr/share/flowproxy/runtime/worker.uc
    
    /etc/init.d/flowproxy enable
    # [Category C] Note: 解决生命周期延迟，确保环境即刻可用
    [ -f "/etc/uci-defaults/99_flowproxy" ] && sh "/etc/uci-defaults/99_flowproxy"
    
    # 历史软链清理与热重载通知
    rm -f /usr/libexec/rpcd/flowproxy
    
    # 🚨 架构级修复：在此处动态注入 Ucode 寻址软链！
    # 解决 Ucode 引擎底层强制去 /usr/share/ucode 寻址导致找不到 constants.uc 的崩溃问题
    mkdir -p /usr/share/ucode
    ln -sfn /usr/share/flowproxy /usr/share/ucode/flowproxy
    
    killall -HUP rpcd 2>/dev/null
fi
exit 0
endef

# [Category B] 卸载前置干预：安全剥离资源与物理软链
define Package/luci-app-flowproxy/prerm
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	# 停止服务并取消开机自启
	/etc/init.d/flowproxy stop 2>/dev/null
	/etc/init.d/flowproxy disable 2>/dev/null
	
	# 🚨 安全卸载：销毁我们在 postinst 中创建的 Ucode 引擎寻址软链
	rm -f /usr/share/ucode/flowproxy
fi
exit 0
endef

$(eval $(call BuildPackage,luci-app-flowproxy))
