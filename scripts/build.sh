#!/bin/bash
# --- [ FlowProxy | Standalone IPK Builder | v1.2 ] ---
# [Category B] 职能：在非 SDK 环境下模拟 RootFS 结构并执行物理组装，生成合规的 .ipk 文件。

set -e

# [Category A] 环境元数据配置
PKG_NAME="luci-app-flowproxy"
PKG_VERSION="1.0.0"
PKG_RELEASE="1"
PKG_ARCH="all"
PKG_MAINTAINER="FlowProxy-Team"

BASE_DIR=$(pwd)
BUILD_DIR="${BASE_DIR}/build_tmp"
IPKG_DIR="${BUILD_DIR}/ipkg"

# 1. 初始化隔离沙箱
# [Category C] Note: 每次构建前必须清理历史残留，防止脏数据污染
rm -rf "$BUILD_DIR" && mkdir -p "$IPKG_DIR/CONTROL"

# 2. 虚拟文件系统 (VFS) 映射
echo "[INFO] Mapping Virtual File System..."

# 核心后端逻辑 (Ucode Modules)
mkdir -p "$IPKG_DIR/usr/share/flowproxy"
cp -r "${BASE_DIR}/usr/share/flowproxy/"* "$IPKG_DIR/usr/share/flowproxy/"

# 生命周期与配置骨架
mkdir -p "$IPKG_DIR/etc/config"
cp "${BASE_DIR}/etc/config/flowproxy" "$IPKG_DIR/etc/config/"
mkdir -p "$IPKG_DIR/etc/init.d"
cp "${BASE_DIR}/etc/init.d/flowproxy" "$IPKG_DIR/etc/init.d/"
mkdir -p "$IPKG_DIR/etc/uci-defaults"
cp "${BASE_DIR}/root/etc/uci-defaults/99_flowproxy" "$IPKG_DIR/etc/uci-defaults/"

# [Category B] 修复点 A & B：RPCD 网关入口点回归 OpenWrt 原生标准目录，挂载 ubus 上下文与 ACL
mkdir -p "$IPKG_DIR/usr/share/rpcd/ucode"
cp "${BASE_DIR}/usr/share/rpcd/ucode/flowproxy.uc" "$IPKG_DIR/usr/share/rpcd/ucode/"
mkdir -p "$IPKG_DIR/usr/share/rpcd/acl.d"
cp "${BASE_DIR}/usr/share/rpcd/acl.d/"*.json "$IPKG_DIR/usr/share/rpcd/acl.d/"

# LuCI 原生菜单与静态资产
mkdir -p "$IPKG_DIR/usr/share/luci/menu.d"
cp "${BASE_DIR}/usr/share/luci/menu.d/"*.json "$IPKG_DIR/usr/share/luci/menu.d/"
mkdir -p "$IPKG_DIR/www/luci-static/resources"
cp -r "${BASE_DIR}/htdocs/luci-static/resources/"* "$IPKG_DIR/www/luci-static/resources/"

# 独立面板 (Zashboard) 映射
# [Category C] Warning: 确保仓库中已包含构建完成的 dist 产物
mkdir -p "$IPKG_DIR/www/zashboard"
if [ -d "${BASE_DIR}/www/zashboard" ]; then
    cp -rP "${BASE_DIR}/www/zashboard/"* "$IPKG_DIR/www/zashboard/"
else
    echo "[WARN] /www/zashboard directory not found, skipping."
fi

# 3. 语言包编译 (po -> lmo)
# [Category B] 修复点 C：更正输出后缀为 zh-cn，适配 LuCI i18n 底层加载规则
echo "[INFO] Compiling I18N packages..."
mkdir -p "$IPKG_DIR/usr/lib/lua/luci/i18n"
if command -v po2lmo > /dev/null; then
    po2lmo "${BASE_DIR}/po/zh_Hans/flowproxy.po" "$IPKG_DIR/usr/lib/lua/luci/i18n/flowproxy.zh-cn.lmo"
else
    echo "[FATAL] po2lmo tool is missing. CI environment must pre-install it."
    exit 1
fi

# 4. 生成控制层元数据 (Control Plane Metadata)
echo "[INFO] Generating CONTROL files..."

cat <<EOF > "$IPKG_DIR/CONTROL/control"
Package: $PKG_NAME
Version: $PKG_VERSION-$PKG_RELEASE
Depends: ucode, ucode-mod-uci, ucode-mod-fs, ucode-mod-math, curl, ca-bundle, kmod-tun
Section: luci
Architecture: $PKG_ARCH
Maintainer: $PKG_MAINTAINER
Description: FlowProxy - Modern sing-box Control Plane
EOF

# 声明 UCI 保护免遭覆盖
echo "/etc/config/flowproxy" > "$IPKG_DIR/CONTROL/conffiles"

# [Category B] 注入 postinst 脚本：处理环境提权与生命周期激活
cat <<'EOF' > "$IPKG_DIR/CONTROL/postinst"
#!/bin/sh
if [ -z "${IPKG_INSTROOT}" ]; then
    # 强制核心脚本 0755 权限
    chmod 0755 /etc/init.d/flowproxy 2>/dev/null
    chmod 0755 /usr/share/flowproxy/runtime/worker.uc 2>/dev/null
    
    # 注册系统服务并立即执行环境初始化
    /etc/init.d/flowproxy enable
    [ -f "/etc/uci-defaults/99_flowproxy" ] && sh "/etc/uci-defaults/99_flowproxy"
    
    # [Category C] Note: 历史遗留软链的容错性清理
    rm -f /usr/libexec/rpcd/flowproxy
    
    # 清除内存侧残留缓存并通知守护进程热重载
    rm -f /tmp/luci-indexcache
    rm -rf /tmp/luci-modulecache/
    killall -HUP rpcd 2>/dev/null
fi
exit 0
EOF
chmod 0755 "$IPKG_DIR/CONTROL/postinst"

# [Category B] 注入 prerm 脚本：安全剥离资源
cat <<'EOF' > "$IPKG_DIR/CONTROL/prerm"
#!/bin/sh
if [ -z "${IPKG_INSTROOT}" ]; then
    /etc/init.d/flowproxy stop 2>/dev/null
    /etc/init.d/flowproxy disable 2>/dev/null
fi
exit 0
EOF
chmod 0755 "$IPKG_DIR/CONTROL/prerm"

# 5. 调用打包器输出
# [Category C] Note: 使用保守的纯位置参数，规避非标准环境 getopt 解析位移异常
echo "[INFO] Executing ipkg-build..."
ipkg-build "$IPKG_DIR" "$BASE_DIR"

echo "[SUCCESS] Build complete."
