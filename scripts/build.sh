#!/bin/bash
# --- [ FlowProxy | Standalone IPK Builder | v1.3 ] ---
# Builds a LuCI IPK without requiring a full OpenWrt SDK tree.
set -e

PKG_NAME="luci-app-flowproxy"
PKG_VERSION="1.0.0"
PKG_RELEASE="1"
PKG_ARCH="all"
PKG_MAINTAINER="FlowProxy-Team"
PKG_DEPENDS="luci-base, rpcd, rpcd-mod-ucode, ucode, ucode-mod-uci, ucode-mod-fs, ucode-mod-math, curl, ca-bundle, sing-box, ip-full, nftables, kmod-tun, kmod-nft-tproxy, kmod-nft-nat, kmod-inet-diag, coreutils-timeout"

BASE_DIR=$(pwd)
BUILD_DIR="${BASE_DIR}/build_tmp"
IPKG_DIR="${BUILD_DIR}/ipkg"

echo "[INFO] Preparing clean build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$IPKG_DIR/CONTROL"

echo "[INFO] Mapping virtual root filesystem..."

mkdir -p "$IPKG_DIR/usr/share/flowproxy"
cp -r "${BASE_DIR}/usr/share/flowproxy/"* "$IPKG_DIR/usr/share/flowproxy/"

echo "[INFO] Provisioning FlowProxy runtime directories..."
mkdir -p "$IPKG_DIR/etc/flowproxy/resources"
mkdir -p "$IPKG_DIR/etc/flowproxy/ruleset"
mkdir -p "$IPKG_DIR/etc/flowproxy/run"

if [ -d "${BASE_DIR}/etc/flowproxy" ] && [ "$(ls -A "${BASE_DIR}/etc/flowproxy" 2>/dev/null)" ]; then
    cp -r "${BASE_DIR}/etc/flowproxy/"* "$IPKG_DIR/etc/flowproxy/"
else
    echo "[INFO] Source etc/flowproxy is empty or missing. Clean infrastructure provisioned."
fi

mkdir -p "$IPKG_DIR/etc/config"
cp "${BASE_DIR}/etc/config/flowproxy" "$IPKG_DIR/etc/config/"

mkdir -p "$IPKG_DIR/etc/init.d"
cp "${BASE_DIR}/etc/init.d/flowproxy" "$IPKG_DIR/etc/init.d/"

mkdir -p "$IPKG_DIR/etc/uci-defaults"
cp "${BASE_DIR}/root/etc/uci-defaults/99_flowproxy" "$IPKG_DIR/etc/uci-defaults/"

mkdir -p "$IPKG_DIR/usr/share/rpcd/ucode"
cp "${BASE_DIR}/usr/share/rpcd/ucode/flowproxy.uc" "$IPKG_DIR/usr/share/rpcd/ucode/"

mkdir -p "$IPKG_DIR/usr/share/rpcd/acl.d"
cp "${BASE_DIR}/usr/share/rpcd/acl.d/"*.json "$IPKG_DIR/usr/share/rpcd/acl.d/"

mkdir -p "$IPKG_DIR/usr/share/luci/menu.d"
cp "${BASE_DIR}/usr/share/luci/menu.d/"*.json "$IPKG_DIR/usr/share/luci/menu.d/"

mkdir -p "$IPKG_DIR/www/luci-static/resources"
cp -r "${BASE_DIR}/htdocs/luci-static/resources/"* "$IPKG_DIR/www/luci-static/resources/"

mkdir -p "$IPKG_DIR/www/zashboard"
if [ -d "${BASE_DIR}/www/zashboard" ] && [ "$(ls -A "${BASE_DIR}/www/zashboard" 2>/dev/null)" ]; then
    cp -rP "${BASE_DIR}/www/zashboard/"* "$IPKG_DIR/www/zashboard/"
else
    echo "[WARN] www/zashboard is empty or missing, skipping."
fi

echo "[INFO] Compiling i18n catalog..."
mkdir -p "$IPKG_DIR/usr/lib/lua/luci/i18n"
if command -v po2lmo >/dev/null 2>&1; then
    po2lmo "${BASE_DIR}/po/zh_Hans/flowproxy.po" "$IPKG_DIR/usr/lib/lua/luci/i18n/flowproxy.zh-cn.lmo"
else
    echo "[FATAL] po2lmo tool is missing. CI environment must pre-install it."
    exit 1
fi

echo "[INFO] Generating CONTROL files..."

cat <<'EOF' > "$IPKG_DIR/CONTROL/preinst"
#!/bin/sh
if [ -z "${IPKG_INSTROOT}" ]; then
    rm -rf /www/zashboard 2>/dev/null
fi
exit 0
EOF
chmod 0755 "$IPKG_DIR/CONTROL/preinst"

cat <<EOF > "$IPKG_DIR/CONTROL/control"
Package: $PKG_NAME
Version: $PKG_VERSION-$PKG_RELEASE
Depends: $PKG_DEPENDS
Section: luci
Architecture: $PKG_ARCH
Maintainer: $PKG_MAINTAINER
Description: FlowProxy - Modern sing-box Control Plane
EOF

echo "/etc/config/flowproxy" > "$IPKG_DIR/CONTROL/conffiles"

cat <<'EOF' > "$IPKG_DIR/CONTROL/postinst"
#!/bin/sh
if [ -z "${IPKG_INSTROOT}" ]; then
    fp_log() {
        logger -t flowproxy-install "$*" 2>/dev/null || echo "flowproxy-install: $*"
    }

    fp_pkg_installed() {
        opkg status "$1" 2>/dev/null | grep -q "Status: install ok installed"
    }

    fp_install_missing_deps() {
        command -v opkg >/dev/null 2>&1 || return 0

        local missing=""
        local pkg
        for pkg in luci-base rpcd rpcd-mod-ucode ucode ucode-mod-uci ucode-mod-fs ucode-mod-math curl ca-bundle sing-box ip-full nftables kmod-tun kmod-nft-tproxy kmod-nft-nat kmod-inet-diag coreutils-timeout; do
            fp_pkg_installed "$pkg" || missing="$missing $pkg"
        done

        [ -n "$missing" ] || return 0

        fp_log "missing dependencies:$missing"
        opkg update >/tmp/flowproxy-opkg-update.log 2>&1 || {
            fp_log "opkg update failed; leaving dependency resolution to the administrator"
            return 0
        }

        opkg install $missing >/tmp/flowproxy-opkg-install.log 2>&1 || {
            fp_log "opkg install failed for:$missing"
            return 0
        }

        fp_log "installed missing dependencies:$missing"
        return 0
    }

    fp_install_missing_deps

    chmod 0755 /etc/init.d/flowproxy 2>/dev/null
    chmod 0755 /usr/share/flowproxy/runtime/worker.uc 2>/dev/null

    /etc/init.d/flowproxy enable 2>/dev/null
    [ -f "/etc/uci-defaults/99_flowproxy" ] && sh "/etc/uci-defaults/99_flowproxy"

    rm -f /usr/libexec/rpcd/flowproxy
    mkdir -p /usr/share/ucode 2>/dev/null
    ln -sfn /usr/share/flowproxy /usr/share/ucode/flowproxy

    rm -f /tmp/luci-indexcache
    rm -rf /tmp/luci-modulecache/
    killall -HUP rpcd 2>/dev/null
fi
exit 0
EOF
chmod 0755 "$IPKG_DIR/CONTROL/postinst"

cat <<'EOF' > "$IPKG_DIR/CONTROL/prerm"
#!/bin/sh
if [ -z "${IPKG_INSTROOT}" ]; then
    /etc/init.d/flowproxy stop 2>/dev/null
    /etc/init.d/flowproxy disable 2>/dev/null
    rm -f /usr/share/ucode/flowproxy
fi
exit 0
EOF
chmod 0755 "$IPKG_DIR/CONTROL/prerm"

echo "[INFO] Executing ipkg-build..."
ipkg-build "$IPKG_DIR" "$BASE_DIR"

echo "[SUCCESS] Build complete."
