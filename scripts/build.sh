#!/bin/bash
# --- [ FlowProxy | Standalone IPK Builder | v1.2 ] ---
# [Category B] 鑱岃兘锛氬湪闈?SDK 鐜涓嬫ā鎷?RootFS 缁撴瀯骞舵墽琛岀墿鐞嗙粍瑁咃紝鐢熸垚鍚堣鐨?.ipk 鏂囦欢銆?
set -e

# [Category A] 鐜鍏冩暟鎹厤缃?PKG_NAME="luci-app-flowproxy"
PKG_VERSION="1.0.0"
PKG_RELEASE="1"
PKG_ARCH="all"
PKG_MAINTAINER="FlowProxy-Team"

BASE_DIR=$(pwd)
BUILD_DIR="${BASE_DIR}/build_tmp"
IPKG_DIR="${BUILD_DIR}/ipkg"

# 1. 鍒濆鍖栭殧绂绘矙绠?# [Category C] Note: 姣忔鏋勫缓鍓嶅繀椤绘竻鐞嗗巻鍙叉畫鐣欙紝闃叉鑴忔暟鎹薄鏌?rm -rf "$BUILD_DIR" && mkdir -p "$IPKG_DIR/CONTROL"

# 2. 铏氭嫙鏂囦欢绯荤粺 (VFS) 鏄犲皠
echo "[INFO] Mapping Virtual File System..."

# 鏍稿績鍚庣閫昏緫 (Ucode Modules)
mkdir -p "$IPKG_DIR/usr/share/flowproxy"
cp -r "${BASE_DIR}/usr/share/flowproxy/"* "$IPKG_DIR/usr/share/flowproxy/"

# 馃毃 鏋舵瀯淇锛氬己琛屾祰绛戞牳蹇冭祫婧愪笌鏁版嵁鐩綍楠ㄦ灦
echo "[INFO] Provisioning Core Infrastructure Directories..."
mkdir -p "$IPKG_DIR/etc/flowproxy/resources"
mkdir -p "$IPKG_DIR/etc/flowproxy/ruleset"
mkdir -p "$IPKG_DIR/etc/flowproxy/run"

# 瀹归敊鎷疯礉锛氬皢婧愮爜涓殑鐗╃悊鏂囦欢锛堝 txt 璧勬簮锛夋敞鍏ラ鏋?if [ -d "${BASE_DIR}/etc/flowproxy" ] && [ "$(ls -A ${BASE_DIR}/etc/flowproxy 2>/dev/null)" ]; then
    cp -r "${BASE_DIR}/etc/flowproxy/"* "$IPKG_DIR/etc/flowproxy/"
else
    echo "[INFO] Source /etc/flowproxy is empty or missing. Clean infrastructure provisioned."
fi

# 鐢熷懡鍛ㄦ湡涓庨厤缃鏋?mkdir -p "$IPKG_DIR/etc/config"
cp "${BASE_DIR}/etc/config/flowproxy" "$IPKG_DIR/etc/config/"
mkdir -p "$IPKG_DIR/etc/init.d"
cp "${BASE_DIR}/etc/init.d/flowproxy" "$IPKG_DIR/etc/init.d/"
mkdir -p "$IPKG_DIR/etc/uci-defaults"
cp "${BASE_DIR}/root/etc/uci-defaults/99_flowproxy" "$IPKG_DIR/etc/uci-defaults/"

# [Category B] 淇鐐?A & B锛歊PCD 缃戝叧鍏ュ彛鐐瑰洖褰?OpenWrt 鍘熺敓鏍囧噯鐩綍锛屾寕杞?ubus 涓婁笅鏂囦笌 ACL
mkdir -p "$IPKG_DIR/usr/share/rpcd/ucode"
cp "${BASE_DIR}/usr/share/rpcd/ucode/flowproxy.uc" "$IPKG_DIR/usr/share/rpcd/ucode/"
mkdir -p "$IPKG_DIR/usr/share/rpcd/acl.d"
cp "${BASE_DIR}/usr/share/rpcd/acl.d/"*.json "$IPKG_DIR/usr/share/rpcd/acl.d/"

# LuCI 鍘熺敓鑿滃崟涓庨潤鎬佽祫浜?mkdir -p "$IPKG_DIR/usr/share/luci/menu.d"
cp "${BASE_DIR}/usr/share/luci/menu.d/"*.json "$IPKG_DIR/usr/share/luci/menu.d/"
mkdir -p "$IPKG_DIR/www/luci-static/resources"
cp -r "${BASE_DIR}/htdocs/luci-static/resources/"* "$IPKG_DIR/www/luci-static/resources/"

# 鐙珛闈㈡澘 (Zashboard) 鏄犲皠
# [Category C] Warning: 纭繚浠撳簱涓凡鍖呭惈鏋勫缓瀹屾垚鐨?dist 浜х墿
mkdir -p "$IPKG_DIR/www/zashboard"
if [ -d "${BASE_DIR}/www/zashboard" ]; then
    cp -rP "${BASE_DIR}/www/zashboard/"* "$IPKG_DIR/www/zashboard/"
else
    echo "[WARN] /www/zashboard directory not found, skipping."
fi

# 3. 璇█鍖呯紪璇?(po -> lmo)
# [Category B] 淇鐐?C锛氭洿姝ｈ緭鍑哄悗缂€涓?zh-cn锛岄€傞厤 LuCI i18n 搴曞眰鍔犺浇瑙勫垯
echo "[INFO] Compiling I18N packages..."
mkdir -p "$IPKG_DIR/usr/lib/lua/luci/i18n"
if command -v po2lmo > /dev/null; then
    po2lmo "${BASE_DIR}/po/zh_Hans/flowproxy.po" "$IPKG_DIR/usr/lib/lua/luci/i18n/flowproxy.zh-cn.lmo"
else
    echo "[FATAL] po2lmo tool is missing. CI environment must pre-install it."
    exit 1
fi

# 4. 鐢熸垚鎺у埗灞傚厓鏁版嵁 (Control Plane Metadata)
echo "[INFO] Generating CONTROL files..."

# [Category B] 娉ㄥ叆 preinst 鑴氭湰锛氳В鍐抽潪鎵樼闈欐€佽祫婧愮殑瑕嗗啓鍐茬獊
cat <<'EOF' > "$IPKG_DIR/CONTROL/preinst"
#!/bin/sh
if [ -z "${IPKG_INSTROOT}" ]; then
    # 寮哄埗鎶归櫎鏃х殑鐗╃悊閬楃暀闈㈡澘锛屼负 opkg 瑙ｅ帇閾哄钩閬撹矾
    rm -rf /www/zashboard 2>/dev/null
fi
exit 0
EOF
chmod 0755 "$IPKG_DIR/CONTROL/preinst"

cat <<EOF > "$IPKG_DIR/CONTROL/control"
Package: $PKG_NAME
Version: $PKG_VERSION-$PKG_RELEASE
Depends: luci-base, rpcd, rpcd-mod-ucode, ucode, ucode-mod-uci, ucode-mod-fs, ucode-mod-math, curl, ca-bundle, sing-box, ip-full, nftables, kmod-tun, kmod-nft-tproxy, kmod-nft-nat, kmod-inet-diag, coreutils-timeout
Section: luci
Architecture: $PKG_ARCH
Maintainer: $PKG_MAINTAINER
Description: FlowProxy - Modern sing-box Control Plane
EOF

# 澹版槑 UCI 淇濇姢鍏嶉伃瑕嗙洊
echo "/etc/config/flowproxy" > "$IPKG_DIR/CONTROL/conffiles"

# [Category B] 娉ㄥ叆 postinst 鑴氭湰锛氬鐞嗙幆澧冩彁鏉冧笌鐢熷懡鍛ㄦ湡婵€娲?cat <<'EOF' > "$IPKG_DIR/CONTROL/postinst"
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

    # 寮哄埗鏍稿績鑴氭湰 0755 鏉冮檺
    chmod 0755 /etc/init.d/flowproxy 2>/dev/null
    chmod 0755 /usr/share/flowproxy/runtime/worker.uc 2>/dev/null
    
    # 娉ㄥ唽绯荤粺鏈嶅姟骞剁珛鍗虫墽琛岀幆澧冨垵濮嬪寲
    /etc/init.d/flowproxy enable
    [ -f "/etc/uci-defaults/99_flowproxy" ] && sh "/etc/uci-defaults/99_flowproxy"
    
    # Legacy rpcd shim cleanup
    rm -f /usr/libexec/rpcd/flowproxy
    
    # 馃毃 鏋舵瀯绾т慨澶嶏細鍔ㄦ€佹敞鍏?Ucode 寮曟搸瀵诲潃杞摼锛?    # 灏嗗疄闄呬笟鍔′唬鐮佹ˉ鎺ュ埌寮曟搸榛樿鎼滅储璺緞锛屽交搴曟秷鐏?module not found 鎶ラ敊
    mkdir -p /usr/share/ucode 2>/dev/null
    ln -sfn /usr/share/flowproxy /usr/share/ucode/flowproxy
    
    # Clear LuCI caches and reload rpcd
    rm -f /tmp/luci-indexcache
    rm -rf /tmp/luci-modulecache/
    killall -HUP rpcd 2>/dev/null
fi
exit 0
EOF
chmod 0755 "$IPKG_DIR/CONTROL/postinst"

# [Category B] 娉ㄥ叆 prerm 鑴氭湰锛氬畨鍏ㄥ墺绂昏祫婧?cat <<'EOF' > "$IPKG_DIR/CONTROL/prerm"
#!/bin/sh
if [ -z "${IPKG_INSTROOT}" ]; then
    /etc/init.d/flowproxy stop 2>/dev/null
    /etc/init.d/flowproxy disable 2>/dev/null
    
    # 馃毃 瀹夊叏鍗歌浇锛氶攢姣佹垜浠湪 postinst 涓垱寤虹殑寮曟搸瀵诲潃杞摼
    rm -f /usr/share/ucode/flowproxy
fi
exit 0
EOF
chmod 0755 "$IPKG_DIR/CONTROL/prerm"

# 5. 璋冪敤鎵撳寘鍣ㄨ緭鍑?# [Category C] Note: 浣跨敤淇濆畧鐨勭函浣嶇疆鍙傛暟锛岃閬块潪鏍囧噯鐜 getopt 瑙ｆ瀽浣嶇Щ寮傚父
echo "[INFO] Executing ipkg-build..."
ipkg-build "$IPKG_DIR" "$BASE_DIR"

echo "[SUCCESS] Build complete."
