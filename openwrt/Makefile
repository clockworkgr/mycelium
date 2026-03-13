#
# OpenWRT package Makefile for Mycelium mesh daemon.
#
# This builds an .ipk package for use with opkg.
#
# Usage with OpenWRT SDK:
#   1. Clone the OpenWRT SDK for your target architecture
#   2. Symlink or copy this directory into package/mycelium/
#   3. Run: make package/mycelium/compile V=s
#
# The pre-built binary approach:
#   1. Build: ../scripts/build-openwrt.sh --release --target aarch64
#   2. The Makefile will pick up the binary from openwrt-bin/<arch>/
#
# Install the resulting .ipk:
#   opkg install mycelium_0.1.0-1_<arch>.ipk

include $(TOPDIR)/rules.mk

PKG_NAME:=mycelium
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_MAINTAINER:=Mycelium Contributors
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=../../LICENSE

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/mycelium
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Mesh Networking
  TITLE:=Mycelium Mesh Communications Daemon
  URL:=https://github.com/mycelium-mesh/mycelium
  DEPENDS:=+libpthread +librt
endef

define Package/mycelium/description
  Infrastructure-independent mesh communications platform using BLE,
  Wi-Fi Direct, LoRa, and internet tunnels for multi-hop encrypted
  messaging with DTN store-and-forward. Run as a supernode for
  always-on relay and prekey bundle caching.
endef

define Package/mycelium/conffiles
/etc/config/mycelium
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
endef

# Cross-compilation is handled by scripts/build-openwrt.sh outside
# the OpenWRT SDK. The Build/Compile step uses the pre-built binary.
define Build/Compile
endef

define Package/mycelium/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(CURDIR)/../openwrt-bin/$(ARCH)/mycelium-node $(1)/usr/bin/mycelium-node

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(CURDIR)/files/etc/config/mycelium $(1)/etc/config/mycelium

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(CURDIR)/files/etc/init.d/mycelium $(1)/etc/init.d/mycelium
endef

define Package/mycelium/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	echo "Enabling and starting mycelium..."
	/etc/init.d/mycelium enable
	/etc/init.d/mycelium start
}
endef

define Package/mycelium/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	/etc/init.d/mycelium stop
	/etc/init.d/mycelium disable
}
endef

$(eval $(call BuildPackage,mycelium))
