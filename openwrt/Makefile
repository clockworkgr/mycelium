include $(TOPDIR)/rules.mk

PKG_NAME:=mycelium
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/mycelium
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Mycelium Mesh Communications
  DEPENDS:=+libpthread +librt
  URL:=https://github.com/mycelium-mesh/mycelium
endef

define Package/mycelium/description
  Mycelium is an infrastructure-independent mesh communications platform.
  This package provides the supernode daemon for OpenWRT routers.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	cd $(PKG_BUILD_DIR) && \
	CARGO_TARGET_DIR=$(PKG_BUILD_DIR)/target \
	cross build --release --target $(CARGO_TARGET) --bin mycelium-node
endef

define Package/mycelium/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/target/$(CARGO_TARGET)/release/mycelium-node $(1)/usr/bin/mycelium-node
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/mycelium $(1)/etc/init.d/mycelium
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/mycelium $(1)/etc/config/mycelium
endef

$(eval $(call BuildPackage,mycelium))
