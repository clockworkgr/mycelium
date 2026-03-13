#
# LuCI app for Mycelium mesh daemon.
#
# Provides a web interface for monitoring and configuring the
# Mycelium supernode daemon running on OpenWRT.

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI Mycelium Mesh Dashboard
LUCI_DEPENDS:=+mycelium +luci-base +luci-compat
LUCI_DESCRIPTION:=Web interface for the Mycelium mesh communications daemon. \
	Shows node status, connected peers, DTN queue, and transport configuration.

PKG_LICENSE:=MIT

include $(TOPDIR)/feeds/luci/luci.mk

define Package/luci-app-mycelium/conffiles
/etc/config/mycelium
endef

# call BuildPackage - OpenWrt buildance
$(eval $(call BuildPackage,luci-app-mycelium))
