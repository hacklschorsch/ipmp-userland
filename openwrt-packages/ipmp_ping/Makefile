# Name: ipmp_ping
# Description: IPMP Ping utility
# Author: Matthew Luckie
# OpenWRT Package: Florian Sesser
# Date: 2010/07


include $(TOPDIR)/rules.mk

PKG_NAME:=ipmp_ping
PKG_REV:=r24137
PKG_VERSION:=0.0.3
PKG_RELEASE:=1

PKG_SOURCE_SUBDIR:=ipmp_ping-$(PKG_VERSION)
PKG_SOURCE_URL:=http://www.so.in.tum.de/ssr/ipmp_ping
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_REV).tar.gz

include $(INCLUDE_DIR)/package.mk


define Package/ipmp_ping
  SECTION:=net
  CATEGORY:=Network
  TITLE:=IPMP Ping utility
  URL:=http://www.so.in.tum.de/
endef

define Package/ipmp_ping/description
  This utility can send IPMP echo requests. For more information on
  the IP Measurement Protocol, see, for example, Matthew Luckie's work:
  http://www.wand.net.nz/pubs.php?person=13
  
  Contributed by Florian Sesser / TUM
  http://www.so.in.tum.de/
endef


define Package/ipmp_ping/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ipmp_ping $(1)/usr/bin/
endef

$(eval $(call BuildPackage,ipmp_ping))
