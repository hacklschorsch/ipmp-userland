# Name: ipmp_pathchar
# Description: IPMP Pathchar utility
# Author: Matthew Luckie
# OpenWRT Package: Florian Sesser
# Date: 2010/07


include $(TOPDIR)/rules.mk

PKG_NAME:=ipmp_pathchar
PKG_REV:=r24266
PKG_VERSION:=0.0.2
PKG_RELEASE:=1

PKG_SOURCE_SUBDIR:=ipmp_pathchar-$(PKG_VERSION)
PKG_SOURCE_URL:=http://www.so.in.tum.de/ssr/ipmp_pathchar
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_REV).tar.gz

include $(INCLUDE_DIR)/package.mk


define Package/ipmp_pathchar
  SECTION:=net
  CATEGORY:=Network
  TITLE:=IPMP Pathchar utility
  URL:=http://www.so.in.tum.de/
endef

define Package/ipmp_pathchar/description
  This utility measures the bandwidth of a multi-hop link using
  IPMP echo requests. For more information on the IP Measurement
  Protocol, see Matthew Luckie's work:
  http://www.wand.net.nz/pubs.php?person=13
  
  Contributed by Florian Sesser / TUM
  http://www.so.in.tum.de/
endef


define Package/ipmp_pathchar/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ipmp_pathchar $(1)/usr/bin/
endef

$(eval $(call BuildPackage,ipmp_pathchar))
