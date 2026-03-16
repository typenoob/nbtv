include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk

PKG_NAME:=nbtv
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT

define Package/nbtv
  SECTION:=utils
  CATEGORY:=Utilities
  DEPENDS:=+libcurl
  TITLE:=NBTV M3U8 Live Source Publish Server
  MAINTAINER:=yuaochen <chenyutao0706@gmail.com>
endef

define Package/nbtv/description
  NBTV M3U8 Live Source Publish Server
endef

# 关键：不定义 PKG_SOURCE，只复制本地文件
define Build/Prepare
  mkdir -p $(PKG_BUILD_DIR)
  $(CP) -r ./nbtv $(PKG_BUILD_DIR)/
  $(CP) -r ./libs $(PKG_BUILD_DIR)/
endef

# 编译
define Build/Compile
  $(MAKE) -C $(PKG_BUILD_DIR)/nbtv \
  CC="$(TARGET_CC)" \
  CFLAGS="$(TARGET_CFLAGS) -I$(PKG_BUILD_DIR)" \
  LDFLAGS="$(TARGET_LDFLAGS) -lcurl"
endef

# 安装
define Package/nbtv/install
  $(INSTALL_DIR) $(1)/usr/bin
  $(INSTALL_BIN) $(PKG_BUILD_DIR)/nbtv/nbtv $(1)/usr/bin/
endef

$(eval $(call BuildPackage,nbtv))