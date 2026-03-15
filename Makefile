include $(TOPDIR)/rules.mk

PKG_NAME:=hello-local
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/hello-local
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Hello from local source
  MAINTAINER:=Your Name <your@email.com>
endef

define Package/hello-local/description
  A simple hello world program built from local source.
endef

# 关键：不定义 PKG_SOURCE，只复制本地文件
define Build/Prepare
    mkdir -p $(PKG_BUILD_DIR)
    $(CP) ./src/* $(PKG_BUILD_DIR)/
endef

# 如果需要配置步骤
define Build/Configure
    # 如果有 configure 脚本
    (cd $(PKG_BUILD_DIR) && ./configure \
        --host=$(GNU_TARGET_NAME) \
        --prefix=/usr)
endef

# 编译
define Build/Compile
    $(MAKE) -C $(PKG_BUILD_DIR) \
        CC="$(TARGET_CC)" \
        CFLAGS="$(TARGET_CFLAGS)" \
        LDFLAGS="$(TARGET_LDFLAGS)"
endef

# 安装
define Package/hello-local/install
    $(INSTALL_DIR) $(1)/usr/bin
    $(INSTALL_BIN) $(PKG_BUILD_DIR)/hello $(1)/usr/bin/
    
    # 安装配置文件（如果有）
    $(INSTALL_DIR) $(1)/etc/config
    $(INSTALL_CONF) ./files/hello.conf $(1)/etc/config/hello
endef

$(eval $(call BuildPackage,hello-local))
