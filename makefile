# -*- coding: utf-8 -*-

# 编译器
CC = gcc

# 编译选项
CFLAGS = -Wall -Wextra -O2
BASE_LDFLAGS = -lcurl -lcjson

# Windows平台
ifeq ($(OS), Windows_NT)
    LDFLAGS = $(BASE_LDFLAGS) -lws2_32
    TARGET = nbtv.exe
    INSTALL_PREFIX = C:/Program Files/Nbtv
    INSTALL_BIN_DIR = $(INSTALL_PREFIX)
    RM = del /Q
    CP = copy
define create_dir
	@if not exist "$(1)" mkdir "$(1)"
endef
    CHMOD = 
    STRIP = 
else
	LDFLAGS = $(BASE_LDFLAGS)
    TARGET = nbtv
    INSTALL_PREFIX = /usr/local
    INSTALL_BIN_DIR = $(INSTALL_PREFIX)/bin
    INSTALL_MAN_DIR = $(INSTALL_PREFIX)/share/man/man1
    INSTALL_SERVICE_DIR = $(INSTALL_PREFIX)/lib/systemd/system
    RM = rm -f
    CP = cp
define create_dir
	@mkdir -p "$(1)"
endef
    CHMOD = chmod
    STRIP = strip
endif

# 源文件
SRC = main.c
OBJ = $(SRC:.c=.o)

# 默认目标
all: $(TARGET)

# 链接目标
$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

# 编译源文件
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理
clean:
	rm -f $(OBJ) $(TARGET)

# 安装目标
install: $(TARGET)
	@echo "Installing $(TARGET) to $(INSTALL_PREFIX)..."
	
# 创建安装目录
	@$(call create_dir,$(INSTALL_BIN_DIR))
	
# 安装可执行文件
	$(CP) $(TARGET) "$(INSTALL_BIN_DIR)/$(TARGET)"
	
# 设置可执行权限（Unix）
	$(if $(CHMOD),$(CHMOD) 755 "$(INSTALL_BIN_DIR)/$(TARGET)")
	
	@echo "Successfully installed"
	@echo "Run: $(INSTALL_BIN_DIR)/$(TARGET)"

# 卸载目标
uninstall:
	@echo "Uninstalling $(TARGET)..."
	
# 删除可执行文件
	$(if $(wildcard $(INSTALL_BIN_DIR)/$(TARGET)),$(RM) "$(INSTALL_BIN_DIR)/$(TARGET)" && echo "删除: $(INSTALL_BIN_DIR)/$(TARGET)")
	
	@echo "Successfully uninstalled"

# 重新构建
rebuild: clean all

.PHONY: all clean install uninstall rebuild