# 编译器
CC = gcc

# 编译选项
CFLAGS = -Wall -Wextra -O2
BASE_LDFLAGS = -lcurl -lcjson

# Windows平台
ifeq ($(OS), Windows_NT)
    LDFLAGS = $(BASE_LDFLAGS) -lws2_32
else
	LDFLAGS = $(BASE_LDFLAGS)
endif

# 目标可执行文件
TARGET = nbtv

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

# 运行
run: $(TARGET)
	./$(TARGET)

# 重新构建
rebuild: clean all

.PHONY: all clean run rebuild