宁波电视台IPTV代理服务器

To build for PC
apt update && apt install libcurl4-openssl-dev
make -C nbtv/makefile

To build for openwrt
1. create a sdk environment
2. ./scripts/feeds update && ./scripts/feeds install libcurl
3. copy this root dir into package
4. make ./package/nbtv/compile

Runtime deps
- libcurl