宁波电视台IPTV代理服务器

To build for PC
1. `apt update && apt install libcurl4-openssl-dev`
2. `make -C nbtv/makefile`

To build for openwrt
1. download openwrt sdk for your cpu, see https://mirrors.tuna.tsinghua.edu.cn/openwrt/releases/, 
    run the following commands in the sdk root directory
2. `./scripts/feeds update && ./scripts/feeds install libcurl`
3. `git clone --recurse-submodules https://github.com/typenoob/nbtv.git package`
4. `make ./package/nbtv/compile`

Runtime deps
- libcurl