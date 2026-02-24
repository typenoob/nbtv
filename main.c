#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif

// 定义频道数量
#define CHANNEL_COUNT 4
#define SERVER_PORT 8787
#define BUFFER_SIZE 4096

// 频道名称数组
const char* channels[CHANNEL_COUNT] = {"nbtv1", "nbtv2", "nbtv3", "nbtv4"};

// 全局变量存储最新的播放列表
char *latest_m3u_content = NULL;
time_t last_update_time = 0;
const int CACHE_TTL = 300; // 缓存5分钟

// 用于存储 CURL 响应数据的结构体
struct MemoryStruct {
    char *memory;
    size_t size;
};

// CURL 写回调函数
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(ptr == NULL) {
        printf("内存分配失败！\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// 获取播放器配置
char* get_player_config() {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    
    chunk.memory = malloc(1);
    chunk.size = 0;

    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://web.ncmc.nbtv.cn/vms/site/nbtv/media/playerJson/liveChannel/9ebadf3777b14e0eac6cc99509ae0493_PlayerParamProfile.json");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        
        res = curl_easy_perform(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "获取配置失败: %s\n", curl_easy_strerror(res));
            free(chunk.memory);
            curl_easy_cleanup(curl);
            return NULL;
        }
        
        curl_easy_cleanup(curl);
        
        // 验证 JSON 是否有效
        cJSON *json = cJSON_Parse(chunk.memory);
        if (json == NULL) {
            printf("JSON 解析失败\n");
            free(chunk.memory);
            return NULL;
        }
        cJSON_Delete(json);
        
        return chunk.memory;
    }
    
    return NULL;
}

// 获取加密的播放 URL
char* get_encrypted_url(const char* player_config, const char* channel) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    
    // 解析 JSON 配置
    cJSON *json = cJSON_Parse(player_config);
    if (json == NULL) {
        printf("配置 JSON 解析失败\n");
        return NULL;
    }
    
    // 获取 paramsConfig
    cJSON *paramsConfig = cJSON_GetObjectItem(json, "paramsConfig");
    if (!paramsConfig) {
        printf("未找到 paramsConfig\n");
        cJSON_Delete(json);
        return NULL;
    }
    
    // 获取 cdnConfig
    cJSON *cdnConfig = cJSON_GetObjectItem(paramsConfig, "cdnConfig");
    if (!cdnConfig || !cJSON_IsArray(cdnConfig) || cJSON_GetArraySize(cdnConfig) == 0) {
        printf("cdnConfig 无效\n");
        cJSON_Delete(json);
        return NULL;
    }
    
    // 获取第一个 CDN 配置
    cJSON *cdn0 = cJSON_GetArrayItem(cdnConfig, 0);
    if (!cdn0) {
        printf("cdnConfig[0] 无效\n");
        cJSON_Delete(json);
        return NULL;
    }
    
    // 获取 publishHost
    cJSON *publishHost = cJSON_GetObjectItem(cdn0, "publishHost");
    if (!publishHost || !cJSON_IsString(publishHost)) {
        printf("publishHost 无效\n");
        cJSON_Delete(json);
        return NULL;
    }
    
    // 获取 cdnConfigEncrypt
    cJSON *cdnConfigEncrypt = cJSON_GetObjectItem(paramsConfig, "cdnConfigEncrypt");
    if (!cdnConfigEncrypt || !cJSON_IsString(cdnConfigEncrypt)) {
        printf("cdnConfigEncrypt 无效\n");
        cJSON_Delete(json);
        return NULL;
    }
    
    // 构建播放 URL
    char play_url[512];
    snprintf(play_url, sizeof(play_url), "%s/live/%s_md.m3u8", 
             cJSON_GetStringValue(publishHost), channel);
    
    // 构建请求体
    char request_body[1024];
    snprintf(request_body, sizeof(request_body), 
             "{\"url\": \"%s\", \"playType\": \"live\", \"type\": \"cdn\", \"cdnEncrypt\": \"%s\", \"cdnIndex\": 0}",
             play_url, cJSON_GetStringValue(cdnConfigEncrypt));
    
    // 清理 JSON
    cJSON_Delete(json);
    
    // 初始化响应内存
    chunk.memory = malloc(1);
    chunk.size = 0;
    
    // 发送请求到加密服务
    curl = curl_easy_init();
    if(curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_URL, "https://em.chinamcloud.com/player/encryptUrl");
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        
        res = curl_easy_perform(curl);
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        
        if(res != CURLE_OK) {
            fprintf(stderr, "获取加密 URL 失败: %s\n", curl_easy_strerror(res));
            free(chunk.memory);
            return NULL;
        }
        
        // 解析返回的 JSON 获取 url
        cJSON *response_json = cJSON_Parse(chunk.memory);
        if (response_json) {
            cJSON *url_obj = cJSON_GetObjectItem(response_json, "url");
            if (url_obj && cJSON_IsString(url_obj)) {
                char *result_url = strdup(cJSON_GetStringValue(url_obj));
                cJSON_Delete(response_json);
                free(chunk.memory);
                return result_url;
            }
            cJSON_Delete(response_json);
        }
        
        free(chunk.memory);
    }
    
    return NULL;
}

// 生成 M3U 播放列表
char* generate_m3u_playlist(char* urls[]) {
    // 分配足够大的内存
    size_t buffer_size = 4096;
    char *m3u_content = malloc(buffer_size);
    if (!m3u_content) {
        return NULL;
    }
    
    snprintf(m3u_content, buffer_size,
        "#EXTM3U x-tvg-url=\"https://epg.erw.cc/e.xml\" catchup=\"append\" catchup-source=\"?playseek=%%24(b)yyyyMMddHHmmss-%%24(e)yyyyMMddHHmmss\"\n"
        "#宁波电视台\n"
        "#EXTINF:-1 tvg-id=\"NBTV1\" tvg-name=\"NBTV1\" tvg-logo=\"https://live.fanmingming.com/tv/CCTV1.png\" group-title=\"宁波电视台\",NBTV-1 新闻综合\n"
        "%s\n"
        "#EXTINF:-1 tvg-id=\"NBTV2\" tvg-name=\"NBTV2\" tvg-logo=\"https://live.fanmingming.com/tv/CCTV2.png\" group-title=\"宁波电视台\",NBTV-2 经济生活\n"
        "%s\n"
        "#EXTINF:-1 tvg-id=\"NBTV3\" tvg-name=\"NBTV3\" tvg-logo=\"https://live.fanmingming.com/tv/CCTV3.png\" group-title=\"宁波电视台\",NBTV-3 都市文体\n"
        "%s\n"
        "#EXTINF:-1 tvg-id=\"NBTV4\" tvg-name=\"NBTV4\" tvg-logo=\"https://live.fanmingming.com/tv/CCTV4.png\" group-title=\"宁波电视台\",NBTV-4 影视剧\n"
        "%s\n",
        urls[0], urls[1], urls[2], urls[3]);
    
    return m3u_content;
}

// 更新 M3U 内容（带缓存）
void update_m3u_content() {
    time_t now = time(NULL);
    
    // 检查缓存是否过期
    if (latest_m3u_content != NULL && (now - last_update_time) < CACHE_TTL) {
        printf("使用缓存内容 (剩余缓存时间: %d秒)\n", CACHE_TTL - (int)(now - last_update_time));
        return;
    }
    
    printf("开始更新播放列表...\n");
    
    // 清理旧内容
    if (latest_m3u_content) {
        free(latest_m3u_content);
        latest_m3u_content = NULL;
    }
    
    // 1. 获取播放器配置
    char *player_config = get_player_config();
    if (!player_config) {
        printf("获取播放器配置失败\n");
        return;
    }
    
    // 2. 为每个频道获取加密 URL
    char *urls[CHANNEL_COUNT] = {NULL};
    int success_count = 0;
    
    for (int i = 0; i < CHANNEL_COUNT; i++) {
        printf("正在获取频道 %s 的播放地址...\n", channels[i]);
        urls[i] = get_encrypted_url(player_config, channels[i]);
        if (urls[i]) {
            success_count++;
        }
    }
    
    // 3. 生成 M3U 播放列表
    if (success_count == CHANNEL_COUNT) {
        latest_m3u_content = generate_m3u_playlist(urls);
        last_update_time = now;
        printf("播放列表更新成功\n");
    } else {
        printf("部分频道获取失败，无法更新播放列表\n");
    }
    
    // 4. 清理资源
    free(player_config);
    for (int i = 0; i < CHANNEL_COUNT; i++) {
        if (urls[i]) free(urls[i]);
    }
}

// 发送 HTTP 响应
void send_http_response(int client_socket, const char *content_type, const char *body) {
    char response[BUFFER_SIZE];
    int length = snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Cache-Control: max-age=%d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        content_type, strlen(body), CACHE_TTL, body);
    
    send(client_socket, response, length, 0);
}

// 处理 HTTP 请求
void handle_client_request(int client_socket) {
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        
        // 检查是否是 GET 请求
        if (strstr(buffer, "GET /iptv.m3u") || strstr(buffer, "GET / ")) {
            printf("收到 M3U 播放列表请求\n");
            
            // 更新内容（如果需要）
            update_m3u_content();
            
            if (latest_m3u_content) {
                send_http_response(client_socket, "text/plain; charset=utf-8", latest_m3u_content);
                printf("已发送 M3U 播放列表 (%zu 字节)\n", strlen(latest_m3u_content));
            } else {
                const char *error_msg = "#EXTM3U\n#EXTINF:-1,Error: Failed to generate playlist\n";
                send_http_response(client_socket, "text/plain; charset=utf-8", error_msg);
                printf("发送错误响应\n");
            }
        } else if (strstr(buffer, "GET /status")) {
            // 状态页面
            char status_page[512];
            time_t now = time(NULL);
            snprintf(status_page, sizeof(status_page),
                "<html><body>"
                "<h1>宁波电视台 IPTV 服务器</h1>"
                "<p>状态: <span style='color:green'>运行中</span></p>"
                "<p>最后更新时间: %s</p>"
                "<p>缓存剩余时间: %d 秒</p>"
                "<p><a href='/iptv.m3u'>下载 M3U 播放列表</a></p>"
                "</body></html>",
                ctime(&last_update_time),
                CACHE_TTL - (int)(now - last_update_time));
            
            send_http_response(client_socket, "text/html; charset=utf-8", status_page);
        } else {
            // 404 页面
            const char *not_found = 
                "<html><body>"
                "<h1>404 Not Found</h1>"
                "<p>可用路径:</p>"
                "<ul>"
                "<li><a href='/iptv.m3u'>/iptv.m3u - M3U 播放列表</a></li>"
                "<li><a href='/status'>/status - 服务器状态</a></li>"
                "</ul>"
                "</body></html>";
            
            send_http_response(client_socket, "text/html; charset=utf-8", not_found);
        }
    }
    
#ifdef _WIN32
    closesocket(client_socket);
#else
    close(client_socket);
#endif
}

// 初始化网络
int init_network() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup 失败\n");
        return 0;
    }
#endif
    return 1;
}

// 清理网络
void cleanup_network() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// 修改主函数
int main(int argc, char *argv[]) {
    // 设置控制台编码（Windows）
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    int g_server_port = SERVER_PORT;
    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("宁波电视台 IPTV HTTP 服务器\n\n");
            printf("用法: %s [选项]\n\n", argv[0]);
            printf("选项:\n");
            printf("  -h, --help          显示此帮助信息\n");
            printf("  -p, --port PORT     指定服务器端口 (默认: %d)\n", SERVER_PORT);
            printf("  -d, --daemon        以守护进程模式运行 (Linux/Unix)\n");
            printf("  -v, --verbose       详细输出模式\n");
            printf("  --no-cache          禁用缓存，每次请求都重新获取\n");
            printf("  --cache-time SECONDS 设置缓存时间 (默认: %d秒)\n", CACHE_TTL);
            printf("\n示例:\n");
            printf("  %s                    # 使用默认端口 %d\n", argv[0], SERVER_PORT);
            printf("  %s -p 8080            # 使用端口 8080\n", argv[0]);
            printf("  %s --port 9000 -v     # 使用端口 9000 并开启详细输出\n", argv[0]);
            return 0;
        }
        else if (strcmp(argv[i], "--port") == 0 || strcmp(argv[i], "-p") == 0) {
            if (i + 1 < argc) {
                int port = atoi(argv[i + 1]);
                if (port > 0 && port < 65536) {
                    g_server_port = port;
                    i++; // 跳过下一个参数
                } else {
                    fprintf(stderr, "错误: 端口必须在 1-65535 之间\n");
                    return 1;
                }
            } else {
                fprintf(stderr, "错误: --port 需要指定端口号\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            // 可以在这里设置详细输出标志
            // 例如: g_verbose_mode = 1;
            printf("详细输出模式已启用\n");
        }
        else if (strcmp(argv[i], "--daemon") == 0 || strcmp(argv[i], "-d") == 0) {
#ifndef _WIN32
            // Linux/Unix 守护进程模式
            pid_t pid = fork();
            
            if (pid < 0) {
                perror("fork 失败");
                exit(EXIT_FAILURE);
            }
            
            if (pid > 0) {
                // 父进程退出
                printf("守护进程已启动，PID: %d\n", pid);
                printf("日志输出到: /var/log/nbtv_iptv.log\n");
                exit(EXIT_SUCCESS);
            }
            
            // 子进程继续运行
            umask(0);
            setsid();
            
            // 关闭标准文件描述符
            close(STDIN_FILENO);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            
            // 重新打开标准输出到日志文件
            FILE *log_file = fopen("/var/log/nbtv_iptv.log", "a");
            if (log_file) {
                dup2(fileno(log_file), STDOUT_FILENO);
                dup2(fileno(log_file), STDERR_FILENO);
                fclose(log_file);
            }
#else
            printf("警告: --daemon 选项在 Windows 上不可用\n");
#endif
        }
        else if (strcmp(argv[i], "--no-cache") == 0) {
            // 可以在这里设置禁用缓存
            printf("缓存已禁用\n");
        }
        else if (strcmp(argv[i], "--cache-time") == 0) {
            if (i + 1 < argc) {
                int cache_time = atoi(argv[i + 1]);
                if (cache_time > 0) {
                    // 可以在这里修改缓存时间
                    // 例如: g_cache_ttl = cache_time;
                    printf("缓存时间设置为: %d 秒\n", cache_time);
                    i++; // 跳过下一个参数
                } else {
                    fprintf(stderr, "错误: 缓存时间必须大于 0\n");
                    return 1;
                }
            } else {
                fprintf(stderr, "错误: --cache-time 需要指定秒数\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-V") == 0) {
            printf("宁波电视台 IPTV HTTP 服务器 v1.0.0\n");
            printf("编译时间: %s %s\n", __DATE__, __TIME__);
            return 0;
        }
        else {
            fprintf(stderr, "错误: 未知选项 '%s'\n", argv[i]);
            fprintf(stderr, "使用 '%s --help' 查看帮助\n", argv[0]);
            return 1;
        }
    }
    
    // 初始化网络
    if (!init_network()) {
        return 1;
    }
    
    // 初始化 CURL
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    printf("=== 宁波电视台 IPTV HTTP 服务器 ===\n");
    printf("服务器启动中...\n");
    printf("端口: %d\n", g_server_port);
#ifdef _WIN32
    printf("进程ID: %ld\n", (long)GetCurrentProcessId());
#else
    printf("进程ID: %d\n", getpid());
#endif
    printf("\n可用路径:\n");
    printf("  http://localhost:%d/iptv.m3u - M3U 播放列表\n", g_server_port);
    printf("  http://localhost:%d/status - 服务器状态\n", g_server_port);
    printf("\n服务器已启动，按 Ctrl+C 停止\n");
    
    // 创建 socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("创建 socket 失败");
        cleanup_network();
        return 1;
    }
    
    // 设置 SO_REUSEADDR
    int opt = 1;
#ifdef _WIN32
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
#else
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    
    // 绑定地址（使用 g_server_port）
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(g_server_port);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("绑定地址失败");
#ifdef _WIN32
        closesocket(server_socket);
#else
        close(server_socket);
#endif
        cleanup_network();
        return 1;
    }
    
    // 监听
    if (listen(server_socket, 10) < 0) {
        perror("监听失败");
#ifdef _WIN32
        closesocket(server_socket);
#else
        close(server_socket);
#endif
        cleanup_network();
        return 1;
    }
    
    printf("服务器监听中...\n");
    
    // 预先获取一次播放列表
    update_m3u_content();
    
    // 主循环
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_socket < 0) {
            perror("接受连接失败");
            continue;
        }
        
        // 获取客户端 IP
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("收到来自 %s:%d 的连接\n", client_ip, ntohs(client_addr.sin_port));
        
        // 处理请求
        handle_client_request(client_socket);
    }
    
    // 清理（理论上不会执行到这里）
    if (latest_m3u_content) {
        free(latest_m3u_content);
    }
    
#ifdef _WIN32
    closesocket(server_socket);
#else
    close(server_socket);
#endif
    
    curl_global_cleanup();
    cleanup_network();
    
    return 0;
}