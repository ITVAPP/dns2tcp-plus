#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "libev/ev.h"

#define DNS2TCP-PLUS_VER "dns2tcp-plus v1.2.0"

#ifndef IPV6_V6ONLY
  #define IPV6_V6ONLY 26
#endif

#ifndef SO_REUSEPORT
  #define SO_REUSEPORT 15
#endif

#ifndef TCP_SYNCNT
  #define TCP_SYNCNT 7
#endif

#define IP4STRLEN INET_ADDRSTRLEN /* 定义IPv4地址字符串长度，包含终止符 */
#define IP6STRLEN INET6_ADDRSTRLEN /* 定义IPv6地址字符串长度，包含终止符 */
#define PORTSTRLEN 6 /* 定义端口号字符串长度，包含终止符 */
#define DNS_MSGSZ 1472 /* 定义DNS消息最大长度，基于MTU减去IP和UDP头部 */
#define MAX_SERVERS 32 /* 定义最大服务器数量 */

/* ======================== helper ======================== */

#define __unused __attribute__((unused))

#define alignto(alignment) __attribute__((aligned(alignment)))

// 获取结构体指针，通过成员指针计算
#define container_of(p_field, struct_type, field_name) ( \
    (struct_type *) ((void *)(p_field) - offsetof(struct_type, field_name)) \
)

/* ======================== log-func ======================== */

/* 定义错误日志宏，仅输出错误信息 */
#define log_error(fmt, args...) \
    fprintf(stderr, "dns2tcp-plus: " fmt "\n", ##args)

/* 定义空日志宏，禁用非关键日志 */
#define log_verbose(fmt, args...) do {} while(0)
#define log_info(fmt, args...) do {} while(0)
/* 将警告日志重定向为错误日志 */
#define log_warning log_error

/* ======================== socket-addr ======================== */

union skaddr {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

#define skaddr_family(addr) ((addr)->sa.sa_family) /* 获取地址族 */
#define skaddr_is_sin(addr) (skaddr_family(addr) == AF_INET) /* 判断是否为IPv4地址 */
#define skaddr_is_sin6(addr) (skaddr_family(addr) == AF_INET6) /* 判断是否为IPv6地址 */
#define skaddr_len(addr) (skaddr_is_sin(addr) ? sizeof((addr)->sin) : sizeof((addr)->sin6)) /* 获取地址结构长度 */

// 将文本地址转换为socket地址结构
static void skaddr_from_text(union skaddr *addr, int family, const char *ipstr, uint16_t port) {
    if (family == AF_INET) {
        addr->sin.sin_family = AF_INET;
        inet_pton(AF_INET, ipstr, &addr->sin.sin_addr); /* 转换IPv4地址 */
        addr->sin.sin_port = htons(port); /* 设置端口号 */
    } else {
        addr->sin6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, ipstr, &addr->sin6.sin6_addr); /* 转换IPv6地址 */
        addr->sin6.sin6_port = htons(port); /* 设置端口号 */
    }
}

// 将socket地址结构转换为文本地址
static void skaddr_to_text(const union skaddr *addr, char *ipstr, uint16_t *port) {
    if (skaddr_is_sin(addr)) {
        inet_ntop(AF_INET, &addr->sin.sin_addr, ipstr, IP4STRLEN); /* 转换IPv4地址为文本 */
        *port = ntohs(addr->sin.sin_port); /* 获取端口号 */
    } else {
        inet_ntop(AF_INET6, &addr->sin6.sin6_addr, ipstr, IP6STRLEN); /* 转换IPv6地址为文本 */
        *port = ntohs(addr->sin6.sin6_port); /* 获取端口号 */
    }
}

// 获取IP地址字符串的地址族
static int get_ipstr_family(const char *ipstr) {
    char tmp[16];
    if (!ipstr)
        return -1; /* 返回无效地址族 */
    if (inet_pton(AF_INET, ipstr, &tmp) == 1)
        return AF_INET; /* 返回IPv4地址族 */
    if (inet_pton(AF_INET6, ipstr, &tmp) == 1)
        return AF_INET6; /* 返回IPv6地址族 */
    return -1; /* 返回无效地址族 */
}

/* ======================== 服务器信息结构 ======================== */

typedef struct {
    char         ipstr[IP6STRLEN]; /* 存储服务器IP地址字符串 */
    uint16_t     port; /* 存储服务器端口号 */
    union skaddr skaddr; /* 存储服务器socket地址 */
} server_info_t;

/* ======================== TCP连接结构 ======================== */

struct ctx; /* 前向声明ctx结构体 */

typedef struct tcp_conn {
    evio_t       watcher; /* 存储TCP事件监视器 */
    int          server_idx; /* 存储服务器索引 */
    struct ctx  *parent_ctx; /* 存储父context指针 */
    char         buffer[2 + DNS_MSGSZ] alignto(__alignof__(uint16_t)); /* 存储接收缓冲区 */
    uint16_t     nbytes; /* 存储已接收字节数 */
    struct tcp_conn *pool_next; /* 存储内存池链表指针 */
} tcp_conn_t;

/* ======================== context ======================== */

typedef struct ctx {
    union skaddr srcaddr; /* 存储客户端地址 */
    char         query_buffer[2 + DNS_MSGSZ] alignto(__alignof__(uint16_t)); /* 存储查询消息 */
    uint16_t     query_len; /* 存储查询消息长度 */
    tcp_conn_t  *connections[MAX_SERVERS]; /* 存储TCP连接数组 */
    int          conn_count; /* 存储连接数量 */
    bool         response_sent; /* 标记是否已发送响应 */
    int          active_conns; /* 存储活跃连接数 */
    struct ctx  *pool_next; /* 存储内存池链表指针 */
} ctx_t;

/* ======================== 内存池实现 ======================== */

#define CTX_POOL_SIZE 32 /* 定义ctx内存池大小，支持32个并发DNS请求 */
#define CONN_POOL_SIZE 256 /* 定义conn内存池大小，支持256个连接 */

static ctx_t ctx_pool[CTX_POOL_SIZE]; /* 定义ctx内存池 */
static ctx_t *ctx_free_list = NULL; /* 存储ctx空闲链表 */
static int ctx_pool_initialized = 0; /* 标记ctx内存池初始化状态 */

static tcp_conn_t conn_pool[CONN_POOL_SIZE]; /* 定义conn内存池 */
static tcp_conn_t *conn_free_list = NULL; /* 存储conn空闲链表 */
static int conn_pool_initialized = 0; /* 标记conn内存池初始化状态 */

// 初始化ctx内存池
static void init_ctx_pool(void) {
    if (ctx_pool_initialized) return; /* 跳过已初始化的内存池 */
    
    for (int i = 0; i < CTX_POOL_SIZE - 1; i++) {
        ctx_pool[i].pool_next = &ctx_pool[i + 1]; /* 链接ctx内存池节点 */
    }
    ctx_pool[CTX_POOL_SIZE - 1].pool_next = NULL; /* 设置链表尾部 */
    ctx_free_list = &ctx_pool[0]; /* 设置空闲链表头部 */
    ctx_pool_initialized = 1; /* 标记内存池已初始化 */
}

// 初始化conn内存池
static void init_conn_pool(void) {
    if (conn_pool_initialized) return; /* 跳过已初始化的内存池 */
    
    for (int i = 0; i < CONN_POOL_SIZE - 1; i++) {
        conn_pool[i].pool_next = &conn_pool[i + 1]; /* 链接conn内存池节点 */
    }
    conn_pool[CONN_POOL_SIZE - 1].pool_next = NULL; /* 设置链表尾部 */
    conn_free_list = &conn_pool[0]; /* 设置空闲链表头部 */
    conn_pool_initialized = 1; /* 标记内存池已初始化 */
}

// 从内存池分配ctx
static ctx_t *alloc_ctx(void) {
    if (!ctx_free_list) {
        log_error("ctx pool exhausted"); /* 记录内存池耗尽错误 */
        return NULL; /* 返回空指针 */
    }
    
    ctx_t *ctx = ctx_free_list; /* 获取空闲ctx */
    ctx_free_list = ctx->pool_next; /* 更新空闲链表 */
    
    ctx->conn_count = 0; /* 初始化连接数量 */
    ctx->response_sent = false; /* 初始化响应状态 */
    ctx->active_conns = 0; /* 初始化活跃连接数 */
    memset(ctx->connections, 0, sizeof(ctx->connections)); /* 清零连接数组 */
    
    return ctx; /* 返回分配的ctx */
}

// 归还ctx到内存池
static void free_ctx_to_pool(ctx_t *ctx) {
    ctx->pool_next = ctx_free_list; /* 链接到空闲链表 */
    ctx_free_list = ctx; /* 更新空闲链表头部 */
}

// 从内存池分配conn
static tcp_conn_t *alloc_conn(void) {
    if (!conn_free_list) {
        log_error("conn pool exhausted"); /* 记录内存池耗尽错误 */
        return NULL; /* 返回空指针 */
    }
    
    tcp_conn_t *conn = conn_free_list; /* 获取空闲conn */
    conn_free_list = conn->pool_next; /* 更新空闲链表 */
    
    conn->nbytes = 0; /* 初始化已接收字节数 */
    
    return conn; /* 返回分配的conn */
}

// 归还conn到内存池
static void free_conn_to_pool(tcp_conn_t *conn) {
    conn->pool_next = conn_free_list; /* 链接到空闲链表 */
    conn_free_list = conn; /* 更新空闲链表头部 */
}

/* ======================== global-vars ======================== */

enum {
    FLAG_IPV6_V6ONLY = 1 << 0, /* 启用IPv6专用模式 */
    FLAG_REUSE_PORT  = 1 << 1, /* 启用端口复用 */
    FLAG_VERBOSE     = 1 << 2, /* 启用详细日志 */
    FLAG_LOCAL_ADDR  = 1 << 3, /* 使用本地TCP地址 */
    FLAG_USE_BUILTIN = 1 << 4, /* 使用内置DNS服务器 */
};

#define has_flag(flag) (g_flags & (flag)) /* 检查标志位 */
#define add_flag(flag) (g_flags |= (flag)) /* 设置标志位 */

static uint8_t g_flags = 0; /* 存储全局标志位 */
static uint8_t g_syn_cnt = 0; /* 存储TCP同步重试次数 */

/* udp listen */
static int          g_listen_fd               = -1; /* 存储UDP监听文件描述符 */
static char         g_listen_ipstr[IP6STRLEN] = {0}; /* 存储UDP监听IP地址 */
static uint16_t     g_listen_port             = 0; /* 存储UDP监听端口 */
static union skaddr g_listen_skaddr           = {0}; /* 存储UDP监听地址结构 */

/* tcp local address [optional] */
static char         g_local_ipstr[IP6STRLEN] = {0}; /* 存储本地TCP IP地址 */
static uint16_t     g_local_port             = 0; /* 存储本地TCP端口 */
static union skaddr g_local_skaddr           = {0}; /* 存储本地TCP地址结构 */

/* 内置的DNS服务器 */
static const char *g_builtin_servers[] = {
    "8.8.8.8#53",        /* Google DNS */
    "1.1.1.1#53",        /* Cloudflare DNS */
    "114.114.114.114#53", /* 114 DNS */
    "223.5.5.5#53",      /* 阿里DNS */
    "119.29.29.29#53",   /* 腾讯DNS */
};

/* 服务器列表 */
static server_info_t g_servers[MAX_SERVERS]; /* 存储服务器信息数组 */
static int g_server_count = 0; /* 存储服务器数量 */

static void udp_recvmsg_cb(evloop_t *evloop, evio_t *watcher, int events); /* 前向声明UDP接收回调 */
static void tcp_connect_cb(evloop_t *evloop, evio_t *watcher, int events); /* 前向声明TCP连接回调 */
static void tcp_sendmsg_cb(evloop_t *evloop, evio_t *watcher, int events); /* 前向声明TCP发送回调 */
static void tcp_recvmsg_cb(evloop_t *evloop, evio_t *watcher, int events); /* 前向声明TCP接收回调 */

// 打印帮助信息
static void print_help(void) {
    printf("usage: dns2tcp-plus <-L listen> [options...]\n"
           " -L <ip[#port]>          udp listen address, port default to 53\n"
           " -R <ip[#port]>          tcp remote address, port default to 53 (can specify multiple)\n"
           " -l <ip[#port]>          tcp local address, port default to 0\n"
           " -s <syncnt>             set TCP_SYNCNT option for tcp socket\n"
           " -6                      set IPV6_V6ONLY option for udp socket\n"
           " -r                      set SO_REUSEPORT option for udp socket\n"
           " -b                      disable builtin servers\n"
           " -v                      print verbose log, used for debugging\n"
           " -V                      print version number of dns2tcp-plus and exit\n"
           " -h                      print help information of dns2tcp-plus and exit\n"
    );
}

enum addr_type {
    ADDR_UDP_LISTEN, /* UDP监听地址类型 */
    ADDR_TCP_REMOTE, /* TCP远程地址类型 */
    ADDR_TCP_LOCAL,  /* TCP本地地址类型 */
};

// 检查服务器是否已存在
static bool server_exists(const char *ipstr, uint16_t port) {
    for (int i = 0; i < g_server_count; i++) {
        if (g_servers[i].port == port && strcmp(g_servers[i].ipstr, ipstr) == 0) {
            return true; /* 返回服务器已存在 */
        }
    }
    return false; /* 返回服务器不存在 */
}

// 添加服务器到列表
static void add_server(const char *ipstr, uint16_t port, int family) {
    if (g_server_count >= MAX_SERVERS) {
        log_warning("server list is full, ignore %s#%hu", ipstr, port); /* 记录服务器列表已满 */
        return;
    }
    
    if (server_exists(ipstr, port)) {
        log_verbose("server %s#%hu already exists, skip", ipstr, port); /* 记录服务器已存在 */
        return;
    }
    
    server_info_t *server = &g_servers[g_server_count]; /* 获取服务器信息结构 */
    strcpy(server->ipstr, ipstr); /* 复制IP地址 */
    server->port = port; /* 设置端口号 */
    skaddr_from_text(&server->skaddr, family, ipstr, port); /* 转换地址结构 */
    g_server_count++; /* 增加服务器计数 */
    
    log_info("add tcp remote addr: %s#%hu", ipstr, port); /* 记录添加服务器 */
}

// 解析地址字符串
static void parse_addr(const char *addr, enum addr_type addr_type) {
    const char *end = addr + strlen(addr); /* 获取地址字符串末尾 */
    const char *sep = strchr(addr, '#') ?: end; /* 查找端口分隔符 */

    const char *ipstart = addr; /* 获取IP起始位置 */
    int iplen = sep - ipstart; /* 计算IP长度 */

    const char *portstart = sep + 1; /* 获取端口起始位置 */
    int portlen = (sep < end) ? end - portstart : -1; /* 计算端口长度 */

    char ipstr[IP6STRLEN]; /* 定义IP地址缓冲区 */
    if (iplen >= IP6STRLEN) goto err; /* 检查IP长度是否超限 */

    memcpy(ipstr, ipstart, iplen); /* 复制IP地址 */
    ipstr[iplen] = 0; /* 添加终止符 */

    int family = get_ipstr_family(ipstr); /* 获取地址族 */
    if (family == -1) goto err; /* 检查地址族是否有效 */

    uint16_t port = addr_type != ADDR_TCP_LOCAL ? 53 : 0; /* 设置默认端口 */
    if (portlen >= 0 && (port = strtoul(portstart, NULL, 10)) == 0 && addr_type != ADDR_TCP_LOCAL) goto err; /* 解析端口号 */

    switch (addr_type) {
        case ADDR_UDP_LISTEN:
            strcpy(g_listen_ipstr, ipstr); /* 复制UDP监听IP */
            g_listen_port = port; /* 设置UDP监听端口 */
            skaddr_from_text(&g_listen_skaddr, family, ipstr, port); /* 转换UDP监听地址 */
            break;
        case ADDR_TCP_REMOTE:
            add_server(ipstr, port, family); /* 添加远程服务器 */
            break;
        case ADDR_TCP_LOCAL:
            strcpy(g_local_ipstr, ipstr); /* 复制本地TCP IP */
            g_local_port = port; /* 设置本地TCP端口 */
            skaddr_from_text(&g_local_skaddr, family, ipstr, port); /* 转换本地TCP地址 */
            break;
    }

    return;

err:
    const char *type; /* 定义地址类型字符串 */
    switch (addr_type) {
        case ADDR_UDP_LISTEN:
            type = "udp_listen"; /* 设置UDP监听类型 */
            break;
        case ADDR_TCP_REMOTE:
            type = "tcp_remote"; /* 设置TCP远程类型 */
            break;
        case ADDR_TCP_LOCAL:
            type = "tcp_local"; /* 设置TCP本地类型 */
            break;
    }

    printf("invalid %s address: '%s'\n", type, addr); /* 打印无效地址错误 */
    print_help(); /* 打印帮助信息 */
    exit(1); /* 退出程序 */
}

// 初始化内置DNS服务器
static void init_builtin_servers(void) {
    log_info("adding builtin DNS servers"); /* 记录添加内置服务器 */
    for (size_t i = 0; i < sizeof(g_builtin_servers) / sizeof(g_builtin_servers[0]); i++) {
        parse_addr(g_builtin_servers[i], ADDR_TCP_REMOTE); /* 解析内置服务器地址 */
    }
}

// 解析命令行参数
static void parse_opt(int argc, char *argv[]) {
    char opt_listen_addr[IP6STRLEN + PORTSTRLEN] = {0}; /* 定义监听地址缓冲区 */
    bool disable_builtin = false; /* 标记是否禁用内置服务器 */

    opterr = 0; /* 禁用getopt错误输出 */
    int shortopt; /* 存储选项字符 */
    const char *optstr = "L:R:l:s:6rbvVh"; /* 定义选项字符串 */
    while ((shortopt = getopt(argc, argv, optstr)) != -1) {
        switch (shortopt) {
            case 'L':
                if (strlen(optarg) + 1 > IP6STRLEN + PORTSTRLEN) {
                    printf("invalid udp listen addr: %s\n", optarg); /* 打印无效UDP监听地址 */
                    goto err;
                }
                strcpy(opt_listen_addr, optarg); /* 复制监听地址 */
                break;
            case 'R':
                if (strlen(optarg) + 1 > IP6STRLEN + PORTSTRLEN) {
                    printf("invalid tcp remote addr: %s\n", optarg); /* 打印无效TCP远程地址 */
                    goto err;
                }
                parse_addr(optarg, ADDR_TCP_REMOTE); /* 解析TCP远程地址 */
                break;
            case 'l':
                if (strlen(optarg) + 1 > IP6STRLEN + PORTSTRLEN) {
                    printf("invalid tcp local addr: %s\n", optarg); /* 打印无效TCP本地地址 */
                    goto err;
                }
                parse_addr(optarg, ADDR_TCP_LOCAL); /* 解析TCP本地地址 */
                add_flag(FLAG_LOCAL_ADDR); /* 设置本地地址标志 */
                break;
            case 's':
                g_syn_cnt = strtoul(optarg, NULL, 10); /* 解析TCP同步重试次数 */
                if (g_syn_cnt == 0) {
                    printf("invalid tcp syn cnt: %s\n", optarg); /* 打印无效同步次数 */
                    goto err;
                }
                break;
            case '6':
                add_flag(FLAG_IPV6_V6ONLY); /* 设置IPv6专用标志 */
                break;
            case 'r':
                add_flag(FLAG_REUSE_PORT); /* 设置端口复用标志 */
                break;
            case 'b':
                disable_builtin = true; /* 禁用内置服务器 */
                break;
            case 'v':
                add_flag(FLAG_VERBOSE); /* 设置详细日志标志 */
                break;
            case 'V':
                printf(DNS2TCP-PLUS_VER"\n"); /* 打印版本号 */
                exit(0); /* 退出程序 */
            case 'h':
                print_help(); /* 打印帮助信息 */
                exit(0); /* 退出程序 */
            case '?':
                if (!strchr(optstr, optopt)) {
                    printf("unknown option '-%c'\n", optopt); /* 打印未知选项 */
                } else {
                    printf("missing optval '-%c'\n", optopt); /* 打印缺少选项值 */
                }
                goto err;
        }
    }

    if (strlen(opt_listen_addr) == 0) {
        printf("missing option: '-L'\n"); /* 打印缺少监听地址选项 */
        goto err;
    }

    parse_addr(opt_listen_addr, ADDR_UDP_LISTEN); /* 解析UDP监听地址 */

    if (!disable_builtin) {
        add_flag(FLAG_USE_BUILTIN); /* 设置使用内置服务器标志 */
        init_builtin_servers(); /* 初始化内置服务器 */
    }

    if (g_server_count == 0) {
        printf("no valid remote servers (use -R to add servers or remove -b to use builtin servers)\n"); /* 打印无有效服务器错误 */
        goto err;
    }

    return;

err:
    print_help(); /* 打印帮助信息 */
    exit(1); /* 退出程序 */
}

// 创建socket并设置选项
static int create_socket(int family, int type) {
    const char *err_op = NULL; /* 存储错误操作名称 */

    int fd = socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0); /* 创建非阻塞socket */
    if (fd < 0) {
        err_op = "create_socket"; /* 设置错误操作 */
        goto out;
    }

    const int opt = 1; /* 定义socket选项值 */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        err_op = "set_reuseaddr"; /* 设置错误操作 */
        goto out;
    }

    if (type == SOCK_DGRAM) {
        if (has_flag(FLAG_REUSE_PORT) && setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
            err_op = "set_reuseport"; /* 设置错误操作 */
            goto out;
        }
        if (family == AF_INET6 && has_flag(FLAG_IPV6_V6ONLY) && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
            err_op = "set_ipv6only"; /* 设置错误操作 */
            goto out;
        }
    } else {
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
            err_op = "set_tcp_nodelay"; /* 设置错误操作 */
            goto out;
        }
        const int syn_cnt = g_syn_cnt; /* 获取同步重试次数 */
        if (syn_cnt && setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &syn_cnt, sizeof(syn_cnt)) < 0) {
            err_op = "set_tcp_syncnt"; /* 设置错误操作 */
            goto out;
        }
    }

out:
    if (err_op)
        log_error("%s(fd:%d, family:%d, type:%d) failed: %m", err_op, fd, family, type); /* 记录socket错误 */
    return fd; /* 返回文件描述符 */
}

// 主函数，初始化程序并启动事件循环
int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN); /* 忽略SIGPIPE信号 */
    setvbuf(stdout, NULL, _IOLBF, 256); /* 设置行缓冲输出 */
    parse_opt(argc, argv); /* 解析命令行参数 */

    init_ctx_pool(); /* 初始化ctx内存池 */
    init_conn_pool(); /* 初始化conn内存池 */

    log_info("udp listen addr: %s#%hu", g_listen_ipstr, g_listen_port); /* 记录UDP监听地址 */
    log_info("total %d tcp remote servers", g_server_count); /* 记录远程服务器数量 */
    if (has_flag(FLAG_USE_BUILTIN)) log_info("builtin servers enabled"); /* 记录启用内置服务器 */
    if (has_flag(FLAG_LOCAL_ADDR)) log_info("tcp local addr: %s#%hu", g_local_ipstr, g_local_port); /* 记录本地TCP地址 */
    if (g_syn_cnt) log_info("enable TCP_SYNCNT:%hhu sockopt", g_syn_cnt); /* 记录TCP同步重试次数 */
    if (has_flag(FLAG_IPV6_V6ONLY)) log_info("enable IPV6_V6ONLY sockopt"); /* 记录IPv6专用选项 */
    if (has_flag(FLAG_REUSE_PORT)) log_info("enable SO_REUSEPORT sockopt"); /* 记录端口复用选项 */
    log_verbose("print the verbose log"); /* 记录详细日志 */

    g_listen_fd = create_socket(skaddr_family(&g_listen_skaddr), SOCK_DGRAM); /* 创建UDP监听socket */
    if (g_listen_fd < 0)
        return 1; /* 返回错误码 */

    if (bind(g_listen_fd, &g_listen_skaddr.sa, skaddr_len(&g_listen_skaddr)) < 0) {
        log_error("bind udp address: %m"); /* 记录绑定错误 */
        return 1; /* 返回错误码 */
    }

    evloop_t *evloop = ev_default_loop(0); /* 初始化事件循环 */

    evio_t watcher; /* 定义事件监视器 */
    ev_io_init(&watcher, udp_recvmsg_cb, g_listen_fd, EV_READ); /* 初始化UDP接收事件 */
    ev_io_start(evloop, &watcher); /* 启动UDP接收事件 */

    return ev_run(evloop, 0); /* 运行事件循环 */
}

// 释放单个TCP连接
static void free_tcp_conn(tcp_conn_t *conn, evloop_t *evloop) {
    if (conn) {
        ev_io_stop(evloop, &conn->watcher); /* 停止事件监视 */
        close(conn->watcher.fd); /* 关闭文件描述符 */
        free_conn_to_pool(conn); /* 归还连接到内存池 */
    }
}

// 释放context及其所有连接
static void free_ctx(ctx_t *ctx, evloop_t *evloop) {
    for (int i = 0; i < ctx->conn_count; i++) {
        if (ctx->connections[i]) {
            free_tcp_conn(ctx->connections[i], evloop); /* 释放TCP连接 */
            ctx->connections[i] = NULL; /* 清空连接指针 */
        }
    }
    free_ctx_to_pool(ctx); /* 归还ctx到内存池 */
}

// 发送响应并清理资源
static void send_response_and_cleanup(ctx_t *ctx, evloop_t *evloop, 
                                      const void *data, size_t len) {
    if (ctx->response_sent) {
        return; /* 跳过已发送的响应 */
    }
    
    ctx->response_sent = true; /* 标记响应已发送 */
    
    ssize_t nsend = sendto(g_listen_fd, data, len, 0, 
                           &ctx->srcaddr.sa, skaddr_len(&ctx->srcaddr)); /* 发送UDP响应 */
    
    if (nsend < 0 || has_flag(FLAG_VERBOSE)) {
        char ip[IP6STRLEN]; /* 定义IP地址缓冲区 */
        uint16_t port; /* 定义端口号 */
        skaddr_to_text(&ctx->srcaddr, ip, &port); /* 转换客户端地址 */
        if (nsend < 0)
            log_warning("send to %s#%hu: %m", ip, port); /* 记录发送错误 */
        else
            log_info("send to %s#%hu, nsend:%zd", ip, port, nsend); /* 记录发送成功 */
    }
    
    free_ctx(ctx, evloop); /* 释放context资源 */
}

// 处理UDP接收事件
static void udp_recvmsg_cb(evloop_t *evloop, evio_t *watcher __unused, int events __unused) {
    ctx_t *ctx = alloc_ctx(); /* 分配ctx */
    if (!ctx) {
        char dummy[DNS_MSGSZ]; /* 定义临时缓冲区 */
        recvfrom(g_listen_fd, dummy, DNS_MSGSZ, 0, NULL, NULL); /* 丢弃请求 */
        return;
    }

    ssize_t nrecv = recvfrom(g_listen_fd, (void *)ctx->query_buffer + 2, DNS_MSGSZ, 0, 
                             &ctx->srcaddr.sa, &(socklen_t){sizeof(ctx->srcaddr)}); /* 接收UDP数据 */
    if (nrecv < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            log_warning("recv from udp socket: %m"); /* 记录接收错误 */
        goto free_ctx;
    }

    if (has_flag(FLAG_VERBOSE)) {
        char ip[IP6STRLEN]; /* 定义IP地址缓冲区 */
        uint16_t port; /* 定义端口号 */
        skaddr_to_text(&ctx->srcaddr, ip, &port); /* 转换客户端地址 */
        log_info("recv from %s#%hu, nrecv:%zd", ip, port, nrecv); /* 记录接收成功 */
    }

    uint16_t *p_msglen = (void *)ctx->query_buffer; /* 获取消息长度指针 */
    *p_msglen = htons(nrecv); /* 设置消息长度 */
    ctx->query_len = nrecv; /* 存储消息长度 */

    for (int i = 0; i < g_server_count; i++) {
        tcp_conn_t *conn = alloc_conn(); /* 分配TCP连接 */
        if (!conn) {
            log_warning("conn pool exhausted"); /* 记录连接池耗尽 */
            continue;
        }
        
        conn->server_idx = i; /* 设置服务器索引 */
        conn->parent_ctx = ctx; /* 设置父context */
        
        int fd = create_socket(skaddr_family(&g_servers[i].skaddr), SOCK_STREAM); /* 创建TCP socket */
        if (fd < 0) {
            free_conn_to_pool(conn); /* 归还连接 */
            continue;
        }

        if (has_flag(FLAG_LOCAL_ADDR) && 
            bind(fd, &g_local_skaddr.sa, skaddr_len(&g_local_skaddr)) < 0) {
            log_warning("bind tcp address: %m"); /* 记录绑定错误 */
            close(fd); /* 关闭文件描述符 */
            free_conn_to_pool(conn); /* 归还连接 */
            continue;
        }

        if (connect(fd, &g_servers[i].skaddr.sa, skaddr_len(&g_servers[i].skaddr)) < 0 && 
            errno != EINPROGRESS) {
            log_warning("connect to %s#%hu: %m", g_servers[i].ipstr, g_servers[i].port); /* 记录连接错误 */
            close(fd); /* 关闭文件描述符 */
            free_conn_to_pool(conn); /* 归还连接 */
            continue;
        }
        
        log_verbose("try to connect to %s#%hu", g_servers[i].ipstr, g_servers[i].port); /* 记录尝试连接 */

        ev_io_init(&conn->watcher, tcp_connect_cb, fd, EV_WRITE); /* 初始化TCP连接事件 */
        ev_io_start(evloop, &conn->watcher); /* 启动TCP连接事件 */
        
        ctx->connections[ctx->conn_count++] = conn; /* 添加连接到数组 */
        ctx->active_conns++; /* 增加活跃连接计数 */
    }

    if (ctx->active_conns == 0) {
        log_error("failed to create any tcp connections"); /* 记录无连接创建 */
        goto free_ctx;
    }

    return;

free_ctx:
    free_ctx(ctx, evloop); /* 释放context */
}

// 处理TCP连接事件
static void tcp_connect_cb(evloop_t *evloop, evio_t *watcher, int events __unused) {
    tcp_conn_t *conn = container_of(watcher, tcp_conn_t, watcher); /* 获取TCP连接 */
    ctx_t *ctx = conn->parent_ctx; /* 获取父context */
    server_info_t *server = &g_servers[conn->server_idx]; /* 获取服务器信息 */

    if (getsockopt(watcher->fd, SOL_SOCKET, SO_ERROR, &errno, &(socklen_t){sizeof(errno)}) < 0 || errno) {
        log_warning("connect to %s#%hu: %m", server->ipstr, server->port); /* 记录连接错误 */
        ctx->active_conns--; /* 减少活跃连接计数 */
        
        for (int i = 0; i < ctx->conn_count; i++) {
            if (ctx->connections[i] == conn) {
                ctx->connections[i] = NULL; /* 移除连接 */
                break;
            }
        }
        
        free_tcp_conn(conn, evloop); /* 释放TCP连接 */
        
        if (ctx->active_conns == 0 && !ctx->response_sent) {
            free_ctx(ctx, evloop); /* 释放context */
        }
        return;
    }
    
    log_verbose("connect to %s#%hu succeed", server->ipstr, server->port); /* 记录连接成功 */

    conn->nbytes = 0; /* 初始化已发送字节数 */
    ev_set_cb(watcher, tcp_sendmsg_cb); /* 设置发送回调 */
    ev_invoke(evloop, watcher, EV_WRITE); /* 触发发送事件 */
}

// 处理TCP发送事件
static void tcp_sendmsg_cb(evloop_t *evloop, evio_t *watcher, int events __unused) {
    tcp_conn_t *conn = container_of(watcher, tcp_conn_t, watcher); /* 获取TCP连接 */
    ctx_t *ctx = conn->parent_ctx; /* 获取父context */
    server_info_t *server = &g_servers[conn->server_idx]; /* 获取服务器信息 */
    
    if (ctx->response_sent) {
        ctx->active_conns--; /* 减少活跃连接计数 */
        for (int i = 0; i < ctx->conn_count; i++) {
            if (ctx->connections[i] == conn) {
                ctx->connections[i] = NULL; /* 移除连接 */
                break;
            }
        }
        free_tcp_conn(conn, evloop); /* 释放TCP连接 */
        return;
    }

    uint16_t datalen = 2 + ctx->query_len; /* 计算发送数据长度 */
    
    ssize_t nsend = send(watcher->fd, (void *)ctx->query_buffer + conn->nbytes, 
                         datalen - conn->nbytes, 0); /* 发送数据 */
    if (nsend < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return; /* 忽略非阻塞错误 */
        log_warning("send to %s#%hu: %m", server->ipstr, server->port); /* 记录发送错误 */
        
        ctx->active_conns--; /* 减少活跃连接计数 */
        for (int i = 0; i < ctx->conn_count; i++) {
            if (ctx->connections[i] == conn) {
                ctx->connections[i] = NULL; /* 移除连接 */
                break;
            }
        }
        free_tcp_conn(conn, evloop); /* 释放TCP连接 */
        
        if (ctx->active_conns == 0 && !ctx->response_sent) {
            free_ctx(ctx, evloop); /* 释放context */
        }
        return;
    }
    
    log_verbose("send to %s#%hu, nsend:%zd", server->ipstr, server->port, nsend); /* 记录发送成功 */

    conn->nbytes += nsend; /* 更新已发送字节数 */
    if (conn->nbytes >= datalen) {
        conn->nbytes = 0; /* 重置已接收字节数 */
        ev_io_stop(evloop, watcher); /* 停止当前事件 */
        ev_io_init(watcher, tcp_recvmsg_cb, watcher->fd, EV_READ); /* 初始化接收事件 */
        ev_io_start(evloop, watcher); /* 启动接收事件 */
    }
}

// 处理TCP接收事件
static void tcp_recvmsg_cb(evloop_t *evloop, evio_t *watcher, int events __unused) {
    tcp_conn_t *conn = container_of(watcher, tcp_conn_t, watcher); /* 获取TCP连接 */
    ctx_t *ctx = conn->parent_ctx; /* 获取父context */
    server_info_t *server = &g_servers[conn->server_idx]; /* 获取服务器信息 */
    
    if (ctx->response_sent) {
        ctx->active_conns--; /* 减少活跃连接计数 */
        for (int i = 0; i < ctx->conn_count; i++) {
            if (ctx->connections[i] == conn) {
                ctx->connections[i] = NULL; /* 移除连接 */
                break;
            }
        }
        free_tcp_conn(conn, evloop); /* 释放TCP连接 */
        return;
    }

    void *buffer = conn->buffer; /* 获取接收缓冲区 */
    
    ssize_t nrecv = recv(watcher->fd, buffer + conn->nbytes, 
                         2 + DNS_MSGSZ - conn->nbytes, 0); /* 接收数据 */
    if (nrecv < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return; /* 忽略非阻塞错误 */
        log_warning("recv from %s#%hu: %m", server->ipstr, server->port); /* 记录接收错误 */
        goto cleanup_conn;
    }
    
    if (nrecv == 0) {
        log_warning("recv from %s#%hu: connection is closed", server->ipstr, server->port); /* 记录连接关闭 */
        goto cleanup_conn;
    }
    
    log_verbose("recv from %s#%hu, nrecv:%zd", server->ipstr, server->port, nrecv); /* 记录接收成功 */

    conn->nbytes += nrecv; /* 更新已接收字节数 */
    
    uint16_t msglen; /* 定义消息长度 */
    if (conn->nbytes < 2 || conn->nbytes < 2 + (msglen = ntohs(*(uint16_t *)buffer))) {
        return; /* 等待完整数据 */
    }
    
    log_info("got response from %s#%hu (winner)", server->ipstr, server->port); /* 记录收到响应 */
    
    send_response_and_cleanup(ctx, evloop, buffer + 2, msglen); /* 发送响应并清理 */
    return;

cleanup_conn:
    ctx->active_conns--; /* 减少活跃连接计数 */
    for (int i = 0; i < ctx->conn_count; i++) {
        if (ctx->connections[i] == conn) {
            ctx->connections[i] = NULL; /* 移除连接 */
            break;
        }
    }
    free_tcp_conn(conn, evloop); /* 释放TCP连接 */
    
    if (ctx->active_conns == 0 && !ctx->response_sent) {
        free_ctx(ctx, evloop); /* 释放context */
    }
}
