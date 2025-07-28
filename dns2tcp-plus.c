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

#define DNS2TCP_PLUS_VER "dns2tcp-plus v1.3.0"

#ifndef IPV6_V6ONLY
  #define IPV6_V6ONLY 26
#endif

#ifndef SO_REUSEPORT
  #define SO_REUSEPORT 15
#endif

#ifndef TCP_SYNCNT
  #define TCP_SYNCNT 7
#endif

#define IP4STRLEN INET_ADDRSTRLEN
#define IP6STRLEN INET6_ADDRSTRLEN
#define PORTSTRLEN 6
#define DNS_MSGSZ 1472
#define MAX_SERVERS 8

/* DNS协议相关定义 */
#define DNS_HEADER_SIZE 12
#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28
#define DNS_CLASS_IN 1
#define DNS_MAX_NAME_LEN 255
#define DNS_COMPRESSION_MASK 0xC0

/* 工具宏定义 */
#define __unused __attribute__((unused))
#define alignto(alignment) __attribute__((aligned(alignment)))

#define container_of(p_field, struct_type, field_name) ( \
    (struct_type *) ((void *)(p_field) - offsetof(struct_type, field_name)) \
)

/* 日志输出宏 */
#define log_error(fmt, args...) \
    fprintf(stderr, "dns2tcp-plus: " fmt "\n", ##args)

#define log_verbose(fmt, args...) do {} while(0)
#define log_info(fmt, args...) do {} while(0)
#define log_warning log_error

/* Socket地址结构 */
union skaddr {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

#define skaddr_family(addr) ((addr)->sa.sa_family)
#define skaddr_is_sin(addr) (skaddr_family(addr) == AF_INET)
#define skaddr_is_sin6(addr) (skaddr_family(addr) == AF_INET6)
#define skaddr_len(addr) (skaddr_is_sin(addr) ? sizeof((addr)->sin) : sizeof((addr)->sin6))

/* 转换文本地址为socket地址结构 */
static void skaddr_from_text(union skaddr *addr, int family, const char *ipstr, uint16_t port) {
    if (family == AF_INET) {
        addr->sin.sin_family = AF_INET;
        inet_pton(AF_INET, ipstr, &addr->sin.sin_addr);
        addr->sin.sin_port = htons(port);
    } else {
        addr->sin6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, ipstr, &addr->sin6.sin6_addr);
        addr->sin6.sin6_port = htons(port);
    }
}

/* 转换socket地址结构为文本地址 */
static void skaddr_to_text(const union skaddr *addr, char *ipstr, uint16_t *port) {
    if (skaddr_is_sin(addr)) {
        inet_ntop(AF_INET, &addr->sin.sin_addr, ipstr, IP4STRLEN);
        *port = ntohs(addr->sin.sin_port);
    } else {
        inet_ntop(AF_INET6, &addr->sin6.sin6_addr, ipstr, IP6STRLEN);
        *port = ntohs(addr->sin6.sin6_port);
    }
}

/* 检测IP字符串的地址族类型 */
static int get_ipstr_family(const char *ipstr) {
    char tmp[16];
    if (!ipstr)
        return -1;
    if (inet_pton(AF_INET, ipstr, &tmp) == 1)
        return AF_INET;
    if (inet_pton(AF_INET6, ipstr, &tmp) == 1)
        return AF_INET6;
    return -1;
}

/* 服务器信息结构体 */
typedef struct {
    char         ipstr[IP6STRLEN];
    uint16_t     port;
    union skaddr skaddr;
} server_info_t;

/* TCP连接结构体 */
struct ctx;

typedef struct tcp_conn {
    evio_t       watcher;
    int          server_idx;
    struct ctx  *parent_ctx;
    char         buffer[2 + DNS_MSGSZ] alignto(__alignof__(uint16_t));
    uint16_t     nbytes;
    struct tcp_conn *pool_next;
} tcp_conn_t;

/* 请求上下文结构体 */
typedef struct ctx {
    union skaddr srcaddr;
    char         query_buffer[2 + DNS_MSGSZ] alignto(__alignof__(uint16_t));
    uint16_t     query_len;
    tcp_conn_t  *connections[MAX_SERVERS];
    int          conn_count;
    bool         response_sent;
    int          active_conns;
    struct ctx  *pool_next;
} ctx_t;

/* 内存池配置 */
#define CTX_POOL_SIZE 128
#define CONN_POOL_SIZE 1024

static ctx_t ctx_pool[CTX_POOL_SIZE];
static ctx_t *ctx_free_list = NULL;
static int ctx_pool_initialized = 0;

static tcp_conn_t conn_pool[CONN_POOL_SIZE];
static tcp_conn_t *conn_free_list = NULL;
static int conn_pool_initialized = 0;

/* 初始化上下文内存池 */
static void init_ctx_pool(void) {
    if (ctx_pool_initialized) return;
    
    for (int i = 0; i < CTX_POOL_SIZE - 1; i++) {
        ctx_pool[i].pool_next = &ctx_pool[i + 1];
    }
    ctx_pool[CTX_POOL_SIZE - 1].pool_next = NULL;
    ctx_free_list = &ctx_pool[0];
    ctx_pool_initialized = 1;
}

/* 初始化连接内存池 */
static void init_conn_pool(void) {
    if (conn_pool_initialized) return;
    
    for (int i = 0; i < CONN_POOL_SIZE - 1; i++) {
        conn_pool[i].pool_next = &conn_pool[i + 1];
    }
    conn_pool[CONN_POOL_SIZE - 1].pool_next = NULL;
    conn_free_list = &conn_pool[0];
    conn_pool_initialized = 1;
}

/* 分配上下文对象 */
static ctx_t *alloc_ctx(void) {
    if (!ctx_free_list) {
        log_error("ctx pool exhausted");
        return NULL;
    }
    
    ctx_t *ctx = ctx_free_list;
    ctx_free_list = ctx->pool_next;
    
    ctx->conn_count = 0;
    ctx->response_sent = false;
    ctx->active_conns = 0;
    memset(ctx->connections, 0, sizeof(ctx->connections));
    
    return ctx;
}

/* 释放上下文对象到内存池 */
static void free_ctx_to_pool(ctx_t *ctx) {
    ctx->pool_next = ctx_free_list;
    ctx_free_list = ctx;
}

/* 分配连接对象 */
static tcp_conn_t *alloc_conn(void) {
    if (!conn_free_list) {
        log_error("conn pool exhausted");
        return NULL;
    }
    
    tcp_conn_t *conn = conn_free_list;
    conn_free_list = conn->pool_next;
    
    conn->nbytes = 0;
    
    return conn;
}

/* 释放连接对象到内存池 */
static void free_conn_to_pool(tcp_conn_t *conn) {
    conn->pool_next = conn_free_list;
    conn_free_list = conn;
}

/* 恶意IP地址过滤列表 */
static const char *g_bad_ipv4[] = {
    "0.0.0.0",
    "127.0.0.1",
    "10.10.10.10",
    "240.0.0.0",
    NULL
};

static const char *g_bad_ipv6[] = {
    "::",
    "::1",
    NULL
};

/* 预编译的二进制恶意IP列表 */
#define MAX_BAD_IPS 16
static struct in_addr g_bad_ipv4_bin[MAX_BAD_IPS];
static int g_bad_ipv4_count = 0;
static struct in6_addr g_bad_ipv6_bin[MAX_BAD_IPS];
static int g_bad_ipv6_count = 0;

/* 域名分流规则配置 */
#define MAX_DOMAIN_RULES 16
#define MAX_RULE_SERVERS 8

typedef struct {
    char suffix[64];
    int server_indices[MAX_RULE_SERVERS];
    int server_count;
} domain_rule_t;

static domain_rule_t g_domain_rules[MAX_DOMAIN_RULES];
static int g_domain_rule_count = 0;

/* 字符转小写查表 */
static const uint8_t g_lowercase_table[256] = {
    0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,
    16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,
    32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,
    48,  49,  50,  51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,
    64,  97,  98,  99,  100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 91,  92,  93,  94,  95,
    96,  97,  98,  99,  100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
    128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
    144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
    160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175,
    176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
    192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207,
    208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223,
    224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255
};

/* 提取DNS查询包中的域名 */
static int extract_domain_from_query(const uint8_t *data, size_t len, char *domain, size_t domain_size) {
    if (len < DNS_HEADER_SIZE + 1) {
        return -1;
    }
    
    const uint8_t *ptr = data + DNS_HEADER_SIZE;
    const uint8_t *end = data + len;
    size_t domain_len = 0;
    
    while (ptr < end && *ptr != 0) {
        if ((*ptr & DNS_COMPRESSION_MASK) == DNS_COMPRESSION_MASK) {
            return -1;
        }
        
        uint8_t label_len = *ptr;
        ptr++;
        
        if (ptr + label_len > end) {
            return -1;
        }
        
        if (domain_len + label_len + 1 >= domain_size) {
            return -1;
        }
        
        if (domain_len > 0) {
            domain[domain_len++] = '.';
        }
        
        memcpy(domain + domain_len, ptr, label_len);
        domain_len += label_len;
        ptr += label_len;
    }
    
    domain[domain_len] = '\0';
    
    /* 转换域名为小写 */
    for (size_t i = 0; i < domain_len; i++) {
        domain[i] = g_lowercase_table[(uint8_t)domain[i]];
    }
    
    return 0;
}

/* 跳过DNS名称字段(支持压缩指针) */
static const uint8_t* skip_dns_name(const uint8_t *ptr, const uint8_t *data, const uint8_t *end) {
    int jumps = 0;
    const uint8_t *save_ptr = NULL;
    
    while (ptr < end && *ptr != 0) {
        if ((*ptr & DNS_COMPRESSION_MASK) == DNS_COMPRESSION_MASK) {
            if (ptr + 1 >= end) return NULL;
            
            if (!save_ptr) save_ptr = ptr + 2;
            
            uint16_t offset = ntohs(*(uint16_t*)ptr) & 0x3FFF;
            ptr = data + offset;
            
            if (++jumps > 5 || ptr >= end) return NULL;
        } else {
            uint8_t label_len = *ptr;
            ptr += 1 + label_len;
        }
    }
    
    return save_ptr ? save_ptr : (ptr < end ? ptr + 1 : NULL);
}

/* 检测DNS响应是否包含恶意IP */
static bool is_bad_response(const uint8_t *data, size_t len) {
    if (len < DNS_HEADER_SIZE) {
        return false;
    }
    
    uint16_t flags = ntohs(*(uint16_t*)(data + 2));
    if ((flags & 0x8000) == 0) {
        return false;
    }
    
    uint16_t qdcount = ntohs(*(uint16_t*)(data + 4));
    uint16_t ancount = ntohs(*(uint16_t*)(data + 6));
    
    if (ancount == 0) {
        return false;
    }
    
    const uint8_t *ptr = data + DNS_HEADER_SIZE;
    const uint8_t *end = data + len;
    
    /* 跳过查询字段 */
    for (int i = 0; i < qdcount; i++) {
        ptr = skip_dns_name(ptr, data, end);
        if (!ptr || ptr + 4 > end) return false;
        ptr += 4;
    }
    
    /* 检查回答记录中的IP地址 */
    for (int i = 0; i < ancount && ptr < end; i++) {
        ptr = skip_dns_name(ptr, data, end);
        if (!ptr || ptr + 10 > end) break;
        
        uint16_t type = ntohs(*(uint16_t*)ptr);
        uint16_t rdlen = ntohs(*(uint16_t*)(ptr + 8));
        ptr += 10;
        
        if (ptr + rdlen > end) break;
        
        /* 检查A记录IPv4地址 */
        if (type == DNS_TYPE_A && rdlen == 4) {
            for (int j = 0; j < g_bad_ipv4_count; j++) {
                if (memcmp(ptr, &g_bad_ipv4_bin[j], 4) == 0) {
                    log_verbose("bad IPv4 detected");
                    return true;
                }
            }
        }
        /* 检查AAAA记录IPv6地址 */
        else if (type == DNS_TYPE_AAAA && rdlen == 16) {
            for (int j = 0; j < g_bad_ipv6_count; j++) {
                if (memcmp(ptr, &g_bad_ipv6_bin[j], 16) == 0) {
                    log_verbose("bad IPv6 detected");
                    return true;
                }
            }
        }
        
        ptr += rdlen;
    }
    
    return false;
}

/* 查找域名匹配的分流规则 */
static int find_domain_rule(const char *domain) {
    size_t domain_len = strlen(domain);
    
    for (int i = 0; i < g_domain_rule_count; i++) {
        size_t suffix_len = strlen(g_domain_rules[i].suffix);
        
        if (domain_len >= suffix_len) {
            const char *domain_suffix = domain + domain_len - suffix_len;
            if (strcmp(domain_suffix, g_domain_rules[i].suffix) == 0) {
                if (domain_len == suffix_len || domain[domain_len - suffix_len - 1] == '.') {
                    return i;
                }
            }
        }
    }
    
    return -1;
}

/* 全局标志位定义 */
enum {
    FLAG_IPV6_V6ONLY = 1 << 0,
    FLAG_REUSE_PORT  = 1 << 1,
    FLAG_VERBOSE     = 1 << 2,
    FLAG_LOCAL_ADDR  = 1 << 3,
    FLAG_USE_BUILTIN = 1 << 4,
};

#define has_flag(flag) (g_flags & (flag))
#define add_flag(flag) (g_flags |= (flag))

static uint8_t g_flags = 0;
static uint8_t g_syn_cnt = 0;

/* UDP监听配置 */
static int          g_listen_fd               = -1;
static char         g_listen_ipstr[IP6STRLEN] = {0};
static uint16_t     g_listen_port             = 0;
static union skaddr g_listen_skaddr           = {0};

/* TCP本地地址配置 */
static char         g_local_ipstr[IP6STRLEN] = {0};
static uint16_t     g_local_port             = 0;
static union skaddr g_local_skaddr           = {0};

/* 内置DNS服务器列表 */
static const char *g_builtin_servers[] = {
    "8.8.8.8#53",
    "1.1.1.1#53",
    "9.9.9.9#53",
};

/* 服务器配置数组 */
static server_info_t g_servers[MAX_SERVERS];
static int g_server_count = 0;

static void udp_recvmsg_cb(evloop_t *evloop, evio_t *watcher, int events);
static void tcp_connect_cb(evloop_t *evloop, evio_t *watcher, int events);
static void tcp_sendmsg_cb(evloop_t *evloop, evio_t *watcher, int events);
static void tcp_recvmsg_cb(evloop_t *evloop, evio_t *watcher, int events);

/* 打印程序帮助信息 */
static void print_help(void) {
    printf("usage: dns2tcp-plus <-L listen> [options...]\n"
           " -L <ip[#port]>          udp listen address, port default to 53\n"
           " -R <ip[#port]>          tcp remote address, port default to 53 (can specify multiple)\n"
           " -D <suffix:servers>     domain routing rule, e.g., -D \"cn:223.5.5.5,119.29.29.29\"\n"
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
    ADDR_UDP_LISTEN,
    ADDR_TCP_REMOTE,
    ADDR_TCP_LOCAL,
};

/* 检查服务器是否已存在于列表中 */
static bool server_exists(const char *ipstr, uint16_t port) {
    for (int i = 0; i < g_server_count; i++) {
        if (g_servers[i].port == port && strcmp(g_servers[i].ipstr, ipstr) == 0) {
            return true;
        }
    }
    return false;
}

/* 添加服务器到全局列表 */
static void add_server(const char *ipstr, uint16_t port, int family) {
    if (g_server_count >= MAX_SERVERS) {
        log_warning("server list is full, ignore %s#%hu", ipstr, port);
        return;
    }
    
    if (server_exists(ipstr, port)) {
        log_verbose("server %s#%hu already exists, skip", ipstr, port);
        return;
    }
    
    server_info_t *server = &g_servers[g_server_count];
    strcpy(server->ipstr, ipstr);
    server->port = port;
    skaddr_from_text(&server->skaddr, family, ipstr, port);
    g_server_count++;
    
    log_info("add tcp remote addr: %s#%hu", ipstr, port);
}

/* 查找服务器在列表中的索引 */
static int find_server_index(const char *ipstr, uint16_t port) {
    for (int i = 0; i < g_server_count; i++) {
        if (g_servers[i].port == port && strcmp(g_servers[i].ipstr, ipstr) == 0) {
            return i;
        }
    }
    return -1;
}

/* 解析地址字符串为IP和端口 */
static void parse_addr(const char *addr, enum addr_type addr_type) {
    const char *type;
    const char *end = addr + strlen(addr);
    const char *sep = strchr(addr, '#') ?: end;

    const char *ipstart = addr;
    int iplen = sep - ipstart;

    const char *portstart = sep + 1;
    int portlen = (sep < end) ? end - portstart : -1;

    char ipstr[IP6STRLEN];
    if (iplen >= IP6STRLEN) goto err;

    memcpy(ipstr, ipstart, iplen);
    ipstr[iplen] = 0;

    int family = get_ipstr_family(ipstr);
    if (family == -1) goto err;

    uint16_t port = addr_type != ADDR_TCP_LOCAL ? 53 : 0;
    if (portlen >= 0 && (port = strtoul(portstart, NULL, 10)) == 0 && addr_type != ADDR_TCP_LOCAL) goto err;

    switch (addr_type) {
        case ADDR_UDP_LISTEN:
            strcpy(g_listen_ipstr, ipstr);
            g_listen_port = port;
            skaddr_from_text(&g_listen_skaddr, family, ipstr, port);
            break;
        case ADDR_TCP_REMOTE:
            add_server(ipstr, port, family);
            break;
        case ADDR_TCP_LOCAL:
            strcpy(g_local_ipstr, ipstr);
            g_local_port = port;
            skaddr_from_text(&g_local_skaddr, family, ipstr, port);
            break;
    }

    return;

err:
    switch (addr_type) {
        case ADDR_UDP_LISTEN:
            type = "udp_listen";
            break;
        case ADDR_TCP_REMOTE:
            type = "tcp_remote";
            break;
        case ADDR_TCP_LOCAL:
            type = "tcp_local";
            break;
    }

    printf("invalid %s address: '%s'\n", type, addr);
    print_help();
    exit(1);
}

/* 解析域名分流规则字符串 */
static void parse_domain_rule(const char *rule) {
    if (g_domain_rule_count >= MAX_DOMAIN_RULES) {
        log_warning("domain rule list is full, ignore rule: %s", rule);
        return;
    }
    
    const char *colon = strchr(rule, ':');
    if (!colon || colon == rule || colon[1] == '\0') {
        printf("invalid domain rule format: '%s'\n", rule);
        printf("correct format: -D \"suffix:server1,server2\"\n");
        printf("example: -D \"cn:223.5.5.5,119.29.29.29\"\n");
        exit(1);
    }
    
    size_t suffix_len = colon - rule;
    if (suffix_len >= sizeof(g_domain_rules[0].suffix)) {
        printf("domain suffix too long: '%.*s'\n", (int)suffix_len, rule);
        exit(1);
    }
    
    domain_rule_t *domain_rule = &g_domain_rules[g_domain_rule_count];
    memcpy(domain_rule->suffix, rule, suffix_len);
    domain_rule->suffix[suffix_len] = '\0';
    
    /* 转换域名后缀为小写 */
    for (size_t i = 0; i < suffix_len; i++) {
        domain_rule->suffix[i] = g_lowercase_table[(uint8_t)domain_rule->suffix[i]];
    }
    
    /* 解析服务器列表 */
    const char *servers = colon + 1;
    domain_rule->server_count = 0;
    
    while (*servers && domain_rule->server_count < MAX_RULE_SERVERS) {
        while (*servers == ' ') servers++;
        if (*servers == '\0') break;
        
        const char *comma = strchr(servers, ',');
        if (!comma) comma = servers + strlen(servers);
        
        size_t server_len = comma - servers;
        char server_addr[IP6STRLEN + PORTSTRLEN];
        
        if (server_len >= sizeof(server_addr)) {
            printf("server address too long in rule: %s\n", rule);
            exit(1);
        }
        
        memcpy(server_addr, servers, server_len);
        server_addr[server_len] = '\0';
        
        while (server_len > 0 && server_addr[server_len - 1] == ' ') {
            server_addr[--server_len] = '\0';
        }
        
        parse_addr(server_addr, ADDR_TCP_REMOTE);
        
        const char *sep = strchr(server_addr, '#');
        char ipstr[IP6STRLEN];
        uint16_t port = 53;
        
        if (sep) {
            size_t iplen = sep - server_addr;
            memcpy(ipstr, server_addr, iplen);
            ipstr[iplen] = '\0';
            port = strtoul(sep + 1, NULL, 10);
        } else {
            strcpy(ipstr, server_addr);
        }
        
        int idx = find_server_index(ipstr, port);
        if (idx >= 0) {
            domain_rule->server_indices[domain_rule->server_count++] = idx;
        }
        
        servers = (*comma == ',') ? comma + 1 : comma;
    }
    
    if (domain_rule->server_count == 0) {
        printf("no valid servers in domain rule: %s\n", rule);
        exit(1);
    }
    
    g_domain_rule_count++;
    log_info("add domain rule: %s -> %d servers", domain_rule->suffix, domain_rule->server_count);
}

/* 初始化内置DNS服务器列表 */
static void init_builtin_servers(void) {
    log_info("adding builtin DNS servers");
    for (size_t i = 0; i < sizeof(g_builtin_servers) / sizeof(g_builtin_servers[0]); i++) {
        parse_addr(g_builtin_servers[i], ADDR_TCP_REMOTE);
    }
}

/* 初始化恶意IP过滤列表 */
static void init_bad_ips(void) {
    for (int i = 0; g_bad_ipv4[i] && g_bad_ipv4_count < MAX_BAD_IPS; i++) {
        if (inet_pton(AF_INET, g_bad_ipv4[i], &g_bad_ipv4_bin[g_bad_ipv4_count]) == 1) {
            g_bad_ipv4_count++;
        }
    }
    
    for (int i = 0; g_bad_ipv6[i] && g_bad_ipv6_count < MAX_BAD_IPS; i++) {
        if (inet_pton(AF_INET6, g_bad_ipv6[i], &g_bad_ipv6_bin[g_bad_ipv6_count]) == 1) {
            g_bad_ipv6_count++;
        }
    }
}

/* 解析命令行参数和选项 */
static void parse_opt(int argc, char *argv[]) {
    char opt_listen_addr[IP6STRLEN + PORTSTRLEN] = {0};
    bool disable_builtin = false;

    opterr = 0;
    int shortopt;
    const char *optstr = "L:R:D:l:s:6rbvVh";
    while ((shortopt = getopt(argc, argv, optstr)) != -1) {
        switch (shortopt) {
            case 'L':
                if (strlen(optarg) + 1 > IP6STRLEN + PORTSTRLEN) {
                    printf("invalid udp listen addr: %s\n", optarg);
                    goto err;
                }
                strcpy(opt_listen_addr, optarg);
                break;
            case 'R':
                if (strlen(optarg) + 1 > IP6STRLEN + PORTSTRLEN) {
                    printf("invalid tcp remote addr: %s\n", optarg);
                    goto err;
                }
                parse_addr(optarg, ADDR_TCP_REMOTE);
                break;
            case 'D':
                parse_domain_rule(optarg);
                break;
            case 'l':
                if (strlen(optarg) + 1 > IP6STRLEN + PORTSTRLEN) {
                    printf("invalid tcp local addr: %s\n", optarg);
                    goto err;
                }
                parse_addr(optarg, ADDR_TCP_LOCAL);
                add_flag(FLAG_LOCAL_ADDR);
                break;
            case 's':
                g_syn_cnt = strtoul(optarg, NULL, 10);
                if (g_syn_cnt == 0) {
                    printf("invalid tcp syn cnt: %s\n", optarg);
                    goto err;
                }
                break;
            case '6':
                add_flag(FLAG_IPV6_V6ONLY);
                break;
            case 'r':
                add_flag(FLAG_REUSE_PORT);
                break;
            case 'b':
                disable_builtin = true;
                break;
            case 'v':
                add_flag(FLAG_VERBOSE);
                break;
            case 'V':
                printf(DNS2TCP_PLUS_VER"\n");
                exit(0);
            case 'h':
                print_help();
                exit(0);
            case '?':
                if (!strchr(optstr, optopt)) {
                    printf("unknown option '-%c'\n", optopt);
                } else {
                    printf("missing optval '-%c'\n", optopt);
                }
                goto err;
        }
    }

    if (strlen(opt_listen_addr) == 0) {
        printf("missing option: '-L'\n");
        goto err;
    }

    parse_addr(opt_listen_addr, ADDR_UDP_LISTEN);

    if (!disable_builtin) {
        add_flag(FLAG_USE_BUILTIN);
        init_builtin_servers();
    }

    if (g_server_count == 0) {
        printf("no valid remote servers (use -R to add servers or remove -b to use builtin servers)\n");
        goto err;
    }

    return;

err:
    print_help();
    exit(1);
}

/* 创建socket并配置选项 */
static int create_socket(int family, int type) {
    const char *err_op = NULL;

    int fd = socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        err_op = "create_socket";
        goto out;
    }

    const int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        err_op = "set_reuseaddr";
        goto out;
    }

    if (type == SOCK_DGRAM) {
        if (has_flag(FLAG_REUSE_PORT) && setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
            err_op = "set_reuseport";
            goto out;
        }
        if (family == AF_INET6 && has_flag(FLAG_IPV6_V6ONLY) && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
            err_op = "set_ipv6only";
            goto out;
        }
    } else {
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
            err_op = "set_tcp_nodelay";
            goto out;
        }
        const int syn_cnt = g_syn_cnt;
        if (syn_cnt && setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &syn_cnt, sizeof(syn_cnt)) < 0) {
            err_op = "set_tcp_syncnt";
            goto out;
        }
    }

out:
    if (err_op)
        log_error("%s(fd:%d, family:%d, type:%d) failed: %m", err_op, fd, family, type);
    return fd;
}

/* 程序主入口函数 */
int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 256);
    parse_opt(argc, argv);

    init_ctx_pool();
    init_conn_pool();
    init_bad_ips();

    log_info("udp listen addr: %s#%hu", g_listen_ipstr, g_listen_port);
    log_info("total %d tcp remote servers", g_server_count);
    if (has_flag(FLAG_USE_BUILTIN)) log_info("builtin servers enabled");
    if (has_flag(FLAG_LOCAL_ADDR)) log_info("tcp local addr: %s#%hu", g_local_ipstr, g_local_port);
    if (g_syn_cnt) log_info("enable TCP_SYNCNT:%hhu sockopt", g_syn_cnt);
    if (has_flag(FLAG_IPV6_V6ONLY)) log_info("enable IPV6_V6ONLY sockopt");
    if (has_flag(FLAG_REUSE_PORT)) log_info("enable SO_REUSEPORT sockopt");
    if (g_domain_rule_count > 0) log_info("loaded %d domain rules", g_domain_rule_count);
    log_verbose("print the verbose log");

    g_listen_fd = create_socket(skaddr_family(&g_listen_skaddr), SOCK_DGRAM);
    if (g_listen_fd < 0)
        return 1;

    if (bind(g_listen_fd, &g_listen_skaddr.sa, skaddr_len(&g_listen_skaddr)) < 0) {
        log_error("bind udp address: %m");
        return 1;
    }

    evloop_t *evloop = ev_default_loop(0);

    evio_t watcher;
    ev_io_init(&watcher, udp_recvmsg_cb, g_listen_fd, EV_READ);
    ev_io_start(evloop, &watcher);

    return ev_run(evloop, 0);
}

/* 释放TCP连接资源 */
static void free_tcp_conn(tcp_conn_t *conn, evloop_t *evloop) {
    if (conn) {
        ev_io_stop(evloop, &conn->watcher);
        close(conn->watcher.fd);
        free_conn_to_pool(conn);
    }
}

/* 释放上下文及关联连接 */
static void free_ctx(ctx_t *ctx, evloop_t *evloop) {
    for (int i = 0; i < ctx->conn_count; i++) {
        if (ctx->connections[i]) {
            free_tcp_conn(ctx->connections[i], evloop);
            ctx->connections[i] = NULL;
        }
    }
    free_ctx_to_pool(ctx);
}

/* 发送DNS响应并清理资源 */
static void send_response_and_cleanup(ctx_t *ctx, evloop_t *evloop, 
                                      const void *data, size_t len) {
    if (ctx->response_sent) {
        return;
    }
    
    ctx->response_sent = true;
    
    ssize_t nsend = sendto(g_listen_fd, data, len, 0, 
                           &ctx->srcaddr.sa, skaddr_len(&ctx->srcaddr));
    
    if (nsend < 0 || has_flag(FLAG_VERBOSE)) {
        char ip[IP6STRLEN];
        uint16_t port;
        skaddr_to_text(&ctx->srcaddr, ip, &port);
        if (nsend < 0)
            log_warning("send to %s#%hu: %m", ip, port);
        else
            log_info("send to %s#%hu, nsend:%zd", ip, port, nsend);
    }
    
    free_ctx(ctx, evloop);
}

/* UDP数据接收事件回调 */
static void udp_recvmsg_cb(evloop_t *evloop, evio_t *watcher __unused, int events __unused) {
    ctx_t *ctx = alloc_ctx();
    if (!ctx) {
        char dummy[DNS_MSGSZ];
        recvfrom(g_listen_fd, dummy, DNS_MSGSZ, 0, NULL, NULL);
        return;
    }

    ssize_t nrecv = recvfrom(g_listen_fd, (void *)ctx->query_buffer + 2, DNS_MSGSZ, 0, 
                             &ctx->srcaddr.sa, &(socklen_t){sizeof(ctx->srcaddr)});
    if (nrecv < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            log_warning("recv from udp socket: %m");
        goto free_ctx;
    }

    if (has_flag(FLAG_VERBOSE)) {
        char ip[IP6STRLEN];
        uint16_t port;
        skaddr_to_text(&ctx->srcaddr, ip, &port);
        log_info("recv from %s#%hu, nrecv:%zd", ip, port, nrecv);
    }

    uint16_t *p_msglen = (void *)ctx->query_buffer;
    *p_msglen = htons(nrecv);
    ctx->query_len = nrecv;

    /* 提取查询域名并匹配分流规则 */
    char domain[DNS_MAX_NAME_LEN] = {0};
    int rule_idx = -1;
    
    if (g_domain_rule_count > 0) {
        if (extract_domain_from_query((uint8_t *)ctx->query_buffer + 2, nrecv, domain, sizeof(domain)) == 0) {
            rule_idx = find_domain_rule(domain);
            if (rule_idx >= 0 && has_flag(FLAG_VERBOSE)) {
                log_info("domain %s matches rule: %s", domain, g_domain_rules[rule_idx].suffix);
            }
        }
    }

    /* 根据分流规则选择服务器 */
    if (rule_idx >= 0) {
        domain_rule_t *rule = &g_domain_rules[rule_idx];
        for (int i = 0; i < rule->server_count; i++) {
            int server_idx = rule->server_indices[i];
            
            tcp_conn_t *conn = alloc_conn();
            if (!conn) {
                log_warning("conn pool exhausted");
                continue;
            }
            
            conn->server_idx = server_idx;
            conn->parent_ctx = ctx;
            
            int fd = create_socket(skaddr_family(&g_servers[server_idx].skaddr), SOCK_STREAM);
            if (fd < 0) {
                free_conn_to_pool(conn);
                continue;
            }

            if (has_flag(FLAG_LOCAL_ADDR) && 
                bind(fd, &g_local_skaddr.sa, skaddr_len(&g_local_skaddr)) < 0) {
                log_warning("bind tcp address: %m");
                close(fd);
                free_conn_to_pool(conn);
                continue;
            }

            if (connect(fd, &g_servers[server_idx].skaddr.sa, skaddr_len(&g_servers[server_idx].skaddr)) < 0 && 
                errno != EINPROGRESS) {
                log_warning("connect to %s#%hu: %m", g_servers[server_idx].ipstr, g_servers[server_idx].port);
                close(fd);
                free_conn_to_pool(conn);
                continue;
            }
            
            log_verbose("try to connect to %s#%hu (rule: %s)", g_servers[server_idx].ipstr, g_servers[server_idx].port, rule->suffix);

            ev_io_init(&conn->watcher, tcp_connect_cb, fd, EV_WRITE);
            ev_io_start(evloop, &conn->watcher);
            
            ctx->connections[ctx->conn_count++] = conn;
            ctx->active_conns++;
        }
    } else {
        /* 使用所有可用服务器 */
        for (int i = 0; i < g_server_count; i++) {
            tcp_conn_t *conn = alloc_conn();
            if (!conn) {
                log_warning("conn pool exhausted");
                continue;
            }
            
            conn->server_idx = i;
            conn->parent_ctx = ctx;
            
            int fd = create_socket(skaddr_family(&g_servers[i].skaddr), SOCK_STREAM);
            if (fd < 0) {
                free_conn_to_pool(conn);
                continue;
            }

            if (has_flag(FLAG_LOCAL_ADDR) && 
                bind(fd, &g_local_skaddr.sa, skaddr_len(&g_local_skaddr)) < 0) {
                log_warning("bind tcp address: %m");
                close(fd);
                free_conn_to_pool(conn);
                continue;
            }

            if (connect(fd, &g_servers[i].skaddr.sa, skaddr_len(&g_servers[i].skaddr)) < 0 && 
                errno != EINPROGRESS) {
                log_warning("connect to %s#%hu: %m", g_servers[i].ipstr, g_servers[i].port);
                close(fd);
                free_conn_to_pool(conn);
                continue;
            }
            
            log_verbose("try to connect to %s#%hu", g_servers[i].ipstr, g_servers[i].port);

            ev_io_init(&conn->watcher, tcp_connect_cb, fd, EV_WRITE);
            ev_io_start(evloop, &conn->watcher);
            
            ctx->connections[ctx->conn_count++] = conn;
            ctx->active_conns++;
        }
    }

    if (ctx->active_conns == 0) {
        log_error("failed to create any tcp connections");
        goto free_ctx;
    }

    return;

free_ctx:
    free_ctx(ctx, evloop);
}

/* TCP连接建立事件回调 */
static void tcp_connect_cb(evloop_t *evloop, evio_t *watcher, int events __unused) {
    tcp_conn_t *conn = container_of(watcher, tcp_conn_t, watcher);
    ctx_t *ctx = conn->parent_ctx;
    server_info_t *server = &g_servers[conn->server_idx];

    if (getsockopt(watcher->fd, SOL_SOCKET, SO_ERROR, &errno, &(socklen_t){sizeof(errno)}) < 0 || errno) {
        log_warning("connect to %s#%hu: %m", server->ipstr, server->port);
        ctx->active_conns--;
        
        for (int i = 0; i < ctx->conn_count; i++) {
            if (ctx->connections[i] == conn) {
                ctx->connections[i] = NULL;
                break;
            }
        }
        
        free_tcp_conn(conn, evloop);
        
        if (ctx->active_conns == 0 && !ctx->response_sent) {
            free_ctx(ctx, evloop);
        }
        return;
    }
    
    log_verbose("connect to %s#%hu succeed", server->ipstr, server->port);

    conn->nbytes = 0;
    ev_set_cb(watcher, tcp_sendmsg_cb);
    ev_invoke(evloop, watcher, EV_WRITE);
}

/* TCP数据发送事件回调 */
static void tcp_sendmsg_cb(evloop_t *evloop, evio_t *watcher, int events __unused) {
    tcp_conn_t *conn = container_of(watcher, tcp_conn_t, watcher);
    ctx_t *ctx = conn->parent_ctx;
    server_info_t *server = &g_servers[conn->server_idx];
    
    if (ctx->response_sent) {
        ctx->active_conns--;
        for (int i = 0; i < ctx->conn_count; i++) {
            if (ctx->connections[i] == conn) {
                ctx->connections[i] = NULL;
                break;
            }
        }
        free_tcp_conn(conn, evloop);
        return;
    }

    uint16_t datalen = 2 + ctx->query_len;
    
    ssize_t nsend = send(watcher->fd, (void *)ctx->query_buffer + conn->nbytes, 
                         datalen - conn->nbytes, 0);
    if (nsend < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        log_warning("send to %s#%hu: %m", server->ipstr, server->port);
        
        ctx->active_conns--;
        for (int i = 0; i < ctx->conn_count; i++) {
            if (ctx->connections[i] == conn) {
                ctx->connections[i] = NULL;
                break;
            }
        }
        free_tcp_conn(conn, evloop);
        
        if (ctx->active_conns == 0 && !ctx->response_sent) {
            free_ctx(ctx, evloop);
        }
        return;
    }
    
    log_verbose("send to %s#%hu, nsend:%zd", server->ipstr, server->port, nsend);

    conn->nbytes += nsend;
    if (conn->nbytes >= datalen) {
        conn->nbytes = 0;
        ev_io_stop(evloop, watcher);
        ev_io_init(watcher, tcp_recvmsg_cb, watcher->fd, EV_READ);
        ev_io_start(evloop, watcher);
    }
}

/* TCP数据接收事件回调 */
static void tcp_recvmsg_cb(evloop_t *evloop, evio_t *watcher, int events __unused) {
    tcp_conn_t *conn = container_of(watcher, tcp_conn_t, watcher);
    ctx_t *ctx = conn->parent_ctx;
    server_info_t *server = &g_servers[conn->server_idx];
    
    if (ctx->response_sent) {
        ctx->active_conns--;
        for (int i = 0; i < ctx->conn_count; i++) {
            if (ctx->connections[i] == conn) {
                ctx->connections[i] = NULL;
                break;
            }
        }
        free_tcp_conn(conn, evloop);
        return;
    }

    void *buffer = conn->buffer;
    
    ssize_t nrecv = recv(watcher->fd, buffer + conn->nbytes, 
                         2 + DNS_MSGSZ - conn->nbytes, 0);
    if (nrecv < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return;
        log_warning("recv from %s#%hu: %m", server->ipstr, server->port);
        goto cleanup_conn;
    }
    
    if (nrecv == 0) {
        log_warning("recv from %s#%hu: connection is closed", server->ipstr, server->port);
        goto cleanup_conn;
    }
    
    log_verbose("recv from %s#%hu, nrecv:%zd", server->ipstr, server->port, nrecv);

    conn->nbytes += nrecv;
    
    uint16_t msglen;
    if (conn->nbytes < 2 || conn->nbytes < 2 + (msglen = ntohs(*(uint16_t *)buffer))) {
        return;
    }
    
    /* 检测并过滤恶意IP响应 */
    if (is_bad_response((uint8_t *)buffer + 2, msglen)) {
        log_warning("bad response from %s#%hu, ignoring", server->ipstr, server->port);
        goto cleanup_conn;
    }
    
    log_info("got response from %s#%hu (winner)", server->ipstr, server->port);
    
    send_response_and_cleanup(ctx, evloop, buffer + 2, msglen);
    return;

cleanup_conn:
    ctx->active_conns--;
    for (int i = 0; i < ctx->conn_count; i++) {
        if (ctx->connections[i] == conn) {
            ctx->connections[i] = NULL;
            break;
        }
    }
    free_tcp_conn(conn, evloop);
    
    if (ctx->active_conns == 0 && !ctx->response_sent) {
        free_ctx(ctx, evloop);
    }
}
