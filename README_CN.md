# dns2tcp-plus

<div align="center">

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/ITVAPP/dns2tcp-plus/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://github.com/ITVAPP/dns2tcp-plus)

[English](README.md) | 简体中文

一个强大的 DNS 工具，用于将 DNS 查询从 UDP 转换为 TCP/TLS，支持多服务器竞速查询、DNS over TLS 加密传输和智能故障转移机制。

</div>

---

## ✨ 核心特性

- 🔒 **DNS over TLS (DoT)** - 853端口自动加密，安全DNS查询
- 🏃 **竞速查询** - 同时向多个服务器发起请求，使用最快的响应
- 🔄 **智能故障转移** - 内置DNS优先，自动回退到系统DNS
- 🌍 **混合DNS** - 无缝结合内置服务器与系统DNS
- 🛡️ **DNS响应验证** - 自动过滤污染响应，防止DNS劫持
- 🎯 **域名智能分流** - 根据域名后缀选择最优服务器
- ⚡ **高性能** - 内存池优化，SSL会话缓存
- 🔧 **零配置** - 自动检测系统DNS，开箱即用

## 🆕 v2.0.0 重大更新

### 1. DNS over TLS (DoT) 支持
- 853端口查询自动加密
- SSL会话缓存提升性能
- 支持主流DoT提供商（Google、Cloudflare）
- 无需额外配置

### 2. 系统DNS集成
- 自动从 `/etc/resolv.conf` 加载DNS服务器
- 作为内置服务器失败时的备用方案
- 可通过 `-f` 参数禁用（适用于隔离环境）

### 3. 智能故障转移机制
```
内置DNS（优先） → 系统DNS（备用）
     ↓ 全部失败        ↓
     └──────────→ 使用缓存的系统响应
```

### 4. 性能优化
- 连接和上下文的内存池管理
- SSL会话复用减少握手开销
- 并发处理能力提升至256

## 📦 安装

### 预编译二进制（推荐）

从 [Releases](https://github.com/ITVAPP/dns2tcp-plus/releases) 下载适合您架构的静态编译版本：

```bash
# 下载 (以 linux-amd64 为例)
wget https://github.com/ITVAPP/dns2tcp-plus/releases/download/v2.0.0/dns2tcp-plus-linux-amd64
chmod +x dns2tcp-plus-linux-amd64
sudo mv dns2tcp-plus-linux-amd64 /usr/local/bin/dns2tcp-plus

# 验证安装
dns2tcp-plus -V
```

### 从源码编译

```bash
git clone https://github.com/ITVAPP/dns2tcp-plus
cd dns2tcp-plus
make && sudo make install
```

依赖：
- libev
- OpenSSL（用于DoT支持）

## 🚀 快速开始

### 基础用法

```bash
# 最简单用法 - 结合内置DNS和系统DNS
dns2tcp-plus -L "127.0.0.1#5353"

# 测试DNS解析
dig @127.0.0.1 -p 5353 google.com

# 测试 DNS over TLS
dig @127.0.0.1 -p 5353 +tcp cloudflare.com
```

### DNS over TLS 示例

```bash
# 添加自定义DoT服务器
dns2tcp-plus -L "127.0.0.1#5353" \
  -R "1.1.1.1#853" \
  -R "8.8.8.8#853" \
  -R "9.9.9.9#853"

# 混合TCP和DoT服务器
dns2tcp-plus -L "127.0.0.1#5353" \
  -R "223.5.5.5#53" \      # TCP
  -R "1.1.1.1#853"         # DoT
```

### 使用DoT的域名分流

```bash
# 敏感域名使用DoT
dns2tcp-plus -L "127.0.0.1#5353" \
  -D "gmail.com:8.8.8.8#853" \
  -D "banking.com:1.1.1.1#853" \
  -D "cn:223.5.5.5#53"
```

### 系统DNS控制

```bash
# 禁用系统DNS（仅使用内置）
dns2tcp-plus -L "127.0.0.1#5353" -f

# 禁用内置服务器（仅使用系统）
dns2tcp-plus -L "127.0.0.1#5353" -b

# 自定义组合
dns2tcp-plus -L "127.0.0.1#5353" \
  -R "8.8.8.8#853" \      # 添加DoT
  -b                       # 禁用其他内置，保留系统
```

## 🌐 内置服务器

### TCP服务器（端口53）
| 提供商 | 地址 | 说明 |
|--------|------|------|
| Google | 8.8.8.8 | 全球覆盖，可靠稳定 |
| Cloudflare | 1.1.1.1 | 注重隐私，快速响应 |

### DoT服务器（端口853）
| 提供商 | 地址 | 主机名 | 说明 |
|--------|------|--------|------|
| Google | 8.8.8.8 | dns.google | 加密的Google DNS |
| Cloudflare | 1.1.1.1 | 1dot1dot1dot1.cloudflare-dns.com | 加密的Cloudflare |

### 系统DNS
自动从 `/etc/resolv.conf` 加载作为备用服务器。

## 🛠️ 命令行参数

| 参数 | 说明 | 默认值 | 限制 |
|------|------|--------|------|
| `-L <ip[#port]>` | UDP监听地址 | 端口默认53 | - |
| `-R <ip[#port]>` | TCP/DoT远程服务器 | 53=TCP, 853=DoT | 最多16个服务器 |
| `-D <suffix:servers>` | 域名分流规则 | 无 | 最多16条规则，每规则8个服务器 |
| `-l <ip[#port]>` | TCP本地地址 | 系统分配 | - |
| `-s <syncnt>` | TCP SYN重试次数 | 系统默认 | - |
| `-6` | 启用IPv6-only模式 | 关闭 | - |
| `-r` | 启用SO_REUSEPORT | 关闭 | - |
| `-b` | 禁用内置服务器 | 启用内置 | - |
| **`-f`** | 禁用系统DNS | 启用系统DNS | - |
| `-v` | 详细日志 | 关闭 | - |
| `-V` | 显示版本号 | - | - |
| `-h` | 显示帮助信息 | - | - |

## 💡 高级用法

### 1. 最大安全配置

```bash
# 仅使用DoT，不回退到未加密连接
dns2tcp-plus -L "127.0.0.1#5353" \
  -R "1.1.1.1#853" \
  -R "8.8.8.8#853" \
  -R "9.9.9.9#853" \
  -b -f  # 禁用所有非DoT服务器
```

### 2. 性能优化配置

```bash
# 混合快速TCP和安全DoT
dns2tcp-plus -L "0.0.0.0#53" \
  -D "sensitive.com:1.1.1.1#853" \
  -D "local:192.168.1.1#53" \
  -r  # 启用SO_REUSEPORT负载均衡
```

### 3. 企业级配置

```bash
dns2tcp-plus -L "0.0.0.0#53" \
  -D "internal.corp:10.0.0.1#53" \
  -D "*.internal:10.0.0.1#53" \
  -D "secure.corp:8.8.8.8#853" \
  -s 3 \  # 快速故障转移
  -v      # 详细日志便于监控
```

### 4. 中国大陆优化配置

```bash
dns2tcp-plus -L "127.0.0.1#5353" \
  -D "cn:223.5.5.5#53,119.29.29.29#53" \
  -D "com.cn:223.5.5.5#53" \
  -D "baidu.com:223.5.5.5#53" \
  -D "international:1.1.1.1#853"  # 国际域名使用DoT
```

## 🏎️ 工作原理

### 带故障转移的查询流程

```
客户端查询
    ↓
dns2tcp-plus
    ├─→ 内置DNS（优先）
    │     ├─ 8.8.8.8:53 (TCP)
    │     ├─ 8.8.8.8:853 (DoT) ← 加密
    │     ├─ 1.1.1.1:53 (TCP)
    │     └─ 1.1.1.1:853 (DoT) ← 加密
    │
    └─→ 系统DNS（备用）
          ├─ 192.168.1.1:53
          └─ 8.8.4.4:53
```

### DoT连接流程

```
DNS查询 → TCP套接字 → SSL/TLS握手 → 加密查询
                           ↓
                     会话缓存（下次查询复用）
```

### 响应优先级

1. 内置DNS的第一个有效响应获胜
2. 系统DNS响应被缓存但仅在所有内置失败时使用
3. 恶意IP过滤适用于所有响应

## 📊 性能指标

基于 v2.0.0 版本测试：

- **并发能力**: 256个并发查询（受上下文池限制）
- **最大服务器数**: 总计16个（内置+自定义+系统）
- **内存占用**: < 3MB（含内存池）
- **连接池**: 2048个预分配连接
- **上下文池**: 256个预分配上下文
- **DoT开销**: 首次查询~30ms，会话复用~5ms
- **故障转移**: < 100ms切换到系统DNS
- **SSL会话缓存**: 128个会话，5分钟超时（300秒）
- **DNS包大小**: 最大1472字节
- **恶意IP过滤**: 拦截 0.0.0.0、127.0.0.1、10.10.10.10、240.0.0.0

## 🔒 安全特性

1. **DNS over TLS**: 防止窃听和篡改
2. **响应验证**: 过滤劫持响应
3. **无证书验证**: 简化部署（谨慎使用）
4. **会话复用**: 减少重复握手的攻击面

## ⚙️ 技术特性

- **TCP_NODELAY**: 针对低延迟DNS查询优化
- **非阻塞I/O**: 基于libev的事件驱动架构
- **内存池**: 热路径零分配设计
- **DNS压缩**: 正确处理DNS标签压缩
- **并发设计**: 每个查询并行连接多服务器
- **智能缓冲**: TCP DNS格式的2字节长度前缀
- **IPv4/IPv6双栈**: 完整支持两种协议

## 🔄 更新日志

### v2.0.0
- 🔒 新增DNS over TLS (DoT)支持，含SSL会话缓存
- 🔄 新增系统DNS集成与智能故障转移
- ⚡ 新增连接内存池优化
- ✨ 改进内置服务器配置
- 📝 增强DoT连接调试日志

### v1.3.0
- ✨ 新增DNS响应验证
- ✨ 新增域名智能分流
- 🔧 优化DNS包解析

## 🐛 故障排除

### DoT连接问题
```bash
# 启用详细日志
dns2tcp-plus -L "127.0.0.1#5353" -v

# 检查SSL握手和会话复用
# 查找: "SSL session reused for..." 消息
```

### 系统DNS未加载
```bash
# 检查 /etc/resolv.conf 格式
cat /etc/resolv.conf

# 必要时强制禁用系统DNS
dns2tcp-plus -L "127.0.0.1#5353" -f
```

## 📄 许可证

本项目基于 MIT 许可证开源。

---

<div align="center">

**如果这个项目对你有帮助，请给个 ⭐ Star 支持一下！**

Made with ❤️ by ITVAPP

[⬆ 回到顶部](#dns2tcp-plus)
</div>
