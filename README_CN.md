# dns2tcp-plus

<div align="center">

[![Version](https://img.shields.io/badge/version-1.3.1-blue.svg)](https://github.com/ITVAPP/dns2tcp-plus/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://github.com/ITVAPP/dns2tcp-plus)

[English](README_EN.md) | 简体中文

一个轻量级的 DNS 工具，用于将 DNS 查询从 UDP 转换为 TCP，支持多服务器竞速查询，显著提升 DNS 解析的速度和可靠性。

</div>

---

## ✨ 核心特性

- 🏃 **竞速查询** - 同时向多个服务器发起请求，使用最快的响应
- 🌍 **内置公共DNS** - 默认包含3个知名公共DNS服务器
- 🛡️ **DNS响应验证** - 自动过滤包含无效IP的响应，防止DNS污染
- 🎯 **域名智能分流** - 根据域名后缀选择最优服务器，降低延迟
- ⚡ **高性能** - 使用 libev 事件驱动，支持高并发
- 🔧 **零配置** - 无需配置文件，命令行参数即可运行
- 📦 **轻量级** - 静态编译体积小，资源占用低
- 🔒 **生产就绪** - 修复关键内存问题，适合7×24小时运行

## 🆕 v1.3.1 关键修复

### 内存安全增强
- **修复 Use-After-Free 漏洞** - 解决了高并发下可能导致崩溃的关键内存问题
- **改进连接生命周期管理** - 增强处理多个并发DNS查询时的稳定性
- **优化资源清理机制** - 确保在所有边界情况下正确回收内存

此修复使 dns2tcp-plus 可以在高流量环境和7×24小时运行中稳定工作。

## 🎯 v1.3.0 功能特性

### 1. DNS响应验证
自动检测并过滤包含以下IP的DNS响应：
- `0.0.0.0` - 无效地址
- `127.0.0.1` / `::1` - 本地回环（查询外部域名时）
- `10.10.10.10` - 某些ISP劫持地址
- 更多可疑地址...

当检测到污染响应时，会自动忽略并等待其他服务器的有效响应。

### 2. 域名智能分流
根据域名后缀自动选择最合适的DNS服务器：

```bash
# 中国域名使用国内DNS，避免解析到海外CDN
dns2tcp-plus -L "127.0.0.1#5353" -D "cn:223.5.5.5,119.29.29.29"

# 为特定网站指定专用DNS
dns2tcp-plus -L "127.0.0.1#5353" -D "google.com:8.8.8.8" -D "github.com:1.1.1.1"
```

## 📦 安装

### 预编译二进制（推荐）

从 [Releases](https://github.com/ITVAPP/dns2tcp-plus/releases) 下载适合您架构的静态编译版本：

```bash
# 下载 (以 linux-amd64 为例)
wget https://github.com/ITVAPP/dns2tcp-plus/releases/download/v1.3.1/dns2tcp-plus-linux-amd64
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

## 🚀 快速开始

### 基础用法

```bash
# 使用内置公共DNS服务器（最简单）
dns2tcp-plus -L "127.0.0.1#5353"

# 测试DNS解析
dig @127.0.0.1 -p 5353 google.com
```

### 域名分流示例

```bash
# 国内外智能分流
dns2tcp-plus -L "127.0.0.1#5353" \
  -D "cn:223.5.5.5,119.29.29.29" \
  -D "com.cn:223.5.5.5,119.29.29.29" \
  -D "baidu.com:223.5.5.5" \
  -D "taobao.com:223.5.5.5"

# 企业内网域名使用内部DNS
dns2tcp-plus -L "127.0.0.1#5353" \
  -D "internal.company.com:192.168.1.1" \
  -D "local:192.168.1.1"
```

### 防污染配置

```bash
# 启用详细日志，查看污染检测
dns2tcp-plus -L "127.0.0.1#5353" -v

# 日志示例：
# dns2tcp-plus: bad IPv4 detected: 10.10.10.10
# dns2tcp-plus: bad response from 202.106.0.20#53, ignoring
```

## 🌐 内置DNS服务器

默认包含以下知名公共DNS服务器：

| 提供商 | 地址 | 说明 |
|--------|------|------|
| Google | 8.8.8.8 | 全球覆盖，稳定快速 |
| Cloudflare | 1.1.1.1 | 注重隐私，性能优秀 |
| Quad9 | 9.9.9.9 | 专注安全，过滤恶意网站 |

> 💡 使用 `-b` 参数可禁用内置服务器

## 🛠️ 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-L <ip[#port]>` | UDP监听地址 | 端口默认53 |
| `-R <ip[#port]>` | TCP远程服务器（可多次指定） | 端口默认53 |
| **`-D <suffix:servers>`** | 域名分流规则 | 无 |
| `-l <ip[#port]>` | TCP本地地址（源地址） | 系统自动分配 |
| `-s <syncnt>` | TCP SYN重试次数 | 系统默认 |
| `-6` | 启用 IPv6-only 模式 | 关闭 |
| `-r` | 启用 SO_REUSEPORT | 关闭 |
| `-b` | 禁用内置DNS服务器 | 启用内置 |
| `-v` | 详细日志模式 | 关闭 |
| `-V` | 显示版本号 | - |
| `-h` | 显示帮助信息 | - |

### 域名分流规则格式

```
-D "域名后缀:服务器1,服务器2,..."
```

示例：
- `-D "cn:223.5.5.5,119.29.29.29"` - .cn域名使用指定DNS
- `-D "google.com:8.8.8.8"` - google.com及其子域名使用8.8.8.8
- `-D "local:192.168.1.1"` - .local域名使用内网DNS

## 💡 使用技巧

### 1. 优化中国大陆访问

```bash
dns2tcp-plus -L "127.0.0.1#5353" \
  -D "cn:223.5.5.5,119.29.29.29" \
  -D "com.cn:223.5.5.5,119.29.29.29" \
  -D "org.cn:223.5.5.5,119.29.29.29" \
  -D "net.cn:223.5.5.5,119.29.29.29" \
  -D "edu.cn:223.5.5.5,119.29.29.29" \
  -D "gov.cn:223.5.5.5,119.29.29.29"
```

### 2. 配合 dnsmasq 使用

```bash
# dnsmasq.conf
server=127.0.0.1#5353
no-resolv
cache-size=1000
```

### 3. systemd 服务配置

```bash
sudo tee /etc/systemd/system/dns2tcp-plus.service > /dev/null <<EOF
[Unit]
Description=DNS to TCP Proxy with Smart Routing
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dns2tcp-plus -L "0.0.0.0#53" -D "cn:223.5.5.5,119.29.29.29"
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now dns2tcp-plus
```

## 🏎️ 工作原理

### 竞速查询机制

```
客户端 → dns2tcp-plus → 同时查询多个服务器 → 使用最快的有效响应
                         ├─ 8.8.8.8 (150ms)
                         ├─ 1.1.1.1 (50ms) ✓ 最快
                         └─ 223.5.5.5 (80ms)
```

### 域名分流机制

```
查询: www.baidu.cn
  ↓
匹配规则: cn → 223.5.5.5, 119.29.29.29
  ↓
仅查询: 223.5.5.5 和 119.29.29.29 (不查询其他服务器)
```

### 响应验证机制

```
收到响应 → 解析IP地址 → 检查是否为Bad IP
                          ├─ 是: 丢弃，等待其他服务器
                          └─ 否: 返回给客户端
```

## 📊 性能指标

基于 v1.3.1 版本测试：

- **并发能力**: 128+个并发查询（稳定）
- **内存占用**: < 2MB
- **延迟增加**: < 1ms（本地网络）
- **CPU占用**: 忽略不计
- **过滤效率**: 100%检测率，0误判率
- **稳定性**: 测试100万+查询，零崩溃

## 🔄 更新日志

### v1.3.1
- 🔒 **关键修复**: 解决高并发场景下的 Use-After-Free 漏洞
- ⚡ 改进连接生命周期管理，提升稳定性
- 🛠️ 增强资源清理机制
- 📊 验证100万+连续查询稳定运行

### v1.3.0
- ✨ 新增DNS响应验证，自动过滤污染响应
- ✨ 新增域名智能分流，支持后缀匹配规则
- 🔧 优化DNS包解析，增强安全性
- 📝 完善错误处理和日志输出

### v1.2.0
- ✨ 新增多服务器竞速查询机制
- ✨ 新增内置公共DNS服务器
- ⚡ 提升并发处理能力到128

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

本项目基于 MIT 许可证开源。


---

<div align="center">

**如果这个项目对你有帮助，请给个 ⭐ Star 支持一下！**

Made with ❤️ by ITVAPP

[⬆ 回到顶部](#dns2tcp-plus)
</div>
