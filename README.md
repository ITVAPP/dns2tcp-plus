# dns2tcp-plus

一个 DNS 实用工具，用于将 DNS 查询从 UDP 转为 TCP。支持多服务器竞速查询，显著提升DNS解析的速度和可靠性。

当然有很多 DNS 工具都可以实现这个功能，比如 pdnsd、dnsforwarder；但如果你只是想使用其 UDP 转 TCP 功能（比如配合 dnsmasq，将 dnsmasq 向上游发出的 DNS 查询从 UDP 转为 TCP），那么 dns2tcp-plus 可能是更好的选择。

`dns2tcp-plus` 设计的非常简洁以及易用，它不需要任何配置文件，在命令行参数中指定一个 **本地 UDP 监听地址** 以及一个或多个 **远程 DNS 服务器地址**（该 DNS 服务器支持 TCP 查询）即可，没有任何多余功能。

## 新特性 (v1.2.0)

- **多服务器支持**：可以指定多个上游DNS服务器
- **内置公共DNS**：默认包含5个公共DNS服务器，与用户指定的服务器一起使用
- **竞速查询**：为每个查询同时向所有服务器发起请求，使用最快的响应
- **自动去重**：相同的服务器地址只会被使用一次
- **更高可靠性**：即使部分服务器故障，仍能正常工作
- **灵活配置**：可以通过`-b`参数禁用内置服务器

## 如何编译

> 为了方便使用，[releases](https://github.com/zfl9/dns2tcp/releases) 页面发布了 linux 下常见架构的 musl 静态链接二进制。

```bash
git clone https://github.com/zfl9/dns2tcp
cd dns2tcp
make && sudo make install
```

dns2tcp-plus 默认安装到 `/usr/local/bin/dns2tcp`，可安装到其它目录，如 `make install DESTDIR=/opt/local/bin`。

交叉编译时只需指定 CC 变量，如 `make CC=aarch64-linux-gnu-gcc`（若报错，请先执行 `make clean`，然后再试）。

## 如何运行

```bash
# 使用内置的公共DNS服务器（默认行为）
dns2tcp -L "127.0.0.1#5353"

# 指定额外的上游服务器（会与内置服务器一起使用）
dns2tcp -L "127.0.0.1#5353" -R "8.8.8.8#53"

# 指定多个额外上游服务器（全部服务器一起竞速）
dns2tcp -L "127.0.0.1#5353" -R "192.168.1.1" -R "192.168.1.2"

# 仅使用指定的服务器，禁用内置服务器
dns2tcp -L "127.0.0.1#5353" -R "192.168.1.1" -b

# 启用详细日志查看竞速效果
dns2tcp -L "127.0.0.1#5353" -v

# 如果想在后台运行，可以这样做：
(dns2tcp -L "127.0.0.1#5353" </dev/null &>>/var/log/dns2tcp.log &)
```

- `-L` 选项指定本地监听地址，该监听地址接受 UDP 协议的 DNS 查询。
- `-R` 选项指定远程 DNS 服务器地址，该 DNS 服务器应支持 TCP 查询（可多次使用）。
- 默认情况下会使用内置的公共DNS服务器，通过`-R`指定的服务器会与内置服务器一起使用。
- 如果只想使用`-R`指定的服务器，请添加`-b`参数禁用内置服务器。

## 内置DNS服务器

默认情况下，dns2tcp-plus 会使用以下内置的公共DNS服务器（即使你指定了 `-R` 参数）：

- Google DNS: 8.8.8.8
- Cloudflare DNS: 1.1.1.1
- 114 DNS: 114.114.114.114
- 阿里 DNS: 223.5.5.5
- 腾讯 DNS: 119.29.29.29

如果需要禁用内置服务器，请使用 `-b` 参数。

## 竞速机制

dns2tcp-plus 会为每个DNS查询同时向所有配置的服务器发起TCP连接，并使用第一个返回完整响应的结果。这种机制带来以下好处：

1. **更快的响应速度**：总是使用最快的服务器响应
2. **更高的可靠性**：即使部分服务器故障也不影响使用
3. **自动负载均衡**：自然地使用性能最好的服务器

## 小技巧

借助 iptables，将本机发往 8.8.8.8:53 的 UDP 查询请求，强行重定向至本机 dns2tcp-plus 监听端口，这样就可以不用修改原有 dns 组件的配置，无感转换为 TCP 查询。还是上面那个例子，在启动 dns2tcp-plus 之后，再执行如下 iptables 命令：

```bash
# 将目标地址为 8.8.8.8:53/udp 的包重定向至 dns2tcp 监听端口，实现透明 udp2tcp 转换
iptables -t nat -A OUTPUT -p udp -d 8.8.8.8 --dport 53 -j REDIRECT --to-ports 5353
```

你可以在本机使用 `dig @8.8.8.8 baidu.com` 测试，观察 dns2tcp 日志（带上 -v），就会发现走 TCP 出去了。

## 全部参数

```console
usage: dns2tcp-plus <-L listen> [options...]
 -L <ip[#port]>          udp listen address, port default to 53
 -R <ip[#port]>          tcp remote address, port default to 53 (can specify multiple)
 -l <ip[#port]>          tcp local address, port default to 0
 -s <syncnt>             set TCP_SYNCNT option for tcp socket
 -6                      set IPV6_V6ONLY option for udp socket
 -r                      set SO_REUSEPORT option for udp socket
 -b                      disable builtin servers
 -v                      print verbose log, used for debugging
 -V                      print version number of dns2tcp-plus and exit
 -h                      print help information of dns2tcp-plus and exit
```

`-l`：设置`TCP`连接的本地地址（源地址），`0地址`或`0端口`表示由系统选择。

`-s`：对`TCP`套接字设置`TCP_SYNCNT`，该选项值将影响`TCP`的连接超时时间。

`-6`：对`UDP`套接字设置`IPV6_V6ONLY`，建议始终启用，把 v4 和 v6 监听严格区分开。

`-r`：对`UDP`套接字设置`SO_REUSEPORT`，用于多进程负载均衡，Linux 3.9+ 开始可用。

`-b`：禁用内置的公共DNS服务器，仅使用通过`-R`参数指定的服务器。

## 更新日志

### v1.2.0
- 新增多服务器支持
- 新增内置公共DNS服务器（默认启用）
- 新增竞速查询机制
- 新增`-b`参数用于禁用内置服务器
- 改进资源管理和错误处理
- 重要变更：现在默认会使用内置服务器+用户指定的服务器

### v1.1.2
- zfl9 的 dns2tcp 原始版本，支持单服务器UDP转TCP
