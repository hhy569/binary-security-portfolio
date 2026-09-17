# OpenWrt ARMv7 Firmware Recon

> 真实ARM固件逆向工程Recon阶段 — 从SquashFS到攻击面分析到QEMU运行

---

## 📋 Recon概览

这是一个完整的真实ARM固件逆向工程案例：

1. **Firmware Download** — OpenWrt ARMv7 rootfs
2. **Filesystem Extraction** — SquashFS 4.0
3. **Binary Inventory** — ARM 32-bit ELF
4. **Startup Services** — 启动脚本分析
5. **Attack Surface** — 网络服务和攻击面识别
6. **Target Binary** — uhttpd Web服务器分析
7. **QEMU Dynamic Run** — 成功在QEMU中运行

---

## 🔧 目标信息

| 项目 | 值 |
|------|-----|
| 固件版本 | OpenWrt 25.12.3 armsr/armv7 |
| 文件格式 | SquashFS 4.0, xz compressed |
| 架构 | ARM 32-bit, EABI5, hard-float |
| libc | musl |
| 链接方式 | dynamic, PIE |
| 大小 | 3.8MB (compressed), 104MB (uncompressed) |

---

## 📦 Filesystem Structure

### 顶层目录
```
squashfs-root/
├── bin/          # 核心工具
├── sbin/         # 系统工具
├── etc/          # 配置文件
├── lib/          # 库文件
├── usr/          # 用户程序
├── www/          # Web界面
├── rom/          # 只读固件
├── overlay/      # 可写层
└── tmp/          # 临时文件
```

---

## 📊 ARM Binary Inventory

### 关键ARM ELF二进制

| 二进制 | 位置 | 功能 |
|--------|------|------|
| busybox | bin/ | BusyBox工具集 |
| ubus | bin/ | OpenWrt总线系统 |
| ubusd | sbin/ | ubus守护进程 |
| procd | sbin/ | 进程管理 |
| netifd | sbin/ | 网络接口管理 |
| rpcd | sbin/ | RPC守护进程 |
| uhttpd | usr/sbin/ | Web服务器 |
| dropbear | usr/sbin/ | SSH服务器 |

---

## 🚀 Startup Services

### 启动脚本
```
etc/init.d/
├── uhttpd      # Web服务器
├── dropbear    # SSH
├── procd       # 进程管理
├── netifd      # 网络管理
└── ...
```

### 网络服务
| 服务 | 端口 | 二进制 |
|------|------|--------|
| HTTP/HTTPS | 80/443 | uhttpd |
| SSH | 22 | dropbear |
| ubus | unix socket | ubusd |

---

## 🎯 Target: uhttpd Web服务器

### 基本信息
```
File: usr/sbin/uhttpd
Arch: ARM 32-bit, EABI5, hard-float
Type: PIE executable
Stripped: yes (no section header)
SHA256: a17979568fc353b85435852759253fe7debed4ea46e7fa65646b52a5112ad93f
```

### 依赖库
- libubox.so
- libjson_script.so
- libblobmsg_json.so
- libjson-c.so

### 插件
- **uhttpd_ubus.so** — JSON-RPC/UBUS插件（独立.so文件）

### Interesting Strings

#### HTTP方法
- `POST`

#### CGI处理
- `/cgi-bin` — CGI脚本路径
- `CGI/1.1` — CGI协议版本

#### 认证
- `Authorization Required`
- `WWW-Authenticate: Basic realm="%s"`
- `HTTP_AUTHORIZATION`
- `HTTP_AUTH_USER`
- `HTTP_AUTH_PASS`

#### UBUS集成
- `JSON-RPC`

### Attack Surface

```
Internet
    ↓
uhttpd (port 80/443)
    ↓
HTTP Request Parser
    ↓
认证检查 (Basic Auth / UBUS session)
    ↓
URL路由
    ├── CGI Handler (/cgi-bin) — 主程序内建
    ├── JSON-RPC (/ubus) — uhttpd_ubus.so插件
    └── Static Files (www/)
```

---

## 🚀 QEMU动态运行验证

### 运行环境
```bash
qemu-arm-static -L . usr/sbin/uhttpd -f -p 127.0.0.1:8080 -h /www
```

### 验证结果
- ✅ uhttpd在QEMU ARM模拟中成功运行
- ✅ HTTP服务器正常监听
- ✅ curl成功连接
- ✅ 返回HTTP 404响应（说明请求处理链路正常）

### 命令行选项（从help输出）
```
-p [addr:]port  Bind to specified address and port
-h directory    Specify the document root
-x string       URL prefix for CGI handler, default is '/cgi-bin'
-u string       URL prefix for UBUS via JSON-RPC handler
-f              Do not fork to background
```

---

## 🔍 潜在攻击点

1. **HTTP Request Parser** — 请求解析
2. **CGI Handler** — CGI脚本启动（主程序内建）
3. **认证逻辑** — Basic Auth / UBUS session
4. **JSON-RPC** — UBUS RPC调用（uhttpd_ubus.so插件）
5. **URL路由** — 路径遍历

---

## 📁 相关文件

```
openwrt-armv7/
├── rootfs.img.gz          # 原始固件（compressed）
├── rootfs.img             # SquashFS镜像
├── _rootfs.img.extracted/ # 提取目录
│   └── squashfs-root/    # RootFS
└── recon_notes.md         # 本报告
```

---

## 🎓 下一步

1. **Ghidra静态分析** — 完整逆向uhttpd
2. **/cgi-bin调用链恢复** — 从URL到CGI执行
3. **GDB动态调试** — 跟踪HTTP请求处理
4. **Fuzzing** — HTTP parser fuzzing
5. **漏洞挖掘** — 找真实漏洞

---

*This is an ARM firmware reconnaissance and dynamic analysis case study on OpenWrt ARMv7 rootfs.*
