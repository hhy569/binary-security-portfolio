# OpenWrt ARMv7 Firmware Recon

> 真实ARM固件逆向工程Recon阶段 — 从SquashFS到攻击面分析

---

## 📋 Recon概览

这是一个真实ARM固件逆向工程的Recon阶段：

1. **Firmware Download** — OpenWrt ARMv7 rootfs
2. **Filesystem Extraction** — SquashFS 4.0
3. **Binary Inventory** — ARM 32-bit ELF
4. **Startup Services** — 启动脚本分析
5. **Attack Surface** — 网络服务和攻击面识别
6. **Target Binary** — uhttpd Web服务器分析

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

### Interesting Strings

#### HTTP方法
- `POST`
- `GET`（隐含在HTTP处理中）

#### CGI处理
- `/cgi-bin` — CGI脚本路径
- `CGI/1.1` — CGI协议版本
- `Failed to create CGI process`
- `Unable to launch the requested CGI program`

#### 认证
- `Authorization Required`
- `WWW-Authenticate: Basic realm="%s"`
- `HTTP_AUTHORIZATION`
- `HTTP_AUTH_USER`
- `HTTP_AUTH_PASS`
- `http-auth-user`
- `http-auth-pass`

#### UBUS集成
- `Do not authenticate JSON-RPC requests against UBUS session api`
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
    ├── CGI Handler (/cgi-bin)
    ├── JSON-RPC (UBUS)
    └── Static Files (www/)
```

---

## 🔍 潜在攻击点

1. **HTTP Request Parser** — 请求解析
2. **CGI Handler** — CGI脚本启动
3. **认证逻辑** — Basic Auth / UBUS session
4. **JSON-RPC** — UBUS RPC调用
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

1. **QEMU用户模式模拟** — 运行uhttpd
2. **GDB动态调试** — 跟踪HTTP请求处理
3. **静态分析** — Ghidra逆向uhttpd
4. **Fuzzing** — HTTP parser fuzzing
5. **漏洞挖掘** — 找真实漏洞

---

*This is an ARM firmware reconnaissance case study on OpenWrt ARMv7 rootfs.*
