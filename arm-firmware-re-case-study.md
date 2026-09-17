# ARM Firmware RE Case Study: HTTP Request Parser

> 完整ARM固件逆向分析案例 — 从静态反汇编到GDB动态数据流跟踪

---

## 📋 案例概览

本案例展示了完整的ARM固件逆向分析流程：

1. **ARM交叉编译** — 构建目标二进制
2. **QEMU User模式运行** — 模拟ARM执行环境
3. **静态分析** — 符号表、反汇编、字符串分析
4. **GDB远程调试** — 断点、寄存器观察、内存检查
5. **数据流跟踪** — 从输入到内存操作的完整追踪
6. **安全观察点** — 识别潜在漏洞模式

---

## 🔧 工具链

| 工具 | 版本 | 用途 |
|------|------|------|
| gcc-arm-linux-gnueabihf | 13.3.0 | ARM交叉编译 |
| QEMU | 8.2.2 | ARM用户模式模拟 |
| gdb-multiarch | 15.1 | 跨架构调试 |
| arm-linux-gnueabihf-objdump | - | 反汇编 |
| arm-linux-gnueabihf-nm | - | 符号分析 |

---

## 📦 目标二进制

### 基本信息
```
File: test_parser_static
Arch: ARM 32-bit (Thumb mode)
Format: ELF 32-bit LSB executable
Linking: statically linked
Endianness: Little
Build: with debug_info, not stripped
```

### 关键函数
| 函数 | 地址 | 大小 |
|------|------|------|
| main | 0x1051c | 入口 |
| parse_request | 0x10440 | 输入处理函数 |

---

## 🔍 静态分析

### parse_request函数反汇编（节选）

```asm
00010440 <parse_request>:
  10440:  push  {r7, lr}          ; 函数序言
  10442:  sub   sp, #32            ; 分配栈空间
  1045c:  cmp   r3, #3             ; 检查输入长度
  1045e:  bgt.n 10466              ; 长度>3则继续
  1046c:  ldr   r1, [r7, #4]       ; 加载输入指针
  10470:  blx   memcpy             ; 调用memcpy
  1047c:  bl    strchr             ; 调用strchr找空格
  10494:  movs  r3, #0             ; 初始化path_len=0
```

---

## 🚀 动态调试（GDB Remote）

### 调试配置
```bash
# 终端1：启动QEMU GDB server
echo "POST /login?user=admin&pass=123 HTTP/1.1" | qemu-arm-static -g 1234 test_parser_static

# 终端2：GDB连接
gdb-multiarch
  (gdb) set architecture arm
  (gdb) file test_parser_static
  (gdb) target remote :1234
  (gdb) break parse_request
  (gdb) continue
```

### 断点命中状态
```
Breakpoint 1, parse_request (input=0x4080076c "POST /login?user=admin&pass=123 HTTP/1.1\n", len=41)
```

### 寄存器状态（断点处）
| 寄存器 | 值 | 含义 |
|--------|-----|------|
| r0 | 0x4080076c | 输入指针 |
| r1 | 0x29 (41) | 输入长度 |
| lr | 0x105a3 | 返回地址 |
| sp | 0x40800738 | 栈指针 |
| pc | 0x1044a | 当前指令地址 |

### 内存观察
```
输入缓冲区 (0x4080076c):
  0x4080076c:  P O S T   / l o g i n ? u s e r = a d m
  "POST /login?user=admin&pass=123 HTTP/1.1\n"
```

---

## 📊 完整数据流跟踪

### Step 1: memcpy(method, input, 3)
```asm
10470:  blx   memcpy
```
- **输入**：input = "POST /login..."
- **复制长度**：3字节
- **输出**：method = "POS"（注意：只复制了3字节！）

### Step 2: strchr(input, ' ')
```asm
1047c:  bl    strchr
```
- **输入**：input = "POST /login?..."
- **查找**：空格
- **输出**：path指针指向"/login?user=admin&pass=123"

### Step 3: 循环计算path_len
```asm
10494:  movs  r3, #0
10496:  str   r3, [r7, #8]    ; path_len = 0
```
- **循环条件**：path[path_len] != ' ' && path[path_len] != 0
- **结果**：path_len = 26

### Step 4: malloc(path_len)
```c
char *buf = malloc(path_len);
```
- **分配大小**：26字节
- **返回地址**：0x66db0

### Step 5: memcpy(buf, path, path_len)
```c
memcpy(buf, path, path_len);
```
- **源**：path = "/login?user=admin&pass=123"
- **长度**：26字节
- **目标**：buf = 0x66db0

---

## 📈 调用链重建

```
main()
  ↓ read(0, buf, 1024)           ; 读取输入到栈缓冲区
  ↓ parse_request(buf, n)
      ├── memcpy(method, input, 3)    ; 复制HTTP方法（栈缓冲区）
      ├── strchr(input, ' ')           ; 查找空格分隔符
      ├── while loop: count path_len   ; 计算路径长度
      ├── malloc(path_len)             ; 堆分配缓冲区
      ├── memcpy(buf, path, path_len)   ; 复制路径到堆
      ├── printf(...)                  ; 打印结果
      └── free(buf)                    ; 释放堆
```

---

## ⚠️ 安全观察点

### 1. memcpy(method, input, 3) — 方法截断
- **问题**：只复制3字节，但HTTP方法可能更长（POST/PUT/DELETE等）
- **影响**：method[3]被强制设为null，POST变成POS
- **风险**：如果后续代码依赖method长度判断，可能绕过安全检查

### 2. malloc(path_len) 但 memcpy(path_len) — 缺少null终止符
- **问题**：分配path_len字节，复制path_len字节，没有null终止
- **影响**：后续字符串操作（strlen/strcmp等）会越界读
- **风险**：可能导致信息泄露或崩溃

### 3. path_len计算没有上限
- **问题**：循环直到遇到空格或null，没有最大长度限制
- **影响**：恶意输入可以让path_len非常大
- **风险**：大块内存分配 → DoS

### 4. 输入来源是栈缓冲区
- **问题**：main的栈缓冲区只有1024字节
- **影响**：如果输入超过1024字节，会栈溢出
- **风险**：直接栈溢出 → RCE

---

## 🎓 本案例学到的技能

1. **ARM交叉编译** — arm-linux-gnueabihf-gcc
2. **QEMU User模式** — qemu-arm-static直接运行ARM二进制
3. **GDB Remote调试** — qemu-arm-static -g + gdb-multiarch target remote
4. **ARM寄存器观察** — r0-r3参数传递，lr返回地址，sp栈指针
5. **内存断点/观察** — x/s, x/20xb 检查内存内容
6. **数据流跟踪** — 从输入指针到memcpy到malloc的完整追踪
7. **调用栈重建** — 从反汇编到动态执行的对应

---

## 📈 下一步

1. **引入安全输入** — 构造恶意输入触发越界
2. **ASan for ARM** — 编译带ASan的ARM版本
3. **Heap分析** — 观察malloc/free行为
4. **真实固件分析** — 从简单ELF到完整IoT固件

---

*This is a complete ARM firmware reverse engineering case study with static + dynamic analysis.*
