# Stripped-Binary Reverse Engineering Case Study

> 从0符号的PIE ELF中恢复函数、调用链和数据结构

---

## 📋 实验概览

本实验是一个完整的stripped-binary逆向工程练习：

1. **自制目标** — 一个mini message parser
2. **编译成-O2 + PIE + stripped** — 0个符号
3. **静态分析** — 从反汇编恢复函数
4. **调用链恢复** — 找出函数调用关系
5. **数据结构恢复** — 从内存访问推断结构布局
6. **动态验证** — 运行程序验证静态推断

---

## 🔧 实验环境

| 项目 | 值 |
|------|-----|
| 架构 | x86-64 |
| 编译选项 | `-O2 -fPIE -pie -s` |
| 工具 | objdump, GDB |
| 符号数 | 0（完全stripped） |

---

## 📦 目标程序

### Ground Truth（源码）
我们写了一个mini message parser，有以下函数：
- main — 入口，读文件
- process_message — 主处理流程
- parse_header — 解析消息头
- validate_checksum — 校验和验证
- dispatch_command — 命令分发
- handle_ping / handle_status / handle_data — 三种命令处理

### 编译结果
```
parser.stripped: ELF 64-bit LSB pie executable, stripped
nm parser.stripped: 0 symbols
```

---

## 🔍 静态分析过程

### Step 1: 找main函数

**方法**: 找调用fopen的函数（main会读文件）

**结果**:
```asm
0x11a0:
    ...
    call fopen@plt    ← main读文件
    call fread@plt
    call fclose@plt
    call 0x1590       ← 调用process_message
```

**恢复**:
| 恢复地址 | 推断功能 | 证据 |
|----------|---------|------|
| 0x11a0 | main | 调用fopen/fread/fclose |

---

### Step 2: 分析process_message (0x1590)

**调用0x1590函数**：

```asm
0x1590:
    ...
    call 0x1370       ← 调用parse_header
    test eax, eax     ← 检查返回值
    jne error

    ; 循环累加字节（validate_checksum，被内联）
0x15f0:
    movzx ecx, byte [rax]
    add rax, 1
    add edx, ecx
    cmp rsi, rax
    jne 0x15f0

    cmp [rsp+0x10], edx  ← 比较校验和
    jne checksum_error

    call 0x1500       ← 调用dispatch_command
    call free@plt     ← 释放payload
```

**恢复**:
| 恢复地址 | 推断功能 | 证据 |
|----------|---------|------|
| 0x1590 | process_message | 调用parse_header，循环校验，调用dispatch |
| 0x1500 | dispatch_command | switch分发 |

---

### Step 3: 分析parse_header (0x1370)

**调用0x1370函数**：

```asm
0x1370:
    cmp esi, 0x7      ← 检查长度 >= 8
    jle too_short

    mov eax, [rdi]    ← 读取前4字节
    cmp eax, 0xdeadbeef  ← 检查magic！🔥
    jne bad_magic

    movzx eax, byte [rdi+4]   ← version
    movzx eax, byte [rdi+5]   ← type
    movzx eax, word [rdi+6]   ← length

    add eax, 0xb      ← 计算总长度
    cmp eax, esi      ← 检查长度
    jge too_short

    call malloc@plt        ← 分配payload
    call __memcpy_chk@plt ← 拷贝payload
```

**恢复**:
| 恢复地址 | 推断功能 | 证据 |
|----------|---------|------|
| 0x1370 | parse_header | 检查magic=0xdeadbeef，解析字段，malloc+memcpy |

---

### Step 4: 数据结构恢复

从parse_header的内存访问推断：

```c
typedef struct {
    uint32_t magic;      // offset 0, 4 bytes, == 0xDEADBEEF
    uint8_t version;     // offset 4, 1 byte
    uint8_t type;        // offset 5, 1 byte
    uint16_t length;     // offset 6, 2 bytes
    uint8_t *payload;    // offset 8, 8 bytes (pointer)
    uint32_t checksum;   // offset 16, 4 bytes
} message_t;
```

**证据**:
- `[rdi+0]` → magic (4 bytes)
- `[rdi+4]` → version (1 byte)
- `[rdi+5]` → type (1 byte)
- `[rdi+6]` → length (2 bytes)

---

## 📊 恢复结果汇总

### 函数恢复表

| 恢复地址 | 推断功能 | Ground Truth | 正确？ |
|----------|---------|-------------|--------|
| 0x11a0 | main | main | ✅ |
| 0x1370 | parse_header | parse_header | ✅ |
| 0x1500 | dispatch_command | dispatch_command | ✅ |
| 0x1590 | process_message | process_message | ✅ |

### 调用链恢复

```
main (0x11a0)
  ↓
process_message (0x1590)
  ↓
parse_header (0x1370)
  ↓
validate_checksum (内联)
  ↓
dispatch_command (0x1500)
  ↓
handle_ping / handle_status / handle_data
```

### 数据结构恢复

```
Message Header:
+0x00: magic (4 bytes) = 0xDEADBEEF
+0x04: version (1 byte)
+0x05: type (1 byte) = 1=PING, 2=STATUS, 3=DATA
+0x06: length (2 bytes)
+0x08: payload (length bytes)
+0x08+length: checksum (4 bytes)
```

---

## 🧪 动态验证

### 测试消息
```python
magic = 0xDEADBEEF
version = 1
type = 1 (PING)
payload = "hello"
checksum = sum("hello")
```

### 运行结果
```
$ ./parser.stripped test_msg.bin
PING: received 5 bytes
```

✅ **验证成功！** 程序正确解析了我们构造的消息。

---

## 📈 本实验学到的技能

1. **stripped binary函数恢复** — 从调用关系找main
2. **magic number识别** — 0xdeadbeef是协议特征
3. **数据结构推断** — 从内存访问偏移推导结构
4. **调用链恢复** — 从call指令构建调用图
5. **内联函数识别** — validate_checksum被-O2内联了

---

## 📁 实验文件

```
stripped-re/
├── parser.c              # 源码（ground truth）
├── parser.debug          # 带符号版本
├── parser.full           # PIE版本（带符号）
├── parser.stripped       # stripped版本（0符号）
├── disasm_stripped.txt   # 反汇编输出
├── test_msg.bin          # 测试消息
├── test_re.sh            # 测试脚本
├── gdb_verify.sh         # GDB验证脚本
└── report.md             # 本报告
```

---

## 🎓 下一步

1. **真实stripped binary** — 用ls/cat等标准工具练习
2. **反混淆** — 简单控制流平坦化恢复
3. **Ghidra使用** — 用Ghidra自动分析+人工修正
4. **ARM stripped RE** — ARM架构的stripped二进制
5. **恶意软件分析** — 简单样本的行为分析

---

*This is a stripped-binary reverse engineering case study with ground truth validation.*
