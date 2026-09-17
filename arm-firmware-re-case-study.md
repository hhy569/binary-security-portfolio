# ARM Firmware RE Case Study: HTTP Request Parser

> 第一个ARM固件逆向分析案例 — 从二进制到动态调用链

---

## 📋 案例概览

本案例展示了完整的ARM固件逆向分析流程：

1. **ARM交叉编译** — 构建目标二进制
2. **QEMU User模式运行** — 模拟ARM执行环境
3. **静态分析** — 符号表、反汇编、字符串分析
4. **函数定位** — 识别输入处理函数
5. **动态验证** — 确认函数行为

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
  1044a:  ldr   r2, [pc, #192]     ; 加载全局指针
  1045c:  cmp   r3, #3             ; 检查输入长度
  1045e:  bgt.n 10466              ; 长度>3则继续
  10460:  mov.w r3, #0xffffffff    ; 返回-1
  1046c:  ldr   r1, [r7, #4]       ; 加载输入指针
  10470:  blx   memcpy             ; 调用memcpy
  1047c:  bl    strchr             ; 调用strchr找空格
  10494:  movs  r3, #0             ; 初始化path_len=0
  10496:  str   r3, [r7, #8]
```

### 关键发现
1. **长度检查**：`cmp r3, #3` — 检查输入长度至少为4字节
2. **memcpy调用**：从输入复制3字节到method缓冲区
3. **strchr调用**：查找空格分隔符
4. **循环计算path_len**：逐个字节计算路径长度

---

## 🚀 动态验证

### QEMU运行
```bash
echo "GET /index.html HTTP/1.1" | qemu-arm-static test_parser_static
```

### 输出
```
Method: GET, Path len: 11
```

### 验证结论
- ✅ parse_request函数被正确调用
- ✅ 方法解析正确（GET）
- ✅ 路径长度计算正确（/index.html = 11字节）

---

## 📊 调用链分析

```
main()
  ↓ read(0, buf, 1024)  ; 读取输入
  ↓ parse_request(buf, n)
      ├── memcpy(method, input, 3)    ; 复制方法
      ├── strchr(input, ' ')           ; 找空格
      ├── while loop: count path_len   ; 计算路径长度
      ├── malloc(path_len)             ; 分配缓冲区
      ├── memcpy(buf, path, path_len)  ; 复制路径
      └── free(buf)
```

---

## ⚠️ 安全观察点

在parse_request函数中发现以下值得关注的点：

1. **malloc(path_len) 但 memcpy(path_len)**
   - 缓冲区大小 = path_len
   - 复制字节数 = path_len
   - 缺少null终止符 → 字符串操作可能越界

2. **path_len计算没有上限**
   - 循环直到遇到空格或null
   - 如果输入没有空格，path_len可能很大
   - 可能导致大块内存分配

3. **没有验证path_len的合理性**
   - 可能被利用进行资源耗尽攻击

---

## 🎓 本案例学到的技能

1. **ARM交叉编译** — 使用arm-linux-gnueabihf-gcc
2. **QEMU User模式** — 直接运行ARM二进制
3. **ARM反汇编阅读** — Thumb指令集
4. **函数定位** — 从符号表到输入处理函数
5. **调用链重建** — 从静态分析到动态验证

---

## 📈 下一步

1. **接入GDB远程调试** — 在parse_request下断点
2. **寄存器/内存观察** — 动态跟踪数据流
3. **BIVAR ARM扩展** — 将二进制分析工具支持ARM
4. **真实固件分析** — 从简单ELF到完整IoT固件

---

*This is the first ARM firmware reverse engineering case in the portfolio.*
