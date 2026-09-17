# Binary Security Research Portfolio

> 二进制安全研究作品集 — 真实漏洞发现 + 自动化分析工具开发

---

## 📋 项目概览

这是一个独立二进制安全研究员的完整作品集，包含：

1. **真实漏洞发现** — 3个被上游确认的二进制漏洞
2. **自动化分析工具** — BIVAR二进制patch分析工具
3. **完整研究方法论** — 从目标选择到根因分析的完整流程

---

## 🔍 漏洞发现

### 1. Apache brpc HPACK Decoder Stack Overflow
**状态：✅ 被Apache PMC正式确认**

- **组件**：Apache brpc HPACK Decoder
- **漏洞类型**：Stack Overflow (递归解码导致栈耗尽)
- **根因**：HPACK头部解码使用递归实现，深度嵌套的头部字段会导致栈溢出
- **修复**：官方PR #3343 — 将递归调用改为迭代循环
- **我的工作**：
  - 发现漏洞并提交报告
  - 与Apache PMC (Weibing Wang) 多轮沟通
  - 验证PR #3343修复的正确性

**技术亮点**：
- 深入理解HTTP/2 HPACK压缩协议
- 识别递归解码的栈耗尽风险
- 跟进上游修复并验证

---

### 2. VirtualBox UsbCardReader Out-of-Bounds Read
**状态：✅ Oracle确认，分配CVE编号**

- **CVE编号**：CVE-2026-60160
- **Oracle TID**：S3628125
- **组件**：VirtualBox UsbCardReader
- **漏洞类型**：Out-of-Bounds Read (未验证长度)
- **根因**：USB卡读卡器组件未正确验证输入长度，导致越界内存读取
- **厂商**：Oracle

**技术亮点**：
- 逆向分析VirtualBox虚拟设备实现
- 识别长度验证缺失导致的OOB read
- 获得官方CVE编号

---

### 3. VirtualBox DevLsiLogicSCSI Integer Underflow
**状态：✅ 提交至Oracle PSIRT**

- **Oracle TID**：S3628141
- **组件**：VirtualBox DevLsiLogicSCSI (虚拟SCSI控制器)
- **漏洞类型**：Integer Underflow
- **根因**：SCSI命令处理中的整数下溢，可能导致越界内存访问
- **PoC**：vbox-lsi-underflow-poc.zip

**技术亮点**：
- 分析虚拟SCSI控制器的命令处理逻辑
- 识别整数下溢导致的内存安全问题
- 编写完整PoC

---

## 🛠️ 工具开发

### BIVAR: Binary Patch-Guided Vulnerability Variant Analyzer
**GitHub**: https://github.com/hhy569/bivar

BIVAR是一个自动化二进制patch分析工具，能够：

- **函数匹配**：识别两个二进制版本之间的函数对应关系
- **指令级Diff**：对比修改函数的指令差异
- **安全语义检测**：自动识别补丁中的安全检查类型
  - LENGTH_CHECK — 长度边界检查
  - NULL_CHECK — 空指针检查
  - INTEGER_OVERFLOW_CHECK — 整数溢出检查
- **安全不变量IR**：将检测到的安全检查翻译成结构化安全不变量
- **Patch完整性分析**：检查补丁是否完整覆盖所有消费者函数
- **变体搜索**：在二进制中搜索同源未修复的变体

**真实CVE Benchmark验证**：
| CVE | 产品 | 漏洞类型 | 检测结果 |
|-----|------|----------|----------|
| CVE-2024-56378 | Poppler | 整数溢出 | ✅ 正确识别 |
| CVE-2025-15504 | LIEF | 空指针解引用 | ✅ 正确识别 |
| NTP patch | PcapPlusPlus | 长度检查 | ✅ 正确识别 |

---

## 📊 研究项目

### PcapPlusPlus NTP Layer Vulnerability Research
**GitHub**: https://github.com/hhy569/pcapplusplus-ntp-vuln

- **目标**：PcapPlusPlus v26.07 NTP协议层
- **发现**：6个getter函数存在越界读取问题
- **方法论**：
  - 静态分析所有协议层getter函数
  - 识别通用模式：直接reinterpret_cast无长度检查
  - 使用ASan动态验证
  - 编写PoC复现
  - 提交补丁并验证修复

**研究流程完整性**：
```
目标选择 → 二进制侦察 → 攻击面分析 → 静态审计 → 动态验证 → 
根因分析 → 补丁设计 → 回归测试 → 技术报告
```

---

## 🎓 技术栈

### 漏洞挖掘
- 二进制逆向分析 (x86/x64)
- 模糊测试 (AFL++, libFuzzer)
- 静态代码审计
- 动态分析 (GDB, ASan, UBSan)

### 工具开发
- Python / C++
- 二进制解析 (ELF, objdump)
- 指令级diff算法
- 安全语义分类

### 协议分析
- HTTP/2 / HPACK
- NTP
- USB协议
- SCSI协议
- 网络协议栈分析

---

## 📈 研究方法论

### 完整研究闭环
1. **Target Recon** — 目标选择与攻击面分析
2. **Static Analysis** — 静态代码/二进制审计
3. **Dynamic Validation** — 动态验证漏洞假设
4. **Root Cause Analysis** — 根因分析与数据流追踪
5. **Patch Verification** — 补丁验证与回归测试
6. **Responsible Disclosure** — 负责任的漏洞披露

### 质量原则
- 真实性 > 可复现性 > 技术深度 > 研究方法 > 自动化 > 覆盖率 > Crash数量
- 不把普通crash描述成高危漏洞
- 不虚构CVE
- 所有发现都有完整证据链

---

## 📞 联系方式

- GitHub: [@hhy569](https://github.com/hhy569)
- 邮箱: 2932088330@qq.com

---

*This portfolio represents real binary security research conducted independently.*
