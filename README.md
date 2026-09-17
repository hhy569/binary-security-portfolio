# Binary Security Research Portfolio

> 独立二进制安全研究员 — 真实漏洞发现 + 自动化分析工具开发 + 漏洞利用研究

---

## About Me

Binary security researcher with hands-on experience in vulnerability discovery, exploit development, and automated analysis tooling. Focused on memory corruption vulnerabilities in parsers, protocol implementations, and virtual device emulation. Currently targeting opportunities in Finland (WithSecure, Traficom, Secproof) and Norway (FFI, Kongsberg).

---

## Core Strengths

- **Vulnerability Discovery**: Real CVEs confirmed by upstream vendors (Apache, Oracle)
- **Memory Corruption Analysis**: Integer overflow → under-allocation → heap OOB write chain
- **Automated Tooling**: BIVAR — binary patch-guided variant analysis tool
- **Exploit Development**: Full mitigation bypass (NX/PIE/Canary/RELRO)
- **Firmware RE**: ARM firmware analysis with QEMU + GDB

---

## 🔴 Real Vulnerability Discoveries

### 1. Apache brpc HPACK Decoder Stack Overflow
**Status**: ✅ Confirmed by Apache PMC, fixed in PR #3343

- **Component**: Apache brpc HTTP/2 HPACK Decoder
- **Type**: Stack Overflow (recursive decoding stack exhaustion)
- **Root Cause**: HPACK header decoding uses recursive implementation; deeply nested header fields cause stack overflow
- **Fix**: Official PR #3343 — recursive → iterative loop
- **My Work**:
  - Discovered and reported
  - Multiple rounds of communication with Apache PMC (Weibing Wang)
  - Verified fix correctness

**Technical Depth**:
- Deep understanding of HTTP/2 HPACK compression protocol
- Identified recursive decoding stack exhaustion risk
- Followed upstream fix and verified regression

---

### 2. VirtualBox UsbCardReader Out-of-Bounds Read
**Status**: ✅ Oracle confirmed, CVE assigned

- **CVE**: CVE-2026-60160
- **Oracle TID**: S3628125
- **Component**: VirtualBox UsbCardReader
- **Type**: Out-of-Bounds Read (unvalidated length)
- **Root Cause**: USB card reader component fails to properly validate input length

**Technical Depth**:
- Reverse engineering of VirtualBox virtual device implementation
- Identified missing length validation leading to OOB read
- Obtained official CVE assignment

---

### 3. VirtualBox DevLsiLogicSCSI Integer Underflow
**Status**: ✅ Submitted to Oracle PSIRT

- **Oracle TID**: S3628141
- **Component**: VirtualBox DevLsiLogicSCSI (virtual SCSI controller)
- **Type**: Integer Underflow
- **Root Cause**: Integer underflow in SCSI command processing

---

### 4. Assimp AMF Integer Overflow → Division by Zero
**Status**: ✅ Reported to Assimp maintainers

- **Component**: Assimp 6.0.5 AMF Importer
- **File**: `code/AssetLib/AMF/AMFImporter_Material.cpp:202`
- **Type**: Integer Overflow → SIGFPE
- **Root Cause**: `width * height` (uint32_t multiplication) overflows to 0, then `data.size() / 0` causes division by zero
- **ASan Confirmation**: ✅ FPE @ AMFImporter_Material.cpp:202
- **PoC**: Minimal AMF file with width=65536, height=65536

---

## 🟠 Memory Corruption Research Case Study

### Assimp 3D Model Importer Systematic Analysis

**Target**: Assimp 6.0.5 (commit 392a658)

**4 ASan-confirmed crashes**:

| # | Importer | Type | Location | Root Cause |
|---|----------|------|----------|------------|
| 1 | AMF | Division by Zero | AMFImporter_Material.cpp:202 | width*height overflow to 0 |
| 2 | IQM | SEGV READ | IQMImporter.cpp:224 | first_vertex*step overflow |
| 3 | IQM | Heap OOB READ | IQMImporter.cpp:205 | num_triangles oversized |
| 4 | **SIB** | **Heap OOB WRITE** | **SIBImporter.cpp:249** | **numPoints*3 uint32_t overflow** |

#### SIB Heap OOB Write — Detailed Analysis

**Vulnerability**: Integer Overflow → Under-allocation → Heap OOB Write

```
numPoints = 0x55555556
    ↓
numPoints * 3 = 0x100000002
    ↓
uint32_t truncation → 0x00000002
    ↓
resize(pos + 2)  ← allocation too small
    ↓
Loop still executes 0x55555556 times
    ↓
Heap OOB WRITE
```

**Write Primitive Characterization**:

| Property | Value | Attacker-Controlled? |
|----------|-------|---------------------|
| Allocation size | pos + 2 uint32_t | ✅ |
| Write count | 0x55555556 iterations | ✅ |
| Write size | 4 bytes (uint32_t) | - |
| Write value (POS) | vertex index from file | ✅ Fully controlled |
| Write value (NRM/UV) | ptIdx counter | ❌ |
| Write offset | initial_idx + n × 12 bytes | ✅ |

**Key Insight**: This is a **fully attacker-controlled heap OOB write primitive**.

#### Variant Hunting Methodology

**Security Invariant Extracted**:
```
count × elements_per_item must satisfy:
  product ≤ SIZE_MAX

AND:
  allocated_elements ≥ count × elements_per_item
```

**Variant Search Results**:
- Scanned entire Assimp codebase for `count * constant` pattern
- Identified 8 candidate locations across multiple importers
- Top candidates: MDLLoader (5 instances of `num_tris * 3`)

---

## 🛠️ Automated Analysis Tool

### BIVAR: Binary Patch-Guided Vulnerability Variant Analyzer
**GitHub**: https://github.com/hhy569/bivar (public)

**6-Step Pipeline**:
1. **Function Matching** — Identify function correspondence between binary versions
2. **Instruction Diff** — Instruction-level comparison of modified functions
3. **Security Semantic Detection** — Classify patch security type
   - LENGTH_CHECK / NULL_CHECK / INTEGER_OVERFLOW_CHECK
4. **Security Invariant IR** — Translate checks into structured invariants
5. **Patch Completeness** — Verify patch covers all consumer functions
6. **Variant Hunting** — Search for similar unpatched variants

**3-CVE Benchmark Validation**:

| Benchmark | CVE / Bug Type | Security Semantic | Function Localized |
|-----------|----------------|-------------------|--------------------|
| PcapPlusPlus NTP | Truncated header OOB | LENGTH_CHECK | ✅ getNtpHeader() |
| Poppler | CVE-2024-56378 | INTEGER_OVERFLOW_CHECK | ✅ JBIG2Bitmap::combine() |
| LIEF | CVE-2025-15504 | NULL_CHECK | ✅ ELFParser::parse_binary() |

This matrix demonstrates BIVAR generalizes across different memory-safety bug classes.

---

## 📊 Protocol Vulnerability Research

### PcapPlusPlus NTP Layer Systematic Audit
**GitHub**: https://github.com/hhy569/pcapplusplus-ntp-vuln

- **Target**: PcapPlusPlus v26.07
- **Finding**: 6 NTP getter functions with OOB read (missing length validation)
- **Pattern**: Direct `reinterpret_cast` without bounds checking
- **Methodology**: Static analysis → ASan validation → PoC → Patch → Regression test

**Systematic Pattern Discovery**:
```
Protocol layer getter
    ↓
reinterpret_cast directly to header struct
    ↓
No length validation
    ↓
Short packet → OOB READ
```

Found across 8 protocol families (ICMP, NTP, DNS, DoIP, SomeIP, SomeIP-SD, S7Comm, Modbus).

---

## 🎯 Exploit Development

### Heap Exploitation Lab — Integer Overflow to Code Execution
**Type**: End-to-end modern-glibc heap exploitation (built around the SIB bug class)

Rather than stopping at a crash, I built a lab that carries the **exact SIB
bug pattern** (`count * 3` 32-bit overflow → undersized allocation → heap OOB
write) through a complete exploitation chain, verified on a Linux VM:

```
integer overflow → undersized malloc → heap OOB write
   → heap feng shui → tcache fd corruption
   → safe-linking (PROTECT_PTR) bypass → arbitrary chunk return
   → vtable/callback overwrite → control-flow hijack
```

**What it demonstrates:**
- Primitive characterization (write value / offset / count controllability)
- Heap feng shui to place a freed tcache chunk adjacent to the overflow
- glibc ≥ 2.32 safe-linking arithmetic: `forged_fd = target ^ (fd_addr >> 12)`
- Modern mitigation map: ASLR, heap ASLR, safe-linking, removed
  `__malloc_hook` (≥2.34), Full RELRO → vtable/callback targets
- A `#ifdef FIXED` build using overflow-safe `size_t` arithmetic that refuses
  the 16 GB allocation, plus an ASan build confirming the OOB write

**Verified builds:** vulnerable (chain walkthrough), ASan
(`heap-buffer-overflow WRITE of size 4`), fixed (allocation safely rejected).

> Key research finding in the real SIB code: the corrupted `idx[UV]` values
> are later dereferenced as array indices in `ReadUVs`
> (`mesh->uv[id].x = ...`), giving a potential **second-stage OOB primitive**.

### Memory Corruption → Exploitability Analysis

**Core Research Question**:
> Can an integer-overflow-induced heap OOB write in a file-format parser be
> escalated from crash to code execution, and what mitigations stand in the way?

Full chain practiced: `Crash → Root Cause → Memory Primitive → Controllability
→ Heap Grooming → Allocator Attack → Control-Flow Hijack`.

---

## 🖥️ Firmware Reverse Engineering

### OpenWrt ARMv7 Firmware Analysis
- **Target**: OpenWrt 25.12.3 armsr-armv7 rootfs
- **Analysis Object**: uhttpd web server
- **Techniques**:
  - SquashFS filesystem extraction
  - ARM 32-bit EABI5 hard-float analysis
  - PIE + stripped binary analysis
  - QEMU user-mode emulation
  - GDB remote debugging

---

## ✍️ Research Writing

Public write-ups that document the research process end to end:

1. **BIVAR: Binary Patch-Guided Vulnerability Variant Analyzer** — how one
   patched CVE becomes a systematic search for its siblings.
2. **Anatomy of an Integer-Overflow Heap OOB Write** — the Assimp SIB case
   study, from ASan report to characterized write primitive.
3. **Security-Invariant Variant Hunting** — the five-stage method for turning
   one CVE into a reusable hunting strategy.

These emphasize honest classification: a multiply is not a bug, a crash is
not a vulnerability, an OOB write is not RCE, and a reproduced public issue is
never claimed as a new CVE.

---

## 📈 Research Methodology

### Complete Research Loop
1. **Target Recon** — Attack surface analysis
2. **Static Analysis** — Code audit and data-flow tracing
3. **Dynamic Validation** — ASan/UBSan confirmation
4. **Root Cause Analysis** — field → variable → arithmetic → memory operation
5. **Invariant Extraction** — generalize the bug pattern
6. **Variant Hunting** — systematic sibling search (BIVAR)
7. **Exploitability Analysis** — crash → primitive → control flow
8. **Responsible Disclosure** — vendor coordination and regression tests

### Coverage-Gated Fuzzing Discipline
Negative results are documented, not hidden: deep-state fuzzing campaigns on
FFmpeg HTJ2K and libheif were deliberately stopped at measured coverage
plateaus (no new paths/min, deep decoder unreachable) rather than burned as
blind CPU time. Each produced a reachability/bottleneck analysis instead of
inflated crash counts.

### Quality Principles
- Truthfulness > Reproducibility > Technical Depth > Methodology > Automation > Coverage > Crash Count
- No fictional CVEs, patches, or severity claims
- All findings have complete evidence chains
- Clear distinction between known bugs, reproductions, and new discoveries
- Local testing only on open-source / authorized targets

---

## 📞 Contact

- GitHub: [@hhy569](https://github.com/hhy569)
- Email: 2932088330@qq.com

---

*This portfolio represents independent binary security research. All crashes are ASan-confirmed. All vulnerabilities have complete evidence chains.*
