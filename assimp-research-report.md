# Assimp Binary Security Research Report

## 研究概述

本报告记录了对Assimp 6.0.5的系统性二进制安全研究，包括：
- 静态代码审计
- 整数溢出分析
- Heap OOB write触发
- Variant hunting（变体搜索）
- 安全不变量提取

---

## 研究成果汇总

| # | Impoter | 漏洞类型 | 根因 | ASan确认 | 状态 |
|---|---------|----------|------|----------|------|
| 1 | AMF | Integer Overflow → Division by Zero | `width * height` uint32_t溢出为0 | ✅ SIGFPE | ✅ 已上报 |
| 2 | IQM | Integer Overflow → OOB READ | `first_vertex * step`溢出 | ✅ SEGV READ | 已知bug #6708 |
| 3 | IQM | Heap OOB READ | `num_triangles`过大 | ✅ Heap-buffer-overflow READ | 可能是新的 |
| 4 | **SIB** | **Integer Overflow → Heap OOB WRITE** | **`numPoints * 3` uint32_t溢出** | **✅ Heap-buffer-overflow WRITE** | **已知bug #6733** |

---

## 重点发现：SIB Heap OOB Write

### 漏洞位置
- **文件：** `code/AssetLib/SIB/SIBImporter.cpp:249`
- **函数：** `ReadFaces`
- **ASan类型：** `heap-buffer-overflow WRITE of size 4`

### 根因分析

```cpp
// SIBImporter.cpp:243-249
size_t pos = mesh->idx.size() + 1;
mesh->idx.resize(pos + numPoints * N);  // N = 3

for (uint32_t n = 0; n < numPoints; n++, idx += N, ptIdx++) {
    uint32_t p = stream->GetU4();
    ...
    idx[POS] = p;      // WRITE
    idx[NRM] = ptIdx;  // WRITE
    idx[UV] = ptIdx;   // WRITE
}
```

### 整数溢出链

```
numPoints = 0x55555556
N = 3

numPoints * N = 0x55555556 × 3 = 0x100000002
            ↓
    uint32_t 截断
            ↓
    0x000000002 (2)
            ↓
    resize(pos + 2)  ← 只分配了pos+2个uint32_t！
            ↓
    但循环仍然执行0x55555556次！
            ↓
    Heap OOB WRITE！
```

### Write Primitive Characterization

| 属性 | 值 | 攻击者可控？ |
|------|-----|-------------|
| Allocation size | `pos + 2` uint32_t | ✅ |
| Write count | `0x55555556` 次 | ✅ |
| Write size | 4字节（uint32_t） | - |
| Write value (POS) | `p` — 从文件读的顶点索引 | ✅ **完全可控！** |
| Write value (NRM/UV) | `ptIdx` — 计数器 | ❌ |
| Write offset | `initial_idx + n × 12` 字节 | ✅ |

### 结论
这是一个**攻击者完全可控的heap OOB write primitive**！

---

## Variant Hunting结果

我们提取了安全不变量：
```
count × elements_per_item 必须满足：
product ≤ SIZE_MAX

同时：
allocated_elements ≥ count × elements_per_item
```

用这个不变量扫整个Assimp代码库，找到以下候选：

| # | 文件 | 行号 | Pattern | 状态 |
|---|------|------|---------|------|
| 1 | MDLLoader.cpp | 489,683,697,1516,1867 | `num_tris * 3` | 待验证 |
| 2 | UnrealLoader.cpp | 435 | `num * 3` | 待验证 |
| 3 | 3DSConverter.cpp | 151 | `mFaces.size() * 3` | 已确认安全 |
| 4 | CSMLoader.cpp | 213 | `alloc * 2` | 已确认安全 |
| 5 | ASEParser.cpp | 1653 | `mFaces.size() * 3` | 已确认安全 |
| 6 | MDLMaterialLoader.cpp | 417,493 | `mWidth` | 已确认安全 |
| 7 | M3D/m3d.h | 2099 | `memcpy(&weights, data, nb_s)` | 已确认安全 |
| 8 | TerragenLoader.cpp | 184 | `mNumFaces * 4` | 已确认安全 |

---

## 安全不变量

### Integer Overflow → Underallocation → Heap OOB Write

```
Attacker-controlled count
        ↓
count × constant (uint32_t arithmetic)
        ↓
Integer overflow → truncated to small value
        ↓
resize/new/malloc 分配太小
        ↓
Loop仍然执行原始count次
        ↓
Heap OOB WRITE
```

---

## 研究方法论

1. **Static Recon** — 读取所有importer源码
2. **Pattern Mining** — 搜索所有`count * constant` pattern
3. **Data-flow Analysis** — 追踪每个count从文件到分配的完整数据流
4. **PoC Construction** — 手动修改二进制文件触发溢出
5. **ASan Validation** — 用AddressSanitizer确认crash
6. **Write Primitive Analysis** — 分析写入的可控性
7. **Variant Hunting** — 用提取的不变量扫整个代码库

---

## 研究价值

- 不是"点了一个按钮等crash"
- 而是完整的研究闭环：
  - 输入面分析
  - 静态审计
  - 整数溢出识别
  - PoC构造
  - ASan验证
  - 根因分析
  - 安全不变量提取
  - 变体搜索

---

## 版本信息

- **Target：** Assimp 6.0.5
- **Commit：** 392a658
- **Build：** ASan + UBSan + Debug
