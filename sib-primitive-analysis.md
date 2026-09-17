# SIB Heap OOB Write — Primitive Analysis Report

## Target
- **Project**: Assimp 6.0.5 (commit 392a658)
- **File**: `code/AssetLib/SIB/SIBImporter.cpp`
- **Function**: `ReadFaces()`
- **Line**: 249
- **Known Issue**: Highly likely matches public issue #6733

---

## 1. Vulnerability Chain

```
Attacker-controlled SIB file
        ↓
FACS chunk: numPoints field
        ↓
numPoints = 0x55555556
        ↓
numPoints * N (N=3) = 0x100000002
        ↓
uint32_t truncation → 0x00000002
        ↓
mesh->idx.resize(pos + 2)  ← undersized allocation
        ↓
Loop still executes 0x55555556 times
        ↓
Heap OOB WRITE
```

---

## 2. Allocation Analysis

### Code
```cpp
size_t pos = mesh->idx.size() + 1;
mesh->idx.resize(pos + numPoints * N);  // N = 3
mesh->idx[pos - 1] = numPoints;
uint32_t *idx = &mesh->idx[pos];
```

### Arithmetic
| Variable | Value |
|----------|-------|
| `numPoints` | 0x55555556 (attacker-controlled) |
| `N` | 3 |
| `numPoints * N` (uint32_t) | 0x100000002 → truncated to 2 |
| `pos` (first FACS chunk) | 1 |
| **Actual allocation** | `resize(1 + 2) = 3 uint32_t = 12 bytes` |
| **Expected allocation** | `1 + 0x100000002 uint32_t` (~16GB) |

---

## 3. Write Loop Analysis

### Code
```cpp
for (uint32_t n = 0; n < numPoints; n++, idx += N, ptIdx++) {
    uint32_t p = stream->GetU4();
    if (p >= mesh->pos.size())
        throw DeadlyImportError("Vertex index is out of range.");
    idx[POS] = p;        // WRITE 1
    idx[NRM] = ptIdx;    // WRITE 2
    idx[UV] = ptIdx;     // WRITE 3
}
```

### Write Properties

| Property | Value | Attacker-Controlled? |
|----------|-------|---------------------|
| Iteration count | 0x55555556 | ✅ Yes (numPoints) |
| Write granularity | 4 bytes (uint32_t) | - |
| Stride | 12 bytes (N=3 uint32_t) | - |
| **idx[POS] value** | `p` from `stream->GetU4()` | ✅ **Fully controlled** |
| idx[NRM] value | `ptIdx` (counter) | ❌ No |
| idx[UV] value | `ptIdx` (counter) | ❌ No |
| First OOB offset | byte 12 (after 3 valid uint32_t) | ✅ Predictable |

### Bounds Check Bypass
The check `if (p >= mesh->pos.size())` is bypassed when:
- The stream reaches EOF during the massive loop
- `StreamReaderLE::GetU4()` returns 0 at EOF
- `p = 0 < mesh->pos.size()` (vertices exist from earlier chunks)
- Check passes, OOB write continues with value 0

---

## 4. Write Primitive Summary

### Primitive Type
**Sequential heap OOB write with attacker-controlled value at fixed stride**

### Formula
```
write_address = base_allocation + 12 + n * 12    (n = 0, 1, 2, ...)
write_value_at_POS   = attacker_input (or 0 at EOF)
write_value_at_NRM   = n (sequential counter)
write_value_at_UV    = n (sequential counter)
```

### Controllability Matrix
| Aspect | Rating | Notes |
|--------|--------|-------|
| Write value | 🟡 Partial | POS channel controlled; NRM/UV are counters |
| Write offset | 🟡 Sequential | Fixed stride of 12 bytes, cannot seek arbitrarily |
| Write count | ✅ Controlled | Via numPoints |
| Write size | ❌ Fixed | 4 bytes per write |
| Relative offset | ✅ Controlled | First chunk vs later chunks changes base |

---

## 5. Post-Corruption Code Path

After the loop (if it completes):
```cpp
mesh->nrm.resize(ptIdx, aiVector3D(0, 0, 0));   // ptIdx = 0x55555556
mesh->uv.resize(ptIdx, aiVector3D(0, 0, 0));    // likely std::bad_alloc
mesh->numPts = ptIdx;
```

And in `ReadUVs()`:
```cpp
uint32_t id = idx[UV];
mesh->uv[id].x = stream->GetF4();   // uses corrupted idx as array index
mesh->uv[id].y = stream->GetF4();
```

**Key insight**: Corrupted `idx[UV]` / `idx[NRM]` values are later used as **array indices** into `mesh->uv[]` / `mesh->nrm[]`. This creates a potential second-stage primitive:
- OOB write corrupts an index value
- Corrupted index used for OOB write/read into uv/nrm arrays
- Could extend exploitation reach

---

## 6. ASan Evidence

```
==1077539==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x5020000004fc
WRITE of size 4 at 0x5020000004fc thread T0
    #0 0x7ffff686fade in ReadFaces
       /home/yhh/assimp-research/assimp/code/AssetLib/SIB/SIBImporter.cpp:249
```

- **Operation**: WRITE
- **Size**: 4 bytes
- **Allocator**: heap (std::vector<uint32_t> backing buffer)

---

## 7. Exploitability Assessment

### Strengths
- Integer overflow → undersized allocation is a classic exploitable pattern
- POS channel write value is attacker-controlled
- Adjacent heap objects (other SIBMesh fields, other mesh data) could be corrupted
- Later code path uses corrupted indices (potential for controlled OOB)

### Limitations
- Fixed stride (12 bytes), cannot write at arbitrary offsets
- Only 1 of every 3 written uint32_t is attacker-controlled
- ASan crashes immediately; real exploitation requires heap feng shui
- C++ std::vector heap layout differs from raw malloc (metadata, capacity)
- The massive loop count (0x55555556) means corruption extends very far, likely segfault quickly without precise heap control

### Required for Full Exploitation
1. Heap layout grooming to place target object adjacent
2. Identify a valuable adjacent object (vtable pointer, length field, function pointer)
3. Control which POS values land at the target offset
4. Bypass ASan (not present in release builds)
5. Defeat modern glibc heap hardening (tcache, safe-linking)

---

## 8. Security Invariant

Extracted from this vulnerability:

```
For any allocation of the form:
    buffer.resize(count * ELEMENTS)

followed by a loop:
    for (i = 0; i < count; i++)
        buffer[i * ELEMENTS + k] = value;

The following MUST hold:
    1. count * ELEMENTS must not overflow (use size_t / checked arithmetic)
    2. allocated_elements >= count * ELEMENTS
    3. The arithmetic type in the allocation must match (or be wider than)
       the loop counter type
```

### Variant Search Pattern
```
count * constant  →  resize/new/malloc  →  for(count)  →  WRITE
```

---

## 9. Conclusion

This is a genuine **integer-overflow-induced heap OOB write** with partial attacker control over written values. While immediate RCE is not demonstrated, the primitive is real and follows a classic exploitation pattern. The primary portfolio value is:

1. Complete root-cause reconstruction
2. Primitive characterization (value/offset/count controllability)
3. Security invariant extraction
4. Foundation for systematic variant hunting

**Classification**: Heap-based out-of-bounds write caused by integer overflow (NOT RCE).
