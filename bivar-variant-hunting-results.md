# BIVAR Variant Hunting — Assimp Integer-Overflow-to-OOB Audit

**Target**: Assimp 6.0.5 (commit 392a658)
**Seed vulnerability**: SIB importer `numPoints * 3` integer overflow → heap OOB write
**Method**: Security-invariant extraction → codebase-wide pattern search → manual data-flow triage

---

## 1. Extracted Security Invariant

From the SIB bug (`SIBImporter.cpp:249`, ReadFaces):

```c
size_t pos = mesh->idx.size() + 1;
mesh->idx.resize(pos + numPoints * N);   // N = 3, 32-bit multiply
for (n = 0; n < numPoints; n++)
    idx[n*3 + k] = value;                // write loop uses ORIGINAL count
```

The violated invariant:

> When an allocation size is derived as `count * elements_per_item`,
> the multiplication must use overflow-safe (size_t) arithmetic, AND
> `allocated_elements >= count * elements_per_item` must hold for every
> subsequent write loop.

**Canonical vulnerable pattern:**

```
attacker count
      ↓
count * CONSTANT        (narrow 32-bit arithmetic)
      ↓
integer overflow → small/truncated size
      ↓
resize / new / malloc   (undersized buffer)
      ↓
for (i < count) write   (loop bound uses un-truncated count)
      ↓
heap OOB WRITE
```

---

## 2. Search Strategy

BIVAR's variant hunter (augmented with targeted grep over `code/AssetLib/`)
searched for:

- `count * 2`, `count * 3`, `count * 4`
- `count * sizeof(T)`
- `width * height`, `rows * cols`
- allocation sites (`resize`, `new[]`, `malloc`, `reserve`)
- followed by indexed writes / `memcpy`

---

## 3. Candidate Triage Table

| ID | File:Line | Expression | Allocation | Write | Verdict |
|----|-----------|-----------|------------|-------|---------|
| V-01 | SIB/SIBImporter.cpp:243 | `numPoints * 3` | `resize` | loop write | **CONFIRMED OOB WRITE** (known #6733) |
| V-02 | MDL/MDLLoader.cpp:489 | `num_tris * 3` | `new aiVector3D[]` | later fill | Candidate — binary format, needs PoC |
| V-03 | MDL/MDLLoader.cpp:683/697 | `num_tris * 3` | `new aiVector3D[]` | later fill | Candidate — same pattern as V-02 |
| V-04 | MDL/MDLLoader.cpp:1516 | `numtris * 3` | `vector.resize` | later fill | Candidate — MDL7 split group |
| V-05 | MDL/MDLLoader.cpp:1867 | `mNumFaces * 3` | `new aiVector3D[]` | later fill | Candidate — derived count |
| V-06 | Unreal/UnrealLoader.cpp:437 | `num * 3` | `new aiVector3D[]` | later fill | Candidate — numFaces from file |
| V-07 | 3DS/3DSConverter.cpp:148 | `mFaces.size() * 3` | vector ctor | loop `size()*3` | **Safe** — loop bound matches |
| V-08 | ASE/ASEParser.cpp:1653 | `mFaces.size() * 3` | `resize` | bounded by faceIdx check | **Safe** — bounds check present |
| V-09 | CSM/CSMLoader.cpp:213 | `alloc * 2` | `new[]` doubling | memcpy `alloc` | **Safe** — geometric growth, no wrap |
| V-10 | Terragen/TerragenLoader.cpp:184 | `mNumFaces * 4` | `new aiVector3D[]` | nested loop | **Safe** — x,y are int16, no wrap |
| V-11 | M3D/m3d.h:2099 | `memcpy(weights, data, nb_s)` | `weights[8]` stack | memcpy | **Safe** — nb_s ∈ {1,2,4,8} |
| V-12 | MDL/MDLMaterialLoader.cpp:417 | `mWidth` | `new unsigned char[mWidth]` | memcpy mWidth | **Safe** — alloc == copy size |
| V-13 | MDL/MDLLoader.cpp:1450 | `iGroup * MAX_NAME` | group-name buffer | fixed-size memcpy | Candidate — needs groups_num overflow PoC |

---

## 4. Confirmed Findings

### V-01 — SIB Heap OOB WRITE (seed bug, known #6733)
- ASan: `heap-buffer-overflow WRITE of size 4 @ SIBImporter.cpp:249`
- PoC: `numPoints = 0x55555556`, product truncates 0x100000002 → 2
- Full primitive analysis: see `sib-primitive-analysis.md`

### Confirmed OOB reads found during the same audit campaign
- IQM `first_vertex * step` overflow → SEGV READ (known #6708)
- IQM `num_triangles` oversized → heap OOB READ (novelty unconfirmed)
- AMF `width * height` overflow → division by zero SIGFPE (reported upstream)

---

## 5. Why most candidates are safe

The audit demonstrates that a multiplication alone is **not** a vulnerability.
Each candidate was traced through the full data flow and rejected when any of
these held:

1. **Loop bound equals allocation** — `for i < size()` where allocation used `size()*3`
2. **Narrow inputs can't wrap** — int16 dimensions, 2-bit fields (nb_s)
3. **Explicit bounds checks** guard the later index (`if (faceIdx >= size()) continue`)
4. **Geometric growth** (`alloc*2`) starts small and cannot reach wrap
5. **Alloc == copy length** in memcpy

This is the core discipline BIVAR enforces: pattern match → data-flow proof →
dynamic validation, never "there's a multiply, therefore bug."

---

## 6. Outstanding candidates (next dynamic-validation queue)

The MDL family (V-02..V-05) and Unreal (V-06) share the seed pattern but use
binary container formats. They require a valid base sample plus targeted
field mutation (same methodology used successfully for SIB/IQM):

1. Obtain a minimal valid .mdl / .unreal sample
2. Locate the triangle/face count field
3. Set it to a wrap value (e.g. `0x55555556` for `*3`)
4. Run under ASan, observe whether allocation truncates before fill

---

## 7. Reusable artifact

The invariant and pattern are encoded for BIVAR's variant hunter so the same
audit can be re-run on future Assimp releases and ported to other native
parsers (Open Asset Import alternatives, geometry/mesh libraries):

```
INVARIANT: alloc_count(count, E) >= count * E   (overflow-safe width)
PATTERN:   [count * E -> alloc] dominated-by [count-bounded write]
GUARD:     checked_mul / size_t width + alloc-success check
```
