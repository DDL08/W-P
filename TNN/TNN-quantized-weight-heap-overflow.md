# TNN-Quantized Weight Parsing Heap Overflow

> Public status: No TNN-related CVE or security issue found.

## Submission Fields (per submit.txt)

- **Vendor**: Tencent
- **Product**: TNN
- **Version or Commit**: f0cb08129a05c5b60f08e4ef66042a54a883a56a
- **Vulnerability Class**: Heap-based Buffer Overflow

## Vulnerability Submission Details

- **Product and Version**: Tencent TNN
- **Vulnerability Name**: TNN ncnn quantized weight parsing heap buffer overflow vulnerability
- **Product Usage**: GitHub Tencent/TNN 4,667 stars (2026-11-25 GitHub API); a high-performance inference framework open-sourced by Tencent, supporting multi-backend deployment on mobile/desktop/server.

<img width="2549" height="1467" alt="image" src="https://github.com/user-attachments/assets/1533c242-32fe-4da2-a5af-c8c249a35c5f" />

- **Exploitation Conditions**: User interaction required
- **Description**: When TNN loads a model in ncnn format, the quantized-weight branch mixes the attacker-controllable weight count w with a fixed 256-entry/1024-byte buffer, causing a heap out-of-bounds write when w<253 or w>256.
- **Details**: Source: weight_data_size in the ncnn .param text (conv_layer_interpreter.cc:105 etc.). Sink: source/tnn/interpreter/ncnn/serializer.h:94-111. When w<253, index_array.resize(AlignSize(w,4)) is followed by a fixed 256-byte read; when w>256, after a RawBuffer (1024 bytes) a loop writes w floats. Trigger: load a malicious .param/.bin with MODEL_TYPE_NCNN.
- **Reproduction Environment**: Ubuntu Linux 6.11.0-29, g++ 14, AddressSanitizer; TNN commit f0cb08129a05c5b60f08e4ef66042a54a883a56a (2025-03-25). The minimal harness directly compiles the real serializer.h + RawBuffer without building the full inference library.
- **Exploitation Details**: 1. Craft a quantized weight stream with w=1 (4-byte quantization header + 256-float quantization table + 256-byte index).  
  2. Run python exp.py.  
  3. AddressSanitizer reports heap-buffer-overflow, WRITE of size 256, with the stack pointing to serializer.h:101, process exit code -6.
- **PoC Details**: python exp.py  
  (default harness: /home/ddl/ai-audit/repro/tnn/poc; the script builds a w=1 quantized weight stream and calls the real Deserializer::GetRaw)
- **Remediation**: Validate the relation between w and 256; index_array should read only min(256, AlignSize(w,4)) bytes; allocate the output RawBuffer as w*sizeof(float); set an upper bound on weight_data_size and validate it against the remaining length of the .bin.

## Detailed Vulnerability Analysis

### 1. Analysis Path

Starting from `weight_data_size` in the ncnn-format `.param`, enter the quantized-weight branch along TNN's ncnn deserializer, verify the usage relation between "the weight count w" and the fixed 256-entry quantization table/index buffer, and validate by directly calling the real `Deserializer::GetRaw()` with a minimal ASAN harness.

- Entry: `source/tnn/interpreter/ncnn/conv_layer_interpreter.cc` reads `weight_data_size`.
- Sink: `source/tnn/interpreter/ncnn/serializer.h:94-111`.

### 2. Input and Validation Gaps

The stream format of ncnn quantized weights is: 4-byte flag + 256-float quantization table + 256-byte index + data. `w` comes from `weight_data_size` in the `.param` and is controlled by the model file. In the quantized branch where `flag != 0`, `GetRaw()`:

```cpp
size_t index_size = AlignSize(w, 4);
std::vector<unsigned char> index_array;
index_array.resize(index_size);                       // allocated according to w
_istream.read(index_array.data(), 256);               // always reads 256 bytes
value = RawBuffer(256 * sizeof(float));               // fixed 1024 bytes
for (size_t i = 0; i < w; i++)
    ptr[i] = quantization_value[index_array[i]];      // writes w floats
```

There is no validation of whether `w` equals 256, nor of `w*sizeof(float)` against the output buffer, nor of `AlignSize(w,4)` against the 256-byte index read.

### 3. Root Cause

- `w < 253` (e.g., `w=1`): `index_array` is only 4 bytes, yet 256 bytes are read into it → heap out-of-bounds write;
- `w > 256`: `index_array[i]` is an out-of-bounds read, and `ptr[i]` writes past the 1024-byte `RawBuffer` → out-of-bounds write;
- The 256-byte index read comes entirely from the model, and the written value is determined by `quantization_value[index]`, so the attacker can control the written content.

### 4. Trigger and Evidence

Construct a quantized weight stream with `w=1`: 4-byte quantization header + 256-float quantization table + 256-byte index. ASAN reports `heap-buffer-overflow WRITE of size 256`, the stack points to `serializer.h:101`, the target is after the 4-byte `index_array` allocation, and the exit code is `-6`.

### 5. Impact

A heap out-of-bounds write of controllable content (starting at 256 bytes), which can corrupt adjacent heap objects; when `w>256`, out-of-bounds read/write coexist. It has RCE potential.

### 6. Fix Boundary

Require `w == 256` for the quantized branch (or validate against the actual format upper bound); `index_array` should read only `min(256, AlignSize(w,4))` bytes; allocate the output `RawBuffer` as `w*sizeof(float)` and validate; set an upper bound on `weight_data_size` and validate it against the remaining length of the `.bin`.

## PoC Details

Usage:
    python exp.py
Dependencies:
    Python 3.8+, standard library only
    Local ASAN reproduction binary: /home/ddl/ai-audit/repro/tnn/poc
Notes:
    The script builds the malicious input and invokes the local ASAN harness, printing the AddressSanitizer verdict lines. The full chain and verification screenshot are in the bundled submission form (screenshot on the last page).

```python
#!/usr/bin/env python3
# TNN ncnn quantized-weight heap overflow (w=1)
# Usage: python exp.py [harness_path]
import os
import subprocess
import sys

HARNESS = sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
    "TNN_POC", "/home/ddl/ai-audit/repro/tnn/poc")


def main():
    if not os.path.isfile(HARNESS):
        print("[!] harness not found: %s" % HARNESS)
        return 2
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=1")
    p = subprocess.run([HARNESS, "1"], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True, env=env)
    out = p.stdout
    print("[*] target: TNN ncnn .param weight_data_size w=1")
    print("[*] source: source/tnn/interpreter/ncnn/serializer.h:94-111")
    for line in out.splitlines():
        if any(k in line for k in (
                "ERROR: AddressSanitizer", "WRITE of size",
                "serializer.h:101", "SUMMARY: AddressSanitizer")):
            print(line)
    print("[*] exit_code=%d" % p.returncode)
    ok = ("heap-buffer-overflow" in out and "serializer.h:101" in out
          and p.returncode != 0)
    if ok:
        print("RESULT: TNN ncnn quantized-weight heap-buffer-overflow "
              "(serializer.h:101, w=1)")
        return 0
    print("RESULT: NOT REPRODUCED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

Observed ASAN evidence:

```text
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 256
#3 tnn::ncnn::Deserializer::GetRaw(...) source/tnn/interpreter/ncnn/serializer.h:101
SUMMARY: AddressSanitizer: heap-buffer-overflow ... serializer.h:101
```



<img width="1011" height="396" alt="image" src="https://github.com/user-attachments/assets/2ca783fe-a8c2-423a-a9ce-d0900bcf380b" />


## Remediation

Validate the relation between w and 256; index_array should read only min(256, AlignSize(w,4)) bytes; allocate the output RawBuffer as w*sizeof(float); set an upper bound on weight_data_size and validate it against the remaining length of the .bin.


