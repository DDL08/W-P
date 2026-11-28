# oneDAL kNN Stack Overflow

> Public status: Only CVE-2022-25905 (search path, unrelated) is public; no CVE for model deserialization was found.

## Submission Fields (per submit.txt)

- **Vendor**: Intel
- **Product**: oneDAL
- **Version or Commit**: de7fa35
- **Vulnerability Class**: Stack-based Buffer Overflow

> ⚠️ Intel is not in the list of 110 vendors in 公司名称.txt, so the platform may not allow selecting this Vendor.

## Vulnerability Submission Details

- **Product and Version**: oneapi-src/oneDAL
- **Vulnerability Name**: oneDAL kNN model index stack overflow vulnerability
- **Product Usage**: GitHub oneapi-src/oneDAL 654 stars (as of 2026-11-26); AI-related native/binary project.
- **Exploitation Conditions**: □No authentication required  □Requires low-privilege account  ☑Requires user interaction  □Only triggered under non-default configuration
- **Description**:

  Summary: oneDAL KD-tree kNN prediction uses leftIndex/rightIndex from the model as the length for a fixed 32-element stack array distance[], causing a stack buffer overflow.

  Affected versions: oneDAL commit de7fa35 (source build used for the reproduction).

  Attacker input: a deserialized KD-tree kNN classification model whose leaf-node fields leftIndex/rightIndex (KDTreeNode in kdtree_knn_classification_model_impl.h:38-44,118-127) are attacker-controlled; the PoC uses dimension=SIZE_MAX, leftIndex=0, rightIndex=10,000,000, rootNodeIndex=0.

  Root cause: the prediction kernel (kdtree_knn_classification_predict_dense_default_batch_impl.i:358-370) declares DAAL_ALIGNAS(256) algorithmFpType distance[__KDTREE_LEAF_BUCKET_SIZE + 1] (32 elements) and calls computeDistance(start, end, distance, ...), which zeroes distance[i-start] for i in [start,end). Input::check only verifies that KDTreeTable is a 4-column AOS and rootNodeIndex < row count; it does not validate the leaf interval end-start <= 32, so a model can set rightIndex arbitrarily large.

  Trigger cases: a single-leaf model with dimension=SIZE_MAX, leftIndex=0, rightIndex=10,000,000, rootNodeIndex=0; after loading, call predict so that the leaf interval end-start far exceeds the 32-element bucket.

  Observed evidence: SIGSEGV during the out-of-bounds memset inside KNNClassificationPredictKernel::findNearestNeighbors with a corrupted stack (gdb reports corrupt stack); reproduced on a oneDAL de7fa35 GNU/TBB/MKL build.

  Impact: stack buffer overflow with a model-controlled length, with RCE potential; the most direct consequence is a crash.

  Duplicate distinction: only CVE-2022-25905 (search path, unrelated) is public; no CVE for model deserialization exists, and this issue is the kNN KD-tree leaf-interval length in a different function/field.

  Fix: validate rightIndex >= leftIndex and rightIndex-leftIndex <= __KDTREE_LEAF_BUCKET_SIZE, and that the leaf interval falls within the data table row count; perform these checks uniformly in Input::check or at the kernel entry point.
- **Details**: Location: kdtree_knn_...impl.i:358-370; see 审计/e/oneDAL.md finding 2.
- **Reproduction Environment**: Local dynamic reproduction (2026-11-27): oneDAL de7fa35 source build (GNU/TBB/MKL); load a deserialized kNN model and call predict.
- **Exploitation Details**: Observed SIGSEGV: out-of-bounds memset write inside KNNClassificationPredictKernel::findNearestNeighbors (distance[32] stack array; model leaf leftIndex=0/rightIndex=10,000,000), corrupting the stack (gdb: corrupt stack).

## Detailed Vulnerability Analysis

### 1. Analysis Path

Start from oneDAL KD-tree kNN model deserialization, check whether `leftIndex/rightIndex` in the model match the leaf bucket capacity, then exercise the real `predict` kernel and observe the crash point with gdb.

- Model fields: `KDTreeNode{leftIndex,rightIndex}` in `kdtree_knn_classification_model_impl.h:38-44,118-127`.
- Prediction kernel: `kdtree_knn_classification_predict_dense_default_batch_impl.i:358-370`.

### 2. Input and Validation Gap

The prediction kernel declares a fixed 32-element stack array:

```cpp
DAAL_ALIGNAS(256) algorithmFpType distance[__KDTREE_LEAF_BUCKET_SIZE + 1]; // 32
...
start = node->leftIndex;
end   = node->rightIndex;
computeDistance(start, end, distance, ...);   // for (i=start; i<end; ++i) distance[i-start]=0
```

`Input::check` only verifies that KDTreeTable is a 4-column AOS and `rootNodeIndex < row count`; it **does not validate that the leaf interval `end-start <= 32`**. A model file can set `rightIndex` to any large value.

### 3. Root Cause

`computeDistance` zeroes `distance[i-start]` before accessing the data table; when `end-start > 32`, a stack out-of-bounds write occurs first, followed by reads from the data table using the out-of-bounds index. Stack protection is corrupted, and gdb reports `corrupt stack`.

### 4. Trigger and Evidence

Construct a single-leaf model: `dimension=SIZE_MAX`, `leftIndex=0`, `rightIndex=10,000,000`, `rootNodeIndex=0`; load it and call predict. Observed SIGSEGV in the memset inside `KNNClassificationPredictKernel::findNearestNeighbors`, with the stack corrupted.

### 5. Impact

Stack buffer overflow with controllable length (model fields), with RCE potential; the most direct consequence is a crash.

### 6. Remediation Boundary

Validate that `rightIndex >= leftIndex` and `rightIndex-leftIndex <= __KDTREE_LEAF_BUCKET_SIZE`; validate that the leaf interval falls within the data table row count; perform these checks uniformly in `Input::check` or at the kernel entry point.

## PoC Details

Usage:
    ./exp.py
Dependencies:
    oneDAL source build (GNU/TBB/MKL)
Expected result:
    SIGSEGV in KNNClassificationPredictKernel::findNearestNeighbors (corrupt stack)

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""oneDAL kd-tree kNN: model-controlled left/rightIndex -> stack buffer overflow."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
D = "/home/ddl/ai-audit/wave3/e/oneDAL/__release_lnx_gnu/daal/latest"
LIBPATH = ":".join([
    D + "/lib/intel64",
    "/home/ddl/ai-audit/tbb/lib",
    "/home/ddl/ai-audit/mklroot/lib/intel64",
    "/home/ddl/ai-audit/mklroot/lib",
])
POC = os.path.join(ROOT, "poc_new")

env = dict(os.environ)
env["LD_LIBRARY_PATH"] = LIBPATH

print("[poc] running oneDAL kNN PoC under gdb ...")
cmd = ["gdb", "-q", "-batch", "-ex", "set pagination off",
       "-ex", "run", "-ex", "bt 4", POC]
proc = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
out = proc.stdout or ""

keys = ("[poc]", "SIGSEGV", "findNearestNeighbors", "memset", "corrupt stack", "#0", "#1")
print("\n" + "=" * 72)
print("KEY EVIDENCE LINES")
print("=" * 72)
for line in out.splitlines():
    if any(k in line for k in keys):
        print(line)

ok = "SIGSEGV" in out and "findNearestNeighbors" in out
print("=" * 72)
print("RESULT: %s" % ("SIGSEGV in KNNClassificationPredictKernel::findNearestNeighbors (PoC succeeded)"
                      if ok else "no crash detected"))
sys.exit(0 if ok else 1)
```

## Attachment Screenshots

![Attachment 1](../../oneDAL/markdown/assets/image1.png)

![Attachment 2](../../oneDAL/markdown/assets/image2.png)

---
> Original form: `oneDAL/PoC/oneDAL-42-kNN/漏洞提交详情表.docx`

## Remediation

Validate the leaf interval rightIndex-leftIndex <= 32 and that it falls within the data table rows.
