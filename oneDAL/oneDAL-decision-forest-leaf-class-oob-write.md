# oneDAL Decision Forest Out-of-Bounds Write

> Public status: Only CVE-2022-25905 (search path, unrelated) is public; no CVE for model deserialization was found.

## Submission Fields

- **Vendor**: Intel
- **Product**: oneDAL
- **Version or Commit**: de7fa35
- **Vulnerability Class**: Out-of-bounds Write


## Vulnerability Submission Details

- **Product and Version**: oneapi-src/oneDAL
- **Vulnerability Name**: oneDAL decision forest leaf class label out-of-bounds write vulnerability
- **Product Usage**: GitHub oneapi-src/oneDAL 654 stars (as of 2026-11-26); AI-related native/binary project.

<img width="2556" height="1451" alt="image" src="https://github.com/user-attachments/assets/ff5ce1b4-8595-4e38-8764-d2b208b3ba1e" />


- **Exploitation Conditions**: Requires user interaction
- **Description**:

  Summary: oneDAL decision forest classification prediction uses the model leaf class label as an index into the output buffer without validating it against nClasses, causing a heap out-of-bounds write.

  Affected versions: oneDAL commit de7fa35 (source build used for the reproduction).

  Attacker input: a deserialized decision forest classification model whose leaf-node class label leftIndexOrClass is attacker-controlled; the PoC uses a single leaf with leftIndexOrClass=1,000,000 while the caller passes nClasses=2.

  Root cause: in fillResults() (df_classification_predict_dense_default_batch_impl.i:66-75) the code does const size_t cl = classes[leafsIndexes[i]]; then ++resPtr[i * nClasses + cl]; with no check that cl < nClasses, and DAAL_ASSERT is an empty macro in release builds. predictByTrees at :333 likewise uses resPtr[pNode->leftIndexOrClass] directly. resPtr is allocated only as batch*nClasses, so a class label much larger than nClasses (e.g. 1,000,000) indexes past the buffer.

  Trigger cases: a single-leaf decision forest model with leaf leftIndexOrClass=1,000,000 and nClasses=2; loading the model and calling predict reaches the fillResults/predictByTrees write.

  Observed evidence: SIGSEGV in PredictKernel::compute → PredictClassificationTask::predictByTreesWithoutConversion on a oneDAL de7fa35 static build, where resPtr[0*nClasses+cl] writes directly out of bounds with the controllable offset cl.

  Impact: heap out-of-bounds write with a controllable offset (written value fixed at +1/weight), which can corrupt heap objects after the result buffer, with RCE potential.

  Duplicate distinction: only CVE-2022-25905 (search path, unrelated) is public; no CVE for model deserialization exists, and this issue is the decision forest leaf class label in a different function/field (df_classification_predict_dense_default_batch_impl.i).

  Fix: validate that every leaf class label satisfies 0 <= cl < nClasses and that leaf indices are within the tree table range; change the relevant DAAL_ASSERT to an error return that remains effective in release builds.
- **Details**: Location: decision forest prediction implementation; see 审计/e/oneDAL.md finding 3.
- **Reproduction Environment**: Local dynamic reproduction (2026-11-27): oneDAL de7fa35 source build (static linking); construct a single-leaf decision forest model and call predict.
- **Exploitation Details**: Observed SIGSEGV: PredictKernel::compute → PredictClassificationTask::predictByTreesWithoutConversion; leaf leftIndexOrClass=1,000,000, nClasses=2, and resPtr[0*nClasses+cl] writes directly out of bounds.

## Detailed Vulnerability Analysis

### 1. Analysis Path

Start from decision forest classification model deserialization, check whether leaf node class labels match the caller's `nClasses`, then exercise the real `predict` kernel.

- Model field: leaf node `leftIndexOrClass` (class index).
- Prediction implementation: `df_classification_predict_dense_default_batch_impl.i:66-75`, `:333`.

### 2. Input and Validation Gap

In `fillResults()`:

```cpp
const size_t cl = classes[leafsIndexes[i]];   // leaf node class label, from the model
++resPtr[i * nClasses + cl];                  // no validation of cl < nClasses
```

`nClasses` comes from the caller's parameter, and there is no cross-check of the model leaf class labels; `DAAL_ASSERT` is an empty macro in release builds. `predictByTrees` at `:333` also directly uses `resPtr[pNode->leftIndexOrClass]`.

### 3. Root Cause

A model file can set a leaf node's class label to a value much larger than `nClasses` (e.g. 1,000,000). `resPtr` is allocated only as `batch*nClasses`, and `cl` is used directly as an offset for the write → heap out-of-bounds write with a controllable offset and a fixed written value of `+1`/weight.

### 4. Trigger and Evidence

Construct a single-leaf decision forest model with leaf `leftIndexOrClass=1,000,000` and `nClasses=2`, then call predict. Observed SIGSEGV in `PredictKernel::compute → PredictClassificationTask::predictByTreesWithoutConversion`.

### 5. Impact

Heap out-of-bounds write with a controllable offset; can corrupt heap objects after the result buffer, with RCE potential.

### 6. Remediation Boundary

Validate that every leaf class label satisfies `0 <= cl < nClasses`; validate that leaf indices are within the tree table range; change the relevant `DAAL_ASSERT` to an error return that remains effective in release builds.

## PoC Details

Usage:
    ./exp.py
Dependencies:
    oneDAL static source build
Expected result:
    SIGSEGV in predictByTreesWithoutConversion (PredictKernel::compute)

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""oneDAL decision forest: model leaf class label used as output index."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
LIBPATH = ":".join(["/home/ddl/ai-audit/tbb/lib",
                    "/home/ddl/ai-audit/mklroot/lib",
                    "/home/ddl/ai-audit/mklroot/lib/intel64"])
POC = os.path.join(ROOT, "poc_forest")

env = dict(os.environ)
env["LD_LIBRARY_PATH"] = LIBPATH

print("[poc] running decision forest prediction PoC under gdb ...")
cmd = ["gdb", "-q", "-batch", "-ex", "set pagination off",
       "-ex", "run", "-ex", "bt 6", POC]
proc = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
out = proc.stdout or ""

keys = ("[poc]", "SIGSEGV", "PredictClassificationTask", "predictByTreesWithoutConversion",
        "PredictKernel", "#0", "#1", "#2", "#3")
print("\n" + "=" * 72)
print("KEY EVIDENCE LINES")
print("=" * 72)
for line in out.splitlines():
    if any(k in line for k in keys):
        print(line)

ok = "SIGSEGV" in out and "predictByTreesWithoutConversion" in out
print("=" * 72)
print("RESULT: %s" % ("SIGSEGV in predictByTreesWithoutConversion (PoC succeeded)"
                      if ok else "no crash detected"))
sys.exit(0 if ok else 1)
```

<img width="984" height="372" alt="image" src="https://github.com/user-attachments/assets/320ab124-2086-4c53-85ed-b23961331441" />


## Remediation

Validate leaf class 0 <= cl < nClasses and the leaf index within the tree table.
