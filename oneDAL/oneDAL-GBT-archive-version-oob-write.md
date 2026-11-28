# oneDAL GBT Archive Out-of-Bounds Write

> Public status: Only CVE-2022-25905 (search path, unrelated) is public; no CVE for model deserialization was found.

## Submission Fields (per submit.txt)

- **Vendor**: Intel
- **Product**: oneDAL
- **Version or Commit**: de7fa35
- **Vulnerability Class**: Out-of-bounds Write

> ⚠️ Intel is not in the list of 110 vendors in 公司名称.txt, so the platform may not allow selecting this Vendor.

## Vulnerability Submission Details

- **Product and Version**: oneapi-src/oneDAL
- **Vulnerability Name**: oneDAL GBT archive header version out-of-bounds write vulnerability
- **Product Usage**: GitHub oneapi-src/oneDAL 654 stars (as of 2026-11-26); AI-related native/binary project.
- **Exploitation Conditions**: □No authentication required  □Requires low-privilege account  ☑Requires user interaction  □Only triggered under non-default configuration
- **Description**:

  Summary: oneDAL GBT model deserialization trusts the archive header version; the old-format conversion writes out of bounds to a heap Collection, with a length controlled by the table row count.

  Affected versions: oneDAL commit de7fa35 (source build used for the reproduction).

  Attacker input: a DAAL archive whose header version (headerValues[1..3] in data_archive.h:806-818) is set below 2019 (the PoC uses 2018.0.0) together with a DecisionTreeTable _obsnum=1,000,000 and a root node that is a leaf; both the version and the table shape come from the file.

  Root cause: when version < 2019, deserialize enters convertDecisionTreesToGbtTrees() (gbt_model_impl.h:471-489): allocateGbtTree(tree) derives capacity from the node graph (capacity is only 1 when the root is a leaf), while decisionTreeToGbtTree() (gbt_model.cpp:243-267) loops over DecisionTreeTable::getNumberOfRows() (_obsnum) writing sonsArr/parentsArr; there is no consistency check between the two, and DAAL_ASSERT is an empty macro in release builds. With nSourceNodes = tree.getNumberOfRows() = 1,000,000 and newTree.getNumberOfNodes()+1 = 2, the loop for (i=0;i<nSourceNodes;++i) sons[i]=nullptr; parents[i]=nullptr; writes past the Collection allocation.

  Trigger cases: a DAAL archive with version 2018.0.0, DecisionTreeTable _obsnum=1,000,000, and a leaf root node; deserialize() then reaches the old-format conversion and the write loop driven by the table row count.

  Observed evidence: SIGSEGV during deserialize (gdb stack: deserializeImpl → convertDecisionTreesToGbtTrees → decisionTreeToGbtTree) on a oneDAL de7fa35 static build, where the number of writes follows the table row count with no consistency check.

  Impact: heap out-of-bounds write at load time, with a controllable number of writes (table row count), which can corrupt heap metadata/adjacent objects, with RCE potential.

  Duplicate distinction: only CVE-2022-25905 (search path, unrelated) is public; no CVE for model deserialization exists, and this issue is the GBT archive-version conversion in a different function/field (gbt_model.cpp:243-267).

  Fix: before entering the old-format conversion, validate that nSourceNodes matches the capacity derived by allocateGbtTree; use an allowlist for archive versions; change DAAL_ASSERT to a check that remains effective in release builds.
- **Details**: Location: gbt_model.cpp:243-267; see 审计/e/oneDAL.md finding 1.
- **Reproduction Environment**: Local dynamic reproduction (2026-11-27): oneDAL de7fa35 source build (static linking); construct a DAAL archive and set the version to 2018.0.0.
- **Exploitation Details**: Observed SIGSEGV: deserializeImpl → convertDecisionTreesToGbtTrees → decisionTreeToGbtTree; DecisionTreeTable _obsnum=1,000,000, with the root node as a leaf (allocateGbtTree capacity is only 1); the number of writes follows the table row count, with no consistency check.

## Detailed Vulnerability Analysis

### 1. Analysis Path

Start from the DAAL archive header version field, check whether `deserialize` validates the "source table row count" against the "new tree capacity" in the old-version branch, then verify through the public `SerializationIface::deserialize` path.

- Version source: `headerValues[1..3]` in `data_archive.h:806-818`.
- Old-format branch: `gbt_model_impl.h:471-489` → `convertDecisionTreesToGbtTrees`.
- Out-of-bounds point: `decisionTreeToGbtTree` in `gbt_model.cpp:243-267`.

### 2. Input and Validation Gap

The archive header version is entirely controlled by the file. When version < 2019, execution enters `convertDecisionTreesToGbtTrees()`: `allocateGbtTree(tree)` derives capacity from the node graph (capacity is only 1 when the root is a leaf), while `decisionTreeToGbtTree()` loops over `DecisionTreeTable::getNumberOfRows()` (`_obsnum`) writing `sonsArr`/`parentsArr`; there is no consistency check between the two; `DAAL_ASSERT` is an empty macro in release builds.

### 3. Root Cause

`nSourceNodes = tree.getNumberOfRows()` can be 1,000,000, while `newTree.getNumberOfNodes()+1` is only 2; the loop `for (i=0;i<nSourceNodes;++i) sons[i]=nullptr; parents[i]=nullptr;` directly writes out of bounds into the `Collection` on the heap.

### 4. Trigger and Evidence

Construct a DAAL archive: set the version to 2018.0.0, `DecisionTreeTable _obsnum=1,000,000`, with the root node as a leaf; during `deserialize`, SIGSEGV occurs in `decisionTreeToGbtTree` (gdb stack: `deserializeImpl → convertDecisionTreesToGbtTrees → decisionTreeToGbtTree`).

### 5. Impact

Heap out-of-bounds write during load, with a controllable number of writes (table row count), which can corrupt heap metadata/adjacent objects, with RCE potential.

### 6. Remediation Boundary

Before entering the old-format conversion, validate that `nSourceNodes` is consistent with the capacity derived by `allocateGbtTree`; use an allowlist for archive versions; change `DAAL_ASSERT` to a check that remains effective in release builds.

## PoC Details

Usage:
    ./exp.py
Dependencies:
    oneDAL static source build
Expected result:
    SIGSEGV in decisionTreeToGbtTree (convertDecisionTreesToGbtTrees)

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""oneDAL GBT: legacy archive version (2018) -> convertDecisionTreesToGbtTrees()
writes one entry per AOS table row into a tree sized from the node graph."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
D = "/home/ddl/ai-audit/wave3/e/oneDAL/__release_lnx_gnu/daal/latest"
LIBPATH = ":".join(["/home/ddl/ai-audit/tbb/lib",
                    "/home/ddl/ai-audit/mklroot/lib",
                    "/home/ddl/ai-audit/mklroot/lib/intel64"])
POC = os.path.join(ROOT, "poc_gbt")

env = dict(os.environ)
env["LD_LIBRARY_PATH"] = LIBPATH

print("[poc] running GBT deserialization PoC under gdb ...")
cmd = ["gdb", "-q", "-batch", "-ex", "set pagination off",
       "-ex", "run", "-ex", "bt 6", POC]
proc = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
out = proc.stdout or ""

keys = ("[poc]", "SIGSEGV", "decisionTreeToGbtTree", "convertDecisionTreesToGbtTrees",
        "deserializeImpl", "#0", "#1", "#2", "#3")
print("\n" + "=" * 72)
print("KEY EVIDENCE LINES")
print("=" * 72)
for line in out.splitlines():
    if any(k in line for k in keys):
        print(line)

ok = "SIGSEGV" in out and "decisionTreeToGbtTree" in out
print("=" * 72)
print("RESULT: %s" % ("SIGSEGV in decisionTreeToGbtTree during model deserialization (PoC succeeded)"
                      if ok else "no crash detected"))
sys.exit(0 if ok else 1)
```

## Attachment Screenshots

![Attachment 1](../../oneDAL/markdown/assets/image1.png)

![Attachment 2](../../oneDAL/markdown/assets/image2.png)

---
> Original form: `oneDAL/PoC/oneDAL-45-GBT/漏洞提交详情表.docx`

## Remediation

Validate nSourceNodes against the allocateGbtTree capacity; allowlist archive versions.
