# Paddle-feed Negative col Heap Underflow

> Public status: No public CVE found for the same issue; Paddle also has CVE-2023-38671/38678/52309, CVE-2022-46741 (different functions).

## Submission Fields (per submit.txt)

- **Vendor**: Baidu
- **Product**: PaddlePaddle
- **Version or Commit**: 2.6.2
- **Vulnerability Class**: Access of Memory Location Before Start of Buffer

> ⚠️ Baidu is not in the 110-vendor list in 公司名称.txt, so the platform may not allow selecting this Vendor.

## Vulnerability Submission Details

- **Product and Version**: Baidu PaddlePaddle
- **Vulnerability Name**: Paddle feed negative col heap underflow vulnerability
- **Product Usage**: GitHub PaddlePaddle/Paddle 24,154 stars (2026-11-26 data); a deep learning framework widely used in China, with inference models distributed as .pdmodel/ProgramDesc.
- **Exploitation Conditions**: □ No authentication  □ Low-privileged account required  ☑ User interaction required  □ Only triggered under non-default configuration
- **Description**:

  Summary: Paddle's legacy-IR feed/fetch operators take the signed col attribute from the model protobuf straight as a size_t index without validating col>=0. With col=-1 the value wraps to SIZE_MAX, the vector is resized to zero, and a write goes to vector[SIZE_MAX], i.e. before the start of the buffer, giving a heap underflow write / crash.

  Affected versions: PaddlePaddle 2.6.2 (legacy IR ProgramDesc path retained).

  Attacker input: a malicious .pdmodel/ProgramDesc whose feed operator carries a negative col attribute (int32); the value is read directly from the model file with no sanity check.

  Root cause: paddle/fluid/framework/program_desc.cc:201-205 (GetFeedTargetNames) and 218-222 (GetFetchTargetNames), with the same pattern at analysis_predictor.cc:2446-2460 and api_impl.cc:46-57 (feeds_[idx]). col=-1 is converted to size_t and becomes SIZE_MAX; resize(col+1) wraps to resize(0) leaving the vector empty; the subsequent write to data()-sizeof(element) (or feed_target_names[col]) lands before the allocation.

  Trigger cases: build two feed operators in a legacy Program, the first with col=0 (allocates the vector), the second with col=-1; calling prog.desc.get_feed_target_names() reaches the write point.

  Observed evidence: dynamic reproduction on Ubuntu Linux 6.11.0-29 with Python 3.12 and paddlepaddle 2.6.2; the child process calling get_feed_target_names crashes in ProgramDesc::GetFeedTargetNames → std::string::_M_assign with SIGSEGV (@0x0) and exit code -11, printing RESULT: Paddle feed col=-1 caused ProgramDesc::GetFeedTargetNames crash.

  Impact: a heap underflow write at a controllable position relative to the vector metadata/adjacent objects, causing memory corruption with privilege-escalation/RCE potential.

  Duplicate distinction: no public CVE was found for this issue; the Paddle CVEs CVE-2023-38671/38678/52309 and CVE-2022-46741 are in different functions, whereas this issue is the negative col handling in GetFeedTargetNames/GetFetchTargetNames.

  Fix: validate col >= 0 and within a reasonable upper bound in GetFeedTargetNames/GetFetchTargetNames/PrepareFeedFetch; uniformly use PADDLE_ENFORCE_GE(col, 0) (positive example at new_executor/feed_fetch_utils.cc:34); check the idx range before resize.
- **Details**: Source: the col attribute (int32) of the feed operator in a malicious .pdmodel/ProgramDesc. Sink: paddle/fluid/framework/program_desc.cc:201-205 (GetFeedTargetNames), 218-222 (GetFetchTargetNames); analysis_predictor.cc:2446-2460 and api_impl.cc:46-57 are isomorphic (feeds_[idx]). col=-1 converts to SIZE_MAX as size_t, resize(-1+1)=0, then writes to data()-sizeof(element).
- **Reproduction Environment**: Ubuntu Linux 6.11.0-29, Python 3.12, paddlepaddle 2.6.2 (retaining the legacy IR ProgramDesc); constructs a feed operator of a legacy Program in Python and calls the real ProgramDesc::GetFeedTargetNames.
- **Exploitation Details**: 1. Construct two feed operators: the first col=0 (allocates the vector), the second col=-1.  
  2. Run python exp.py; the child process calls prog.desc.get_feed_target_names().  
  3. Paddle C++ stack: ProgramDesc::GetFeedTargetNames → std::string::_M_assign, SIGSEGV (@0x0), child process exits -11; output RESULT: Paddle feed col=-1 caused ProgramDesc::GetFeedTargetNames crash.
- **PoC Details**: python exp.py  
  (the script constructs two feed operators of a legacy Program in a child process and calls get_feed_target_names; the crash is caught by the parent process, and exp.py exits 0 normally)
- **Remediation**: In GetFeedTargetNames/GetFetchTargetNames/PrepareFeedFetch, validate col >= 0 and col < a reasonable upper bound; uniformly use PADDLE_ENFORCE_GE(col, 0) (there is already a positive example at new_executor/feed_fetch_utils.cc:34); check the idx range before resize.

## Detailed Vulnerability Analysis

### 1. Analysis Path

Starting from the `col` attribute of the `feed` operator in the legacy `ProgramDesc`, check how `ProgramDesc::GetFeedTargetNames()` uses this value to index/expand `feed_target_names`, then trigger it by constructing a real legacy Program in Python.

- Entry: `col` (int32) of the `feed` operator in the `.pdmodel`/ProgramDesc.
- Sink: `paddle/fluid/framework/program_desc.cc:201-205` (`GetFeedTargetNames`), `:218-222` (`GetFetchTargetNames`).

### 2. Input and Validation Gaps

The `col` of `feed` indicates the position of this input in the feed list and comes directly from the model file. `GetFeedTargetNames()` uses `col` as the basis for vector indexing/expansion, but does not validate `col >= 0` or `col < a reasonable upper bound`.

### 3. Root Cause

`col = -1` converts to `size_t` and becomes `SIZE_MAX`:

- If the code executes `resize(col + 1)`, `col + 1` wraps to 0 and the vector remains empty;
- It then writes to `data() - sizeof(element)` or `feed_target_names[col]`, i.e., performs a negative-offset write on the `data()` of an empty vector → heap underflow (the write is located before the allocation).

The same pattern appears in `GetFetchTargetNames()` and in `feeds_[idx]` at `analysis_predictor.cc:2446-2460` and `api_impl.cc:46-57`.

### 4. Trigger and Evidence

Construct two `feed` operators: the first `col=0` (allocates the vector), the second `col=-1`. Call `prog.desc.get_feed_target_names()`, and the heap underflow is triggered at the write point in `program_desc.cc`. The PoC is in `Paddle/PoC/triggers/` and the original submission package.

### 5. Impact

A heap underflow write at a controllable position (before the vector metadata/adjacent objects), which can cause memory corruption; it has privilege-escalation/RCE potential.

### 6. Fix Boundary

Validate `col >= 0` and that it does not exceed the allowed maximum input count; use `.at()` or explicit bounds checks; validate the upper bound of `col` before `resize(col+1)` to avoid the signed-to-unsigned conversion.

## Attachment Screenshots

![Attachment 1](../../Paddle/markdown/assets/image1.png)

![Attachment 2](../../Paddle/markdown/assets/image2.png)

---
> Original form: `Paddle/PoC/Paddle-19-feed/漏洞提交详情表.docx`
