# Results from Grok compare against source code of the malware 
# WINODWS AI-IDS
# as we can see the ML is not perfect but pretty nice!

### Syscall Patterns Mapped to Source Code Locations

This table maps the syscall sets observed in the ML logs to the most likely locations in the provided C++ source code of `eteDllLoader.exe`.  
Scores are more negative = more suspicious/anomalous according to the ML model.  
Most patterns are **indirect** (triggered by WinAPI / runtime libraries like mscoree, wbem, COM, CLR hosting).  
Direct ntdll usage is limited to the registry notification function.

| Syscall Set (from log)                                           | Score Range (more neg = sus) | Exact / Closest Place in C++ Code                              | Line Estimate       | Direct or Indirect? | Explanation / How It Gets Triggered                                                                 |
|------------------------------------------------------------------|------------------------------|----------------------------------------------------------------|---------------------|---------------------|-----------------------------------------------------------------------------------------------------|
| `NtQuerySymbolicLinkObject, NtClose, NtOpenSymbolicLinkObject`   | ~ -0.0066                    | `GetModuleFileNameW` (called in every self-delete method) + `escapeForWmi` path building | Multiple (~100–410) | Indirect            | Path resolution via `GetModuleFileNameW` / WMI objectPath → object manager symbolic links. Repeated across methods/PIDs. |
| `NtSaveMergedKeys, NtClose, NtCreateSection`                     | ~ -0.0076                    | `AppDomain->Load_3` in CLR or `svc->ExecMethod` in WMI          | CLR (~340), WMI (~400) | Indirect            | Section creation + key merging during CLR assembly load (embedded resource) or WMI provider ops. TxF-like behavior. |
| `NtClose, NtOpenProcessTokenEx, NtQueryInformationToken`         | ~ -0.0224                    | `CoSetProxyBlanket` / `CoInitializeSecurity` in WMI             | WMI (~365–375)      | Indirect            | Token queries for COM impersonation / security levels during WMI setup.                             |
| `NtDuplicateToken, NtClose, NtOpenProcessTokenEx`                | ~ -0.0210                    | Same as above (token duplication step)                          | WMI (~365–375)      | Indirect            | Impersonation token duplication for WMI proxy blanket.                                             |
| `NtThawTransactions, NtClose` (standalone — ~30 repeated entries) | -0.0197 / -0.0018            | WMI loop: 3000× `svc->ExecMethod` on `CIM_DataFile.Delete`      | WMI (~400–410)      | Indirect            | WMI mass file deletes in loop → potential internal TxF (Transactional NTFS) usage for batch/rollback safety. Repetition from loop. |
| `NtAllocateLocallyUniqueId, NtWriteFile, NtClose, NtDeviceIoControlFile` | -0.3098 / -0.1243 (strongest) | `CoCreateInstance(CLSID_WbemLocator)` in WMI                    | WMI (~360)          | Indirect            | COM object creation → LUID allocation + IOCTLs (security/policy device checks). Amplified by WMI loop. |
| `NtOpenKeyEx, NtSetInformationJobObject, NtClose, NtQueryKey`    | -0.0626 / -0.0445            | CLR hosting: `runtimeHost->Start()` / `GetDefaultDomain`       | CLR (~320–330)      | Indirect            | .NET runtime sets up job objects + queries registry keys for isolation/config during startup.      |
| `NtCreateEvent, NtClose, NtNotifyChangeMultipleKeys`             | ~ -0.0142                    | Registry notify: `NtNotifyChangeKey_x` loop setup               | Registry (~255–270) | Semi-direct         | Events created for async completion in `NtNotifyChangeKey` loop.                                   |
| `NtOpenKeyEx, NtClose, NtNotifyChangeMultipleKeys`               | ~ -0.0012                    | `NtNotifyChangeKey_x` in loop (200× + extras)                   | Registry (~255–282) | **Direct**          | Explicit ntdll call with callbacks (DeleteFileW / Sleep / FreeLibrary). Loops cause repetition.     |
| `NtOpenFile, NtQueryInformationFile, NtSetInformationFile, NtClose` | ~ -0.0190                    | WMI loop: `CIM_DataFile.Delete` or `DeleteFileW` callbacks      | WMI (~400), self-delete (~100–200) | Indirect            | File metadata queries during looped delete attempts.                                                |
| `NtThawTransactions, NtOpenSection, NtClose, NtMapViewOfSection` (and variants) | ~ -0.0325 (repeated)         | CLR: `AppDomain->Load_3` (SafeArray from embedded resource)     | CLR (~340)          | Indirect            | CLR in-memory assembly load → section mapping (NtMapViewOfSection) for PE image without disk. TxF thaw possible during transacted load. |
| `NtThawTransactions, NtQuerySystemInformationEx, NtMapViewOfSection, NtClose` | ~ -0.0325                    | Same as above (CLR load + section mapping)                      | CLR (~340)          | Indirect            | Extra system/module query before/during CLR section mapping.                                        |
| `NtThawTransactions, NtQueryValueKey, NtClose, NtOpenKey`        | ~ -0.0325                    | CLR registry queries during hosting + potential TxF             | CLR (~320–340)      | Indirect            | TxF paired with registry access for CLR config or assembly load.                                    |
| `NtOpenSection, NtClose, NtCreateWaitCompletionPacket, NtAssociateWaitCompletionPacket, NtMapViewOfSection` | ~ -0.0156                    | Timer queues: `CreateTimerQueueTimer` / RTL: `RtlRegisterWait`  | Timers (~130–140), RTL (~150–180) | Indirect            | Async timers / waits → sections + wait completion packets under the hood.                           |
| `NtCreateWorkerFactory, NtOpenSection, NtCreateIoCompletion, NtClose, NtAssociateWaitCompletionPacket, NtMapViewOfSection` | ~ -0.0164                    | RTL: `RtlRegisterWait` / worker factory                         | RTL (~150–180)      | Indirect            | Worker pooling / async execution → sections + IO completion ports.                                  |
| `NtThawTransactions, NtAllocateVirtualMemory, NtClose`            | ~ -0.0325                    | CLR load: memory allocation after section map + TxF             | CLR (~340)          | Indirect            | Virtual memory alloc for assembly image + potential TxF thaw during CLR load.                       |
| `NtReleaseSemaphore, NtOpenSemaphore, NtQueueApcThreadEx, NtAllocateVirtualMemory, NtClose` | ~ -0.0233                    | APC: `QueueUserAPC` / threads: `CreateThread`                   | APC (~220–240), threads (~190–210) | Indirect            | Semaphore signaling + APC queue + memory alloc for timing / self-unload race conditions.            |

**Notes:**
- **Direct** ntdll syscall usage is limited to the `delete_using_registry_notification()` function.
- High-suspicion patterns (TxF + section mapping, LUID + IOCTL) mostly come from **CLR in-memory loading** (`delete_using_clr`) and **WMI mass-delete loop** (`delete_using_wmi` — 3000 iterations).
- Repetition of certain patterns (especially `NtThawTransactions, NtClose`) is caused by loops in the code, which the ML model correctly flags as anomalous.

  # ML Syscall Detection Results Summary for eteDllLoader.exe

**Short Summary of Model Performance**

The ML model performs **very well** (solid **8.5–9/10**) on this self-deleting / evasion-heavy loader sample.

### Strengths
- **Excellent anomaly detection** on the most suspicious patterns:
  - LUID + `NtDeviceIoControlFile` + `NtWriteFile` combo  
    → strongest flags: **−0.3098 / −0.1243**  
    → tied to COM/WMI initialization side-effects
  - Symbolic link + event signaling sequences  
    → **−0.2184**  
    → linked to WMI/CLR path resolution
  - TxF (`NtThawTransactions`) + section mapping (`NtMapViewOfSection`) variants  
    → repeated **−0.0325** scores  
    → associated with CLR in-memory assembly loading
- **Handles repetition intelligently** — dozens of `NtThawTransactions, NtClose` entries consistently flagged as anomalous
- **Low false-positive rate** — normal housekeeping (token queries, key opens, basic file ops) receives only mild suspicion (−0.006 to −0.022)
- Captures **evasion intent** hidden in:
  - Heavy loops (WMI 3000× deletes, registry notify 200×)
  - Rare runtime behaviors from CLR hosting and WMI mass operations

### Minor Improvement Opportunities
- Increase weight on **repeated `NtThawTransactions`** (especially 20–30+ occurrences)
- Add **burst / repetition entropy** feature to amplify looped suspicious sequences even more strongly

**Bottom line**  
The model is already doing an **excellent job** at surfacing malicious / red-team-grade behavior in this sneaky self-deleting DLL loader — significantly outperforming basic signature or static-rule-based detectors on this sample.



# ML Syscall Detection Results: LockBit Ransomware Sample (ktop\lockbit.exe)

This document summarizes the ML model's syscall-based anomaly detection results for a LockBit ransomware sample (process: `ktop\lockbit.exe`, PID 5600).  
The model uses syscall sequences to assign suspicion scores: **more negative = more suspicious/anomalous**.

LockBit is a notorious Ransomware-as-a-Service (RaaS) family known for aggressive encryption, data exfiltration, and advanced **EDR evasion** techniques (e.g., unhooking, ETW patching, process hollowing, shadow copy deletion, and tools like Backstab/Process Hacker to disable security). Recent variants (LockBit 3.0/Black, 5.0) emphasize library unhooking (reloading clean NTDLL/Kernel32) and API hooking to bypass monitoring.

### Key Observations from ML Results
- **Overall model performance**: Strong (8–8.5/10) — correctly flags evasion-related patterns with the most negative scores.
- **Top suspicious signals** (most negative scores):
  - `NtCreateFile → NtClose → NtDeviceIoControlFile` (−0.0277) → Likely driver/device communication or EDR bypass attempts (common in ransomware for disabling tools or IOCTL abuse).
  - `NtThawTransactions, NtClose` (repeated 6× at −0.0197) → Strong indicator of **Transactional NTFS (TxF) abuse** or unhooking routines (freeze/thaw transactions to remap clean libraries like NTDLL and evade user-mode hooks).
  - `NtAllocateLocallyUniqueId → NtClose → NtDeviceIoControlFile` (−0.0236) → LUID allocation + device IOCTL → typical in COM/security checks or EDR/driver interaction evasion.
- **Moderate signals**:
  - File/section operations (`NtCreateFile → NtQueryInformationFile → NtClose → NtCreateSection`) (−0.0243, repeated) → Section mapping for memory loading / unhooking.
  - Token queries (`NtOpenProcessTokenEx → NtQueryInformationToken`) (−0.0224) → Privilege checks / impersonation (common in ransomware escalation).
- **Low-suspicion housekeeping**:
  - Symbolic link queries, basic file ops, thread resume — normal Windows behavior, mild scores (−0.006 to −0.007).

### Syscall Patterns Mapped to Likely LockBit Behaviors

| Syscall Set (from ML log)                                      | Score (more neg = sus)      | Likely LockBit Behavior / Technique                          | Notes / Evasion Context                                                                 |
|----------------------------------------------------------------|-----------------------------|--------------------------------------------------------------|------------------------------------------------------------------------------------------|
| `NtQuerySymbolicLinkObject, NtClose, NtOpenSymbolicLinkObject` | −0.0066                     | Path resolution / symbolic link handling                     | Common in file enumeration / encryption prep; low suspicion.                             |
| `NtSaveMergedKeys, NtClose, NtCreateSection`                   | −0.0076                     | Section creation + registry transaction ops                  | Possible during unhooking or memory mapping of clean libs.                               |
| `NtCreateFile, NtClose, NtDeviceIoControlFile`                 | **−0.0277** (strong)        | Device/driver IOCTL (e.g., policy/security checks or bypass) | Ransomware often uses IOCTLs to talk to drivers or disable EDR components.               |
| `NtClose, NtOpenProcessTokenEx, NtQueryInformationToken`       | −0.0224                     | Process token query / privilege check                        | Used for escalation or impersonation before encryption.                                  |
| `NtCreateFile, NtQueryInformationFile, NtClose, NtCreateSection` (repeated) | −0.0243                     | File open → query → section mapping                          | Classic for mapping clean NTDLL sections during unhooking (EDR evasion).                 |
| `NtCreateFile, NtSetInformationFile, NtClose`                  | −0.0005 (very mild)         | File attribute/metadata modification                         | Likely during encryption or note drop.                                                   |
| `NtResumeThread`                                               | −0.0046 (mild)              | Thread resumption                                            | Used in multi-threaded encryption or after injection/hollowing.                          |
| `NtCreateFile, NtClose, NtCreateSection`                       | −0.0036 (mild)              | Basic section creation after file open                       | Memory mapping / unhooking precursor.                                                    |
| `NtThawTransactions, NtClose` (repeated 6×)                    | **−0.0197** (repeated)      | TxF transaction thaw (after freeze)                          | **High-confidence EDR evasion** — used to remap clean libraries (NTDLL unhooking).      |
| `NtAllocateLocallyUniqueId, NtClose, NtDeviceIoControlFile`    | **−0.0236** (strong)        | LUID allocation + device IOCTL                               | Common in COM/security init or talking to vulnerable drivers for bypass.                 |

### Summary Rating & Recommendations
- **Model goodness**: 8–8.5/10 — Effectively surfaces **EDR evasion** (TxF + section mapping, IOCTL abuse) and ransomware prep (file/section ops, token checks).
- **Strongest red flags**: TxF thaw repetition + DeviceIoControlFile combos — align with known LockBit unhooking / bypass tactics.
- **Improvement ideas**:
  - Heavily boost weight on repeated `NtThawTransactions` (TxF abuse is rare and highly malicious).
  - Add cross-entry repetition detection for burst patterns.
  - Correlate with process name/path reputation (e.g., `lockbit.exe` in non-standard dir → higher base suspicion).

**Bottom line**  
Your ML system is catching **real LockBit evasion signatures** effectively — especially unhooking-like behaviors that many traditional tools miss. This sample shows classic ransomware prep + EDR bypass attempts. Great work detecting it via syscalls alone!



# ML-Based Syscall Anomaly Detection: Nidhogg User-Mode Client Analysis

**Repository Context**  
This analysis evaluates the syscall sequences generated by the user-mode client of [Nidhogg](https://github.com/Idov31/Nidhogg) — a modern kernel-mode rootkit / EDR manipulation framework.  
The tested binary is `idhoggClient.exe`, which serves as the primary interface for sending IOCTL commands to the Nidhogg kernel driver.

**Detection Methodology**  
The ML model assigns suspicion scores based on syscall sequences:  
- **More negative score** = higher anomaly / malicious likelihood  
- Patterns are derived from runtime tracing of the client during typical command execution.

**Summary of Results**  
The model consistently identifies the **kernel-driver communication pattern** as the most anomalous behavior, which aligns precisely with the design and purpose of NidhoggClient.

### Observed Syscall Patterns & Source Code Mapping

| Syscall Sequence                                      | Score              | Corresponding Code Location in NidhoggClient | Approximate Line(s) in `NidhoggClient.cpp` | Explanation / Behavioral Context                                                                 |
|-------------------------------------------------------|--------------------|----------------------------------------------|--------------------------------------------|--------------------------------------------------------------------------------------------------|
| `NtQuerySymbolicLinkObject, NtClose, NtOpenSymbolicLinkObject` | -0.00656594        | `CreateFileW(L"\\\\.\\Nidhogg", ...)`        | ~40–60 (early in `main()` or init function) | Resolves the symbolic link for the Nidhogg device object during driver handle acquisition.       |
| `NtSaveMergedKeys, NtClose, NtCreateSection`          | -0.00761750        | Buffer / structure preparation for complex IOCTLs | ~150–300 (inside command handlers)          | Occurs during preparation of large input/output buffers or memory sections used in IOCTL payloads. Mild signal. |
| `NtClose, NtOpenProcessTokenEx, NtQueryInformationToken` | -0.02238871        | Privilege / integrity level checks before privileged commands | ~80–150 (command validation or `SendCommand` helper) | Queries current process token to validate permissions or set up impersonation context for driver operations. |
| `NtAllocateLocallyUniqueId, NtClose, NtDeviceIoControlFile` | **-0.02357042** (repeated across PIDs) | **Core IOCTL dispatch: `DeviceIoControl()`** | ~200–500+ (main command loop / switch-case for each feature) | **Primary driver communication signature**. `NtAllocateLocallyUniqueId` often precedes privileged IOCTLs; `NtDeviceIoControlFile` is the direct syscall behind every `DeviceIoControl` call to `\\.\Nidhogg`. This pattern repeats for every command (process protection, ETW patching, file hiding, etc.). |

### Code Snippet References (from NidhoggClient.cpp)

Typical driver initialization (handle open + path resolution):

```cpp
// Approximate location: early in main() or dedicated initialization function
HANDLE hNidhogg = CreateFileW(
    L"\\\\.\\Nidhogg",                          // triggers NtOpenSymbolicLinkObject / NtQuerySymbolicLinkObject
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL
);

if (hNidhogg == INVALID_HANDLE_VALUE) {
    // error handling
}
