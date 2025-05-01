# Common Suspicious Process Patterns

This document outlines common patterns seen in malicious processes and how proc-wolf detects them.

## Naming Patterns

Malware often uses distinctive naming patterns to blend in or disguise itself. Here are common patterns that proc-wolf watches for:

### Random-looking Names

```
x8j29ska.exe
ksjsnf7s.exe
svchost432.exe
```

Many malware variants use randomly generated names or include random numbers to avoid detection.

### System-lookalike Names

```
scvhost.exe    (instead of legitimate svchost.exe)
crsss.exe      (instead of legitimate csrss.exe)
explorerr.exe  (instead of legitimate explorer.exe)
```

By using names similar to legitimate Windows processes, malware attempts to hide in plain sight.

### Suspicious Prefixes/Suffixes

```
svc_[random].exe
agent_[random].exe
helper_[random].exe
```

### GUID-like Names

```
5e8d91a2-7f8b-4c1d-b27e-a052981d5e41.exe
```

Some malware uses GUID patterns as filenames to appear as legitimate system components.

## Location Red Flags

Where a process runs from can be a major indicator of its legitimacy:

### Temp Directories

```
C:\Users\[username]\AppData\Local\Temp\malware.exe
C:\Windows\Temp\dropper.exe
```

Legitimate applications rarely run executables directly from temp directories.

### User Public Folders

```
C:\Users\Public\Documents\hidden_malware.exe
```

Malware may use public folders to ensure access across all user accounts.

### Unusual Paths

```
C:\[random_folder]\[random].exe
```

Legitimate software typically uses standard installation directories.

### Network Shares

```
\\[network_share]\hidden\backdoor.exe
```

Execution from network shares that aren't company deployment servers is suspicious.

## Behavioral Indicators

Proc-wolf monitors for these behavioral red flags:

### High Resource Usage

- Processes using 80%+ CPU for extended periods
- Memory usage spikes without user interaction

### Network Activity

- Unexpected outbound connections
- Connections to unusual ports (4444, 1337, etc.)
- High volume of traffic from unexpected processes

### File Operations

- Accessing multiple sensitive system files
- Creating many temporary files
- Modifying system registry keys

### Self-preservation Techniques

- Processes that restart immediately after being killed
- Creating multiple copies of themselves
- Modifying startup registry keys

### Process Relationship Anomalies

- Child processes that don't match parent's normal behavior
- Process injection into legitimate processes
- Orphaned processes with unusual lineage

## Real-world Examples

Here are some examples of actual malware process patterns that proc-wolf can detect:

### Cryptominers

```
xmrig.exe
nheqminer.exe
```

Often use high CPU and have unusual network connections.

### Remote Access Trojans (RATs)

```
teamviewer_[random].exe  (not the legitimate TeamViewer)
remote_[random].exe
```

Typically establish outbound connections and may inject into other processes.

### Keyloggers

```
klog.exe
hook_[random].exe
```

Often access keyboard device drivers and write frequent small log files.

### Credential Stealers

```
mimikatz.exe
dump_[random].exe
```

Attempt to access LSASS or SAM database.

## How proc-wolf Handles These Threats

The detection is only part of the process. proc-wolf's escalating response system handles threats appropriately:

1. For low-threat suspicious processes: Issue warnings and monitor
2. For medium-threat processes showing persistence: Attempt soft kill
3. For high-threat processes: Force kill immediately  
4. For critical threats or those that keep reviving: Prevent resurrection by:
   - Disabling associated services
   - Moving executable to quarantine
   - Blocking execution paths

This multi-layered approach ensures that legitimate processes are protected while genuine threats are neutralized effectively.