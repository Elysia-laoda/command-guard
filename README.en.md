# command-guard | anti-ai-rm-rf

> ## Stop your AI from nuking the repo: put a tripwire in front of `delete`
>
> One command can wipe an entire workspace — that happened for real on 2026-09-15. This project
> makes a recursive delete **stop dead at the first tripwire** instead of reporting an error and
> carrying on.

[中文](README.md) ｜ also known as **anti-ai-rm-rf** ｜ Keywords: **agent guardrail** · anti-delete · tripwire · AI-safety · Windows/PowerShell

**Positioning, stated up front**: this is an *anti-fat-finger* tool, not security software. It stops
"wrong path, variable eaten by the shell, an agent firing off a recursive delete". It does **not**
stop a determined adversary — every bypass is listed in [Limits](#limits-this-section-matters-more-than-the-features), not hidden.

---

## 30-second start

```powershell
# 1) Check whether both layers are in place (command-level check, OS-level permission)
.\protect\Guard.ps1 status

# 2) Install protection per guard.json (dry run by default; -Apply writes)
.\protect\Guard.ps1 install -Apply

# 3) Make every Remove-Item pass the checker first (put this in your profile)
. D:\path\to\command-guard\adapters\Remove-Item.shim.ps1
```

Everything about *what* to protect lives in one file, `guard.json`:

```json
{ "path": "D:\\MyWorkspace", "depth": 1, "level": "sentinel", "exclude": ["_trash"] }
```

`depth` means **the same thing in both layers — how many levels down protection reaches**:
`0` = the root only / `1` = root + first level / `n` = n levels / `-1` = the whole subtree.

---

## What it actually stops

The 2026-09-15 command looked like this:

```bash
powershell -NoProfile -Command "
$new = 'Win11-Video-LockScreen-Shinjuku-Battle'
if (Test-Path \"D:\ZCodeprojecttt\\$new\") { Remove-Item \"D:\ZCodeprojecttt\\$new\" -Recurse -Force }"
```

Three mistakes stacked: bash ate `$new`, so the path collapsed to the **workspace root**; the
`if (Test-Path ...)` guard evaluated a **variable** instead of a literal, so it guarded nothing; and
`-Force` meant the command took **three unrelated project directories** with it.

This project stops that **shape**, rather than relying on "remember to be careful".

---

## How it works: four gates between a command and a deleted file

```
author writes it ─▶ 1. engine verdict ─▶ 2. PowerShell runs it ─▶ 3. OS permission ─▶ 4. tripwire
(AI/human/script)     (never executes)     (gate honours pref)      (either of two routes)  (batch stops)
```

1. **Command layer (engine)** — the command goes through `cli.mjs check`: does the target fall inside a protected range at or above `depth`? If yes → **blocked, never executed**, with a reason. The shim also adds `-ErrorAction Stop` to recursive deletes (**arming the tripwire**).
2. **During execution (PowerShell)** — the provider **recurses itself, sequentially, item by item**; a failed delete becomes a `WriteError`. If armed, the **first refusal throws and the whole batch stops**.
3. **OS layer (ACL)** — a refusal comes from one of **two routes**: the object's own `DELETE`, or the parent's `DeleteSubdirectoriesAndFiles`. Both have to be closed.
4. **Tripwire** — the walk stops at the first item it cannot delete, so putting it **first** means zero loss.

The three are a chain: the engine blocks before issue, the ACL refuses inside the OS, the tripwire
turns "one refusal" into "the batch stops".

---

## The three parties, and who can stop what

| Party | Who | In this project | Works against another agent? |
|---|---|---|---|
| **Author** | writes the command | — (needs no cooperation) | — |
| **Courier** | delivers it | `adapters/` (ZCode hook, shell wrapper, cmdlet shadow) | one thin adapter per host |
| **Engine** | decides allow/deny | `src/policy.mjs` + `src/cli.mjs` | yes (it is just a function) |
| **Execution env** | actually does it | `protect/` (ACL + tripwire) | **does not care where the command came from** |

Ranked by how hard they are to bypass:

| Layer | Bypass difficulty | What it stops |
|---|---|---|
| shadow / engine | **one line** (`-NoProfile`, module-qualified name, `[IO.File]::Delete`, `cmd /c del`) | slips of the hand, a casually dangerous command |
| courier hook | gone with the next agent | tool calls that pass through it |
| **ACL + tripwire** | **cannot be bypassed** (short of changing permissions — a conspicuous act) | the OS-level delete |
| backups / VCS | — | recovers after everything above has been bypassed |

---

## Measured results

Everything below was run on Windows, most of it on **both Windows PowerShell 5.1.26100 and PowerShell 7.6.6**. Every number is measured, not estimated.

### The mechanism (read from the source)

In `src/System.Management.Automation/namespaces/FileSystemProvider.cs`, a recursive delete is a
**sequential loop in managed code**:

```csharp
// RemoveDirectoryInfoItem, from line 3036
foreach (DirectoryInfo childDir in directory.EnumerateDirectories())
{
    if (Stopping) { return; }
    RemoveDirectoryInfoItem(childDir, recurse, force, false);   // recurses itself, one at a time
}
```

```csharp
// RemoveFileSystemItem, from line 3209
if (!Force && (Attributes & (Hidden | System | ReadOnly)) != 0)
{
    WriteError(errorRecord);   // a refusal is written as an error
    return;                    // and then it returns - not a throw, so the outer loop continues
}
```

| Finding | Measurement |
|---|---|
| **There is no "delete this tree" syscall** | item-by-item `foreach`; wall clock is linear in item count (200→3.7s, 400→7.3s, 800→15.2s, 1600→33.9s — 8× items, 9.1× time) |
| **Sequential, depth-first, not parallel** | refusal aimed at the 1st request → zero loss; 3rd → 12 lost; 5th → 24 lost |
| **A failure is skipped, the rest still go** | 15 read-only files out of 60 → 22 errors reported, **only those 15 survived**, the other 45 deleted |

### The circuit breaker: `-ErrorAction Stop` turns "skip" into "halt"

`WriteError` obeys `-ErrorAction`. Under the default `Continue` a refusal is skipped; set it to `Stop`
and the first refusal throws, **aborting the whole batch**.

| Scenario | Result |
|---|---|
| 15 read-only files, default `ErrorAction` | only **15/60** survived (the other 45 deleted) |
| same, `-ErrorAction Stop` | **57/60** survived, threw |
| 60 plain files, **one protected subdirectory** + `Stop` | **41/60** survived; the protected dir and everything after it intact |
| control: no protection at all + `Stop` | everything deleted, no exception |

**A single protected item is enough to stop the whole batch, and `-Force` cannot defeat it** (an ACL refusal is an OS-level access denial, not an attribute). The cost: it is *damage limitation*, not a shield, and it changes semantics — so the shim only adds `Stop` when the caller did **not** specify `-ErrorAction` themselves (`COMMAND_GUARD_STOP_ON_REFUSAL=0` for fully native semantics).

### `Remove-Item` never uses the Recycle Bin (and that has nothing to do with `-Force`)

| Approach | Lands in the bin |
|---|---|
| `Remove-Item` (plain / `-Force` / `-Recurse -Force` / read-only + `-Force`) | **none of them** |
| control: `Microsoft.VisualBasic.FileIO.FileSystem::DeleteFile(..., SendToRecycleBin)` | **yes** |

What `-Force` actually does is **mask Hidden/System/ReadOnly and suppress the confirmation prompt** —
measured: without `-Force`, a read-only file *and its directory* survive. But **dropping `-Force` would
not have prevented the incident**: a tree of ordinary files deleted with `Remove-Item -Recurse` is
removed **silently, with no prompt at all**.

### Deleting a child has two routes, and an object-level deny closes only one

> To delete a directory it must first be **empty**, and you need at least one of:
> **① `DELETE` on the object itself**, or **② `DeleteSubdirectoriesAndFiles` on its parent**.

| Location | Parent grants ② | Empty directory (the tripwire shape) held? |
|---|---|---|
| `E:\<parent>\<tripwire>` | no | **held** |
| `%TEMP%\<parent>\<tripwire>` | **yes** | **did not hold** (not even an error) |
| `D:\ZCodeprojecttt\_session-temp\<parent>\<tripwire>` | no | **held** |

That model explains every observation: a non-empty directory only *looks* safer because **an empty one
can be deleted at all**; once its contents are gone it is taken out through the parent route too. So
**protection anywhere must close both routes** — closing ② is just one deny of
`DeleteSubdirectoriesAndFiles` on the parent, and it is **narrow** (it removes only the alternate
path; other children are still deletable through their own `DELETE`).

### The tripwire: one protected empty directory per protected level

| Setup | Loss |
|---|---|
| tripwire name sorts first + `Stop` | **0/30** |
| tripwire name sorts last + `Stop` | 30/30 |
| tripwire first, but **no** `Stop` | 30/30 |
| tripwire present, but the command targets one subtree | that subtree is deleted (**by design**: this is the "dilute the damage to one subtree" case) |

**The name has to sort first among its siblings**: `000-guard` loses to `.git` (`.` = 0x2E < `0` = 0x30),
and every git repo has a `.git` — hence the default name **`!000-guard`** (`!` = 0x21, the lowest
printable ASCII). The tooling **actually deletes a probe tree** at install time to verify it lands
first, and names the offending sibling when it does not.

### Three protection strengths

| Mode | Blocks deletion | Blocks content wipe | Still editable inside | For |
|---|---|---|---|---|
| **tripwire** (`level: sentinel`) | whole-directory delete is cut short | no | **yes** (atomic save included) | projects you still work in |
| **tree lock** (`level: tree`) | yes | no | no (read-only-ish) | semi-archived |
| **archive** (`level: archive`) | yes | yes | no, but **still readable** | irreplaceable data |

Tree lock, measured: `Remove-Item -Recurse -Force` loses nothing; `cmd rd /s /q`, .NET
`Directory.Delete`, `robocopy /MIR` and `cmd del /f /s /q` are all refused; creating and modifying
files inside still works, while **atomic save (temp file + overwrite) is blocked**. Archive mode,
measured: overwrite and append refused, delete refused, **reading and listing fully working**.

### Approaches that measured as failures

- **A single canary** (one file held open): the command finished in 199 ms, **neither hung nor aborted**; only the canary survived while the rest of the tree was emptied — it only protects itself.
- **Holding every file open**: 50/50 survived, so it is a real shell — but worse than ACL on every axis: `Set-Content` blocked, rename blocked, **gone after a reboot**, `taskkill` on the guard releases it, one handle per file.
- **A non-inherited ACL**: leaves an *empty shell* — contents wiped, directory still there. Looks like protection; protects nothing.
- **A user-mode file-access router**: does not exist. Intercepting another process's file access requires a kernel minifilter (not buildable here: no kernel headers, no signing cert, Secure Boot on, not an admin). And it would **not** stop more than the ACL does — it only adds per-request conditions, which the command-layer rules can already express.

---

## Limits (this section matters more than the features)

**Text matching is inherently incomplete.** The engine reads the command text:

- deletes that never name a destructive verb: `[IO.File]::Delete()`, `.Delete()`, a command written into a `.ps1` and then run;
- verbs that are built or substituted: `Invoke-Expression`, `$cmd`, base64, string concatenation;
- **variables reveal their shape, not their value** — that rule blocks "a variable next to a recursive switch", i.e. a *shape*.

**The shadow layer is bypassable in one line.** `-NoProfile`, the module-qualified
`Microsoft.PowerShell.Management\Remove-Item`, `Remove-Item Function:Remove-Item` to delete the
function, `[IO.File]::Delete()`, `cmd /c del`. **Its value is turning "being careful" into a mechanical
rule** — it does not defeat an adversary.

**ACL limits.** It stops the *action* of deletion, not malice: **an owner can always re-permission the
object** — so it defends against accidents, not adversaries. It only has effective shapes ("the whole
subtree", or "one tripwire per level"); covering only part of a tree leaves an empty shell. And it
provides **no recovery whatsoever**.

**The only layer that makes a deletion reversible is backup / version control.** The three layers above
make deletion less likely and catch it earlier — they do not make it undoable. Do both.

---

## Layout

```
command-guard/
  guard.json                  the single config: depth for the engine, level for the installer
  src/policy.mjs              the policy engine (pure function, host-agnostic)
  src/cli.mjs                 check / run / describe / selftest, supports --depth
  tests/policy.test.mjs       engine contract tests (22 assertions)
  tests/Test-ShimFidelity.ps1 shadow fidelity tests (17, shimmed vs unshimmed, item by item)
  adapters/zcode-hook.mjs     ZCode PreToolUse adapter (thin, with an audit log)
  adapters/guard.sh           wrapper usable from any shell (thin)
  adapters/Remove-Item.shim.ps1  cmdlet shadow: every Remove-Item passes the checker first
  protect/Guard.ps1           the front door: status / install / remove (dry run by default)
  protect/GuardSentinel.ps1   tripwire: install + real-delete verification + health check
  protect/Protect-Path.ps1    tree lock (-DenyWrite = archive mode)
  protect/Unprotect-Path.ps1  break glass
  protect/Test-Protection.ps1 OS-layer tests (25 assertions)
  logs/audit.jsonl            one line per adapter invocation
```

**Installed on a real workspace** (measured on this machine): 16 tripwires, all behaviourally
verified; acceptance 10/10 — creating, editing, **atomic saving**, deleting a file and deleting a
subdirectory all still work at both the root and project level, while a **whole-directory delete is
cut short with zero loss**.

## License

MIT.
