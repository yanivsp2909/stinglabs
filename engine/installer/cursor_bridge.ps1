<#
    cursor_bridge.ps1 — the Cursor-on-Windows transport.

    Cursor runs a hook roughly as:
        Get-Content '<temp>.json' -Raw | & { $input | <command> }

    That pipeline breaks a plain `python sting_hook.py` in TWO independent ways
    (RC1 and RC2), and this bridge is the shape that survives both. It is the
    generalisation of a workaround a developer got working with Cursor 3.15.6.

    ⚠ UNVERIFIED ON THIS MACHINE. Every PowerShell behaviour below is reasoned
    from the failure report and Cursor 3.15.6, not run here (this repo is
    developed on macOS). `tests/test_cursor_windows_transport.py` proves the
    ENGINE half — BOM tolerance and env-file loading — on every platform; the
    TRANSPORT half is proven only when a Windows machine runs it. Mark it
    verified there, do not assume it here.

    WHY EACH STEP EXISTS — confirmed against the two root causes, not copied:

      -File, not -Command   a script file is not re-parsed by PowerShell's
                            command grammar, so a path with spaces or a value
                            with a colon is not mistaken for something else.
      -NoProfile            a developer's PowerShell profile can write to stdout
                            (banners, `oh-my-posh`), which would land in the
                            payload; -NoProfile removes that source of corruption.
      -ExecutionPolicy Bypass  an unsigned .ps1 will not run under the default
                            Restricted policy, and demanding the operator sign it
                            is friction this install does not need.
      read stdin, trim to { or [   RC2: Get-Content -Raw prepends a UTF-8 BOM,
                            and json.loads dies on the first character. Trimming
                            here AND in the engine is belt-and-braces; the engine
                            half covers any payload the bridge does not touch.
      ~/.sting/env, not the command line   RC1 and A.3: a POSIX `KEY='value'`
                            prefix is read by PowerShell as a command NAME, and
                            hooks.json is world-readable. The environment lives
                            in a 0600 file that the bridge loads.
      ProcessStartInfo, not a pipe   RC2 again: `$input | native.exe` is
                            unreliable for feeding a native process's stdin —
                            the developer saw empty and truncated stdin. Writing
                            to RedirectStandardInput through .NET is reliable.
      the interpreter, RECORDED   1.1: never a hardcoded C:\PythonNN. It is
                            `sys.executable` at install time, written into the
                            env file as STING_PYTHON. The last-resort `python`
                            is ANNOUNCED, because on Windows a bare `python`
                            can be the Store alias stub, which exits without
                            running — a silent allow.
      the entry, DERIVED    1.2 and 1.4: never a hardcoded prefix and never a
                            version directory typed anywhere. `sting_hook.py`
                            is this script's own sibling-of-parent, so any
                            STING_INSTALL_ROOT the installer used is honoured
                            by construction; the current.txt POINTER (a file —
                            `os.replace` is atomic for files, not directories)
                            is the fallback when the sibling is missing.
      the roots, from the env file   1.3: STING_ROOTS is loaded from
                            ~/.sting/env like everything else, and install.py
                            has already checked that each entry exists and
                            reported the ones that do not.

    ⚠ WHAT THIS FILE STILL ASSUMES THAT THE INSTALLER COULD CHANGE:

      ~/.sting/env          the env file's location is hardcoded HERE, in
                            `install.ENV_FILE`, and in `envfile.default_path()`
                            — three copies of one path, in two languages. They
                            agree today. `tests/test_cursor_bridge_shape.py`
                            pins them together, because the failure mode is a
                            bridge that loads no environment and reports
                            nothing missing.
      the version layout    the entry is resolved as `../sting_hook.py`, which
                            is a statement about `place.PAYLOAD` putting this
                            file at `<version>/installer/`. Moving it inside
                            the payload breaks the bridge, and the same test
                            pins that relationship.
#>
param(
    [string]$Agent = "cursor"
)

$ErrorActionPreference = "Stop"

# ── read the whole payload from stdin ────────────────────────────────────────
$raw = [Console]::In.ReadToEnd()

# ⚠ TRIM TO WHERE JSON BEGINS. Strips a UTF-8 BOM and any leading whitespace or
# banner so the child receives valid JSON. The engine repeats this, so a payload
# that reaches the child by any other route is still safe.
$start = $raw.IndexOfAny([char[]]('{', '['))
if ($start -ge 0) { $payload = $raw.Substring($start) } else { $payload = $raw }

# ── load ~/.sting/env, so nothing sensitive rides on the command line ────────
$envFile = Join-Path $HOME ".sting\env"
$sting = @{}
if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        $t = $line.Trim()
        if ($t -eq "" -or $t.StartsWith("#")) { continue }
        if ($t.StartsWith("export ")) { $t = $t.Substring(7) }
        $eq = $t.IndexOf("=")
        if ($eq -lt 0) { continue }
        $key = $t.Substring(0, $eq).Trim()
        $val = $t.Substring($eq + 1).Trim().Trim("'`"")
        # ⚠ THE ENVIRONMENT WINS, same rule as envfile.py. Only set a key the
        # shell did not already set.
        if (-not (Test-Path "Env:$key")) { $sting[$key] = $val }
    }
}

# ── the interpreter: what the install RECORDED, never a guessed path ─────────
# STING_PYTHON is `sys.executable` at install time, written into ~/.sting/env.
# The last resort below is a real risk, not a formality: a bare `python` on
# Windows resolves to the Store alias stub on a machine with no Python on PATH,
# which exits without running anything — and a hook that exits without running
# is a SILENT ALLOW under failClosed:false. So it is announced on stderr, where
# the developer's transcript will show it, rather than taken quietly.
$python = $sting["STING_PYTHON"]
if (-not $python) {
    $python = "python"
    [Console]::Error.Write("sting: STING_PYTHON is not set in $envFile — " +
        "falling back to 'python' on PATH. If that is the Microsoft Store " +
        "alias, this hook exits without deciding and the action proceeds. " +
        "Re-run install.py to record the interpreter.`n")
}

# ── the entry point ──────────────────────────────────────────────────────────
#
# ⚠ THIS IS WHERE `STING_INSTALL_ROOT` USED TO BE IGNORED, AND IT WAS THE
# DANGEROUS ONE. The line was:
#
#     $prefix = Join-Path $HOME ".local\share\sting"
#
# hardcoded, while `installer/place.default_prefix()` honours
# `$env:STING_INSTALL_ROOT`. On a custom-prefix install the installer therefore
# placed everything under the chosen prefix, wrote a hooks.json naming the
# bridge there — and the bridge then looked for `current.txt` somewhere else,
# found nothing, spawned a path that does not exist, and `failClosed:false`
# turned the failure into a SILENT ALLOW. A guard that reported a successful
# install and permitted everything.
#
# ⚠ THE FIX IS TO DERIVE, NOT TO READ THE VARIABLE, and the difference matters.
# Reading `$env:STING_INSTALL_ROOT` at hook time would be wrong twice over:
# Cursor does not inherit the shell the installer ran in, so it is usually
# UNSET (no fix at all); and if it IS set, to a prefix other than the one this
# bridge was placed under, honouring it would make a bridge from one tree spawn
# an engine from another. The variable's only job is to tell the INSTALLER
# where to put things, and it already did that — this file is sitting in the
# answer.
#
# So: `sting_hook.py` is resolved as this script's own SIBLING-OF-PARENT,
#
#     <prefix>/<version>/installer/cursor_bridge.ps1     <- $PSScriptRoot
#     <prefix>/<version>/sting_hook.py                   <- the entry
#
# which is correct for every prefix, needs no variable, and makes the bridge
# and the engine it spawns ONE VERSIONED ARTIFACT — a v1 bridge cannot drive a
# v2 entry point, which the old `<prefix>/cursor_bridge.ps1` copy could.
$versionDir = Split-Path -Parent $PSScriptRoot
$entry = Join-Path $versionDir "sting_hook.py"
$entrySource = "beside this bridge"

# ⚠ THE POINTER IS THE FALLBACK, AND IT IS READ AS A FILE. On Windows `current`
# is `current.txt` holding a path — `os.replace` is atomic for FILES and not for
# directories, which is why the layout differs from POSIX. Reading it is not the
# same as following a symlink, and three places in this project have gone round
# it by building `<prefix>/current/<x>`, a path that CANNOT EXIST on Windows.
#
# This arm fires only when the sibling is missing, which means the install is
# already damaged (place() refuses to produce a tree without sting_hook.py). It
# is here so a partially-deleted install degrades to the right engine instead of
# to no engine — and the prefix is DERIVED from this script's location too, so
# it is still the prefix the installer chose.
if (-not (Test-Path $entry)) {
    $prefix = Split-Path -Parent $versionDir
    $pointer = Join-Path $prefix "current.txt"
    if (Test-Path $pointer) {
        $current = (Get-Content $pointer -Raw).Trim()
        if ($current) {
            $entry = Join-Path $current "sting_hook.py"
            $entrySource = "via the current.txt pointer at $pointer"
        }
    }
    [Console]::Error.Write("sting: no sting_hook.py beside the bridge at " +
        "$versionDir; resolved $entrySource. This install is incomplete — " +
        "re-run install.py.`n")
}

# ── spawn Python via ProcessStartInfo and write to its stdin ─────────────────
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $python
$psi.Arguments = "`"$entry`" --agent $Agent"
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
# ⚠ THE CHILD'S WORKING DIRECTORY IS THE INSTALL TREE, NOT THE PROJECT, and
# that is deliberate rather than incidental. The engine takes `cwd` from the
# PAYLOAD (`resolve_cwd`), so the process's own directory decides nothing — but
# it must be a directory that EXISTS, or `Process.Start` throws before the hook
# runs at all, which under failClosed:false is a silent allow. The install tree
# is the one directory this script knows is present: it is standing in it.
# Forward slashes are safe in .NET on Windows and avoid any backslash-escaping
# surprise when the path is interpolated.
$psi.WorkingDirectory = $versionDir.Replace("\", "/")

# the loaded env-file values, into the child's environment
foreach ($k in $sting.Keys) { $psi.EnvironmentVariables[$k] = $sting[$k] }

$proc = [System.Diagnostics.Process]::Start($psi)
$proc.StandardInput.Write($payload)
$proc.StandardInput.Close()
$out = $proc.StandardOutput.ReadToEnd()
$err = $proc.StandardError.ReadToEnd()
$proc.WaitForExit()

if ($out) { [Console]::Out.Write($out) }
if ($err) { [Console]::Error.Write($err) }
exit $proc.ExitCode
