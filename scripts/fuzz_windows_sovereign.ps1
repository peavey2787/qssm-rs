param(
    [string]$FuzzTarget = "verify_lattice",
    [string]$CrateDir = "crates/qssm-le/fuzz",
    [string]$ExtraArgs = "-runs=1000000"
)

$ErrorActionPreference = "Stop"

function Resolve-VsWherePath {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe",
        "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Resolve-VisualStudioRoot {
    $vswhere = Resolve-VsWherePath
    if ($vswhere) {
        $path = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($LASTEXITCODE -eq 0 -and $path -and (Test-Path $path.Trim())) {
            return $path.Trim()
        }
    }

    $fallback = @($env:VSINSTALLDIR, $env:VisualStudioInstallDir) | Where-Object { $_ -and (Test-Path $_) }
    if ($fallback.Count -gt 0) {
        return $fallback[0]
    }
    throw "Unable to locate Visual Studio installation."
}

function Resolve-LlvmBin([string]$VsRoot) {
    $p = Join-Path $VsRoot "VC\Tools\Llvm\x64\bin"
    if (-not (Test-Path $p)) {
        throw "LLVM bin directory not found at $p"
    }
    if (-not (Test-Path (Join-Path $p "lld-link.exe"))) {
        throw "lld-link.exe not found in $p"
    }
    return $p
}

function Resolve-AsanLibDir([string]$VsRoot) {
    $llvmRoot = Join-Path $VsRoot "VC\Tools\Llvm\x64\lib\clang"
    if (-not (Test-Path $llvmRoot)) {
        throw "LLVM clang runtime root missing: $llvmRoot"
    }
    $versions = Get-ChildItem -Path $llvmRoot -Directory | Sort-Object Name -Descending
    foreach ($v in $versions) {
        $windowsLib = Join-Path $v.FullName "lib\windows"
        $asanLib = Join-Path $windowsLib "clang_rt.asan_dynamic-x86_64.lib"
        if (Test-Path $asanLib) {
            return $windowsLib
        }
    }
    throw "Unable to locate clang_rt.asan_dynamic-x86_64.lib."
}

function Resolve-AsanDllPath([string]$AsanLibDir) {
    $dllPath = Join-Path $AsanLibDir "clang_rt.asan_dynamic-x86_64.dll"
    if (Test-Path $dllPath) {
        return $dllPath
    }
    throw "Unable to locate clang_rt.asan_dynamic-x86_64.dll beside ASan import library."
}

function Resolve-RustupHome {
    if ($env:RUSTUP_HOME -and (Test-Path $env:RUSTUP_HOME)) {
        return $env:RUSTUP_HOME
    }
    $default = Join-Path $env:USERPROFILE ".rustup"
    if (Test-Path $default) {
        return $default
    }
    throw "Unable to resolve rustup home. Set RUSTUP_HOME or install rustup."
}

function Resolve-NightlyToolchainLibDir {
    $rustupHome = Resolve-RustupHome
    $toolchainRoot = Join-Path $rustupHome "toolchains\nightly-x86_64-pc-windows-msvc"
    if (-not (Test-Path $toolchainRoot)) {
        throw "Nightly toolchain not found at $toolchainRoot. Install with: rustup toolchain install nightly-x86_64-pc-windows-msvc"
    }
    $libDir = Join-Path $toolchainRoot "lib\rustlib\x86_64-pc-windows-msvc\lib"
    if (-not (Test-Path $libDir)) {
        throw "Nightly rustlib directory missing at $libDir"
    }
    return $libDir
}

function Repair-SysrootAsanArchive([string]$AsanLibDir) {
    $rustLibDir = Resolve-NightlyToolchainLibDir
    $targetArchive = Join-Path $rustLibDir "librustc-nightly_rt.asan.a"
    if (Test-Path $targetArchive) {
        Write-Host "[fuzz-sovereign] Sysroot ASan archive present: $targetArchive"
        return $targetArchive
    }

    $sourceLib = Join-Path $AsanLibDir "clang_rt.asan_dynamic-x86_64.lib"
    if (-not (Test-Path $sourceLib)) {
        throw "ASan source import library missing: $sourceLib"
    }

    Write-Host "[fuzz-sovereign] Sysroot repair: missing $targetArchive"
    Write-Host "[fuzz-sovereign] Attempting to copy/rename $sourceLib -> $targetArchive"
    Write-Host "[fuzz-sovereign] If this fails with access denied, run this script as Administrator once."
    Copy-Item -Path $sourceLib -Destination $targetArchive -Force
    return $targetArchive
}

function Get-ShortPath([string]$PathValue) {
    $escaped = $PathValue.Replace('"', '""')
    $short = cmd /c "for %I in (""$escaped"") do @echo %~sI"
    if (-not $short) { return $PathValue }
    return $short.Trim()
}

Write-Host "[fuzz-sovereign] Resolving VS/LLVM..."
$vsRoot = Resolve-VisualStudioRoot
$llvmBin = Resolve-LlvmBin -VsRoot $vsRoot
$asanLibDir = Resolve-AsanLibDir -VsRoot $vsRoot
$asanDllPath = Resolve-AsanDllPath -AsanLibDir $asanLibDir
$repairedArchive = Repair-SysrootAsanArchive -AsanLibDir $asanLibDir
$asanLibDirShort = Get-ShortPath $asanLibDir
$repoRoot = Resolve-Path "."
$hijackDir = Join-Path $repoRoot "target\fuzz_hijack"
$hijackArchive = Join-Path $hijackDir "librustc-nightly_rt.asan.a"
$llvmAr = Join-Path $llvmBin "llvm-ar.exe"

if (-not (Test-Path $llvmAr)) {
    throw "llvm-ar.exe not found in $llvmBin"
}

New-Item -ItemType Directory -Force -Path $hijackDir | Out-Null
if (Test-Path $hijackArchive) {
    Remove-Item -Force $hijackArchive
}
Write-Host "[fuzz-sovereign] Hijack phase: creating stub ASan archive at $hijackArchive"
& $llvmAr "cr" $hijackArchive
if ($LASTEXITCODE -ne 0) {
    throw "llvm-ar failed to create hijack archive (exit $LASTEXITCODE)"
}
$hijackDirShort = Get-ShortPath $hijackDir

$env:Path = "$llvmBin;$($env:Path)"
$env:ASAN_LIB_DIR = $asanLibDir
$env:RUSTFLAGS = "-C linker=lld-link -Zsanitizer=address -L $hijackDirShort -Clink-arg=/LIBPATH:$asanLibDirShort -Clink-arg=clang_rt.asan_dynamic-x86_64.lib"

Write-Host "[fuzz-sovereign] VS root: $vsRoot"
Write-Host "[fuzz-sovereign] LLVM bin: $llvmBin"
Write-Host "[fuzz-sovereign] ASAN_LIB_DIR: $asanLibDir"
Write-Host "[fuzz-sovereign] ASAN_DLL: $asanDllPath"
Write-Host "[fuzz-sovereign] SYSROOT_ASAN_ARCHIVE: $repairedArchive"
Write-Host "[fuzz-sovereign] HIJACK_DIR: $hijackDir"
Write-Host "[fuzz-sovereign] RUSTFLAGS=$($env:RUSTFLAGS)"

$fullCrateDir = Resolve-Path $CrateDir
Push-Location $fullCrateDir
try {
    $targetReleaseDir = Join-Path (Join-Path (Get-Location) "target") "release"
    New-Item -ItemType Directory -Force -Path $targetReleaseDir | Out-Null
    Copy-Item -Path $asanDllPath -Destination (Join-Path $targetReleaseDir "clang_rt.asan_dynamic-x86_64.dll") -Force
    Write-Host "[fuzz-sovereign] Copied ASan DLL to $targetReleaseDir"

    $cmd = @("+nightly", "run", "--release", "--bin", $FuzzTarget)
    if ($ExtraArgs -and $ExtraArgs.Trim().Length -gt 0) {
        $cmd += "--"
        $cmd += ($ExtraArgs -split "\s+")
    }
    Write-Host "[fuzz-sovereign] Running: cargo $($cmd -join ' ')"
    & cargo @cmd
    if ($LASTEXITCODE -ne 0) {
        throw "cargo run failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

Write-Host "[fuzz-sovereign] Completed."
