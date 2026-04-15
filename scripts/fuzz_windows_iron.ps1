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

function Get-ShortPath([string]$PathValue) {
    $escaped = $PathValue.Replace('"', '""')
    $short = cmd /c "for %I in (""$escaped"") do @echo %~sI"
    if (-not $short) { return $PathValue }
    return $short.Trim()
}

Write-Host "[fuzz-iron] Resolving VS/LLVM..."
$vsRoot = Resolve-VisualStudioRoot
$llvmBin = Resolve-LlvmBin -VsRoot $vsRoot
$asanLibDir = Resolve-AsanLibDir -VsRoot $vsRoot
$asanDllPath = Resolve-AsanDllPath -AsanLibDir $asanLibDir
$asanLibDirShort = Get-ShortPath $asanLibDir

$env:Path = "$llvmBin;$($env:Path)"
$env:ASAN_LIB_DIR = $asanLibDir
$env:RUSTFLAGS = "-C passes=asan -C linker=lld-link -C target-feature=-crt-static -Clink-arg=/LIBPATH:$asanLibDirShort -Clink-arg=clang_rt.asan_dynamic-x86_64.lib"

Write-Host "[fuzz-iron] VS root: $vsRoot"
Write-Host "[fuzz-iron] LLVM bin: $llvmBin"
Write-Host "[fuzz-iron] ASAN_LIB_DIR: $asanLibDir"
Write-Host "[fuzz-iron] ASAN_DLL: $asanDllPath"
Write-Host "[fuzz-iron] RUSTFLAGS=$($env:RUSTFLAGS)"

$fullCrateDir = Resolve-Path $CrateDir
Push-Location $fullCrateDir
try {
    Copy-Item -Path $asanDllPath -Destination (Join-Path (Get-Location) "clang_rt.asan_dynamic-x86_64.dll") -Force
    Write-Host "[fuzz-iron] Copied ASan DLL to crate root $(Get-Location)"

    $targetReleaseDir = Join-Path (Join-Path (Get-Location) "target") "release"
    New-Item -ItemType Directory -Force -Path $targetReleaseDir | Out-Null
    Copy-Item -Path $asanDllPath -Destination (Join-Path $targetReleaseDir "clang_rt.asan_dynamic-x86_64.dll") -Force
    Write-Host "[fuzz-iron] Copied ASan DLL to $targetReleaseDir"

    $cmd = @("+nightly", "run", "--release", "--bin", $FuzzTarget)
    if ($ExtraArgs -and $ExtraArgs.Trim().Length -gt 0) {
        $cmd += "--"
        $cmd += ($ExtraArgs -split "\s+")
    }
    Write-Host "[fuzz-iron] Running: cargo $($cmd -join ' ')"
    & cargo @cmd
    if ($LASTEXITCODE -ne 0) {
        throw "cargo run failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

Write-Host "[fuzz-iron] Completed."
