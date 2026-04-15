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

    $fallbacks = @($env:VSINSTALLDIR, $env:VisualStudioInstallDir) | Where-Object { $_ -and (Test-Path $_) }
    if ($fallbacks.Count -gt 0) {
        return $fallbacks[0]
    }
    throw "Unable to locate Visual Studio installation."
}

function Resolve-AsanLibDir([string]$VsRoot) {
    $llvmRoot = Join-Path $VsRoot "VC\Tools\Llvm\x64\lib\clang"
    if (Test-Path $llvmRoot) {
        $clangVersions = Get-ChildItem -Path $llvmRoot -Directory | Sort-Object Name -Descending
        foreach ($cv in $clangVersions) {
            $windowsLib = Join-Path $cv.FullName "lib\windows"
            $asanLib = Join-Path $windowsLib "clang_rt.asan_dynamic-x86_64.lib"
            if (Test-Path $asanLib) {
                return $windowsLib
            }
        }
    }

    $msvcTools = Join-Path $VsRoot "VC\Tools\MSVC"
    if (Test-Path $msvcTools) {
        $versions = Get-ChildItem -Path $msvcTools -Directory | Sort-Object Name -Descending
        foreach ($v in $versions) {
            $fallbackBin = Join-Path $v.FullName "bin\Hostx64\x64"
            $asanLib = Join-Path $fallbackBin "clang_rt.asan_dynamic-x86_64.lib"
            if (Test-Path $asanLib) {
                return $fallbackBin
            }
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
    if (-not $short) {
        return $PathValue
    }
    return $short.Trim()
}

Write-Host "[fuzz-native] Resolving VS + ASan paths..."
$vsRoot = Resolve-VisualStudioRoot
$asanLibDir = Resolve-AsanLibDir -VsRoot $vsRoot
$asanDllPath = Resolve-AsanDllPath -AsanLibDir $asanLibDir
$env:ASAN_LIB_DIR = $asanLibDir

# Requested native path: standard cargo run pipeline with explicit MSVC linker.
$env:RUSTFLAGS = "-Ctarget-feature=-crt-static -C linker=link.exe"
$env:RUSTFLAGS += " -Clink-arg=/fsanitize=address"
$asanLibDirForLinker = Get-ShortPath $asanLibDir
$env:RUSTFLAGS += " -Clink-arg=/LIBPATH:$asanLibDirForLinker"

Write-Host "[fuzz-native] VS root: $vsRoot"
Write-Host "[fuzz-native] ASAN_LIB_DIR=$asanLibDir"
Write-Host "[fuzz-native] ASAN_DLL=$asanDllPath"
Write-Host "[fuzz-native] ASAN_LIB_DIR(short)=$asanLibDirForLinker"
Write-Host "[fuzz-native] RUSTFLAGS=$($env:RUSTFLAGS)"

$fullCrateDir = Resolve-Path $CrateDir
Push-Location $fullCrateDir
try {
    # Build first so we can place ASan runtime DLL next to the produced executable.
    $buildCmd = @("build", "--release", "--bin", $FuzzTarget)
    Write-Host "[fuzz-native] Building: cargo $($buildCmd -join ' ')"
    & cargo @buildCmd
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE"
    }

    $exePath = Join-Path (Join-Path (Get-Location) "target\release") "$FuzzTarget.exe"
    if (-not (Test-Path $exePath)) {
        throw "Built executable not found at $exePath"
    }

    $exeDir = Split-Path -Parent $exePath
    Copy-Item -Path $asanDllPath -Destination (Join-Path $exeDir "clang_rt.asan_dynamic-x86_64.dll") -Force
    Write-Host "[fuzz-native] Copied ASan DLL to $exeDir"

    $cmd = @("run", "--release", "--bin", $FuzzTarget)
    if ($ExtraArgs -and $ExtraArgs.Trim().Length -gt 0) {
        $cmd += "--"
        $cmd += ($ExtraArgs -split "\s+")
    }
    Write-Host "[fuzz-native] Running: cargo $($cmd -join ' ')"
    & cargo @cmd
    if ($LASTEXITCODE -ne 0) {
        throw "cargo run failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

Write-Host "[fuzz-native] Completed."
