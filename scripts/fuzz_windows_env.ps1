param(
    [string]$FuzzTarget = "verify_lattice",
    [string]$CrateDir = "crates/qssm-le",
    [string]$ExtraFuzzArgs = ""
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

    $fallbacks = @(
        $env:VSINSTALLDIR,
        $env:VisualStudioInstallDir
    ) | Where-Object { $_ -and (Test-Path $_) }

    if ($fallbacks.Count -gt 0) {
        return $fallbacks[0]
    }

    throw "Unable to locate Visual Studio installation. Install VS with C++ workload and vswhere.exe."
}

function Resolve-AsanLibDir([string]$VsRoot) {
    # Most reliable modern location (LLVM runtime libs shipped with VS):
    # VC\Tools\Llvm\x64\lib\clang\<version>\lib\windows\clang_rt.asan_dynamic-x86_64.lib
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

    # Fallback requested by user prompt (sometimes referenced in tooling docs):
    # VC\Tools\MSVC\<version>\bin\Hostx64\x64
    $msvcTools = Join-Path $VsRoot "VC\Tools\MSVC"
    if (Test-Path $msvcTools) {
        $versions = Get-ChildItem -Path $msvcTools -Directory | Sort-Object Name -Descending
        foreach ($v in $versions) {
            $binDir = Join-Path $v.FullName "bin\Hostx64\x64"
            $asanLib = Join-Path $binDir "clang_rt.asan_dynamic-x86_64.lib"
            if (Test-Path $asanLib) {
                return $binDir
            }
        }
    }

    throw "Unable to locate clang_rt.asan_dynamic-x86_64.lib under Visual Studio installation."
}

Write-Host "[fuzz] Resolving Visual Studio installation..."
$vsRoot = Resolve-VisualStudioRoot
Write-Host "[fuzz] VS root: $vsRoot"

Write-Host "[fuzz] Resolving ASan runtime library directory..."
$asanLibDir = Resolve-AsanLibDir -VsRoot $vsRoot
$env:ASAN_LIB_DIR = $asanLibDir
Write-Host "[fuzz] ASAN_LIB_DIR=$($env:ASAN_LIB_DIR)"

$fullCrateDir = Resolve-Path $CrateDir
Push-Location $fullCrateDir
try {
    $fuzzArgs = @("+nightly", "fuzz", "run", $FuzzTarget)
    if ($ExtraFuzzArgs -and $ExtraFuzzArgs.Trim().Length -gt 0) {
        $fuzzArgs += "--"
        $fuzzArgs += ($ExtraFuzzArgs -split "\s+")
    }

    Write-Host "[fuzz] Running: cargo $($fuzzArgs -join ' ')"
    & cargo @fuzzArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cargo fuzz failed with exit code $LASTEXITCODE"
    }
}
finally {
    Pop-Location
}

Write-Host "[fuzz] Completed successfully."
