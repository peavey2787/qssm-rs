$ErrorActionPreference = "Stop"

$url = "https://cdn.jsdelivr.net/npm/dbip-city-lite/dbip-city-lite.mmdb.gz"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$resourcesDir = Join-Path $root "src-tauri/resources"
$gzPath = Join-Path $resourcesDir "dbip-city-lite.mmdb.gz"
$mmdbPath = Join-Path $resourcesDir "dbip-city-lite.mmdb"

if (!(Test-Path $resourcesDir)) {
  New-Item -ItemType Directory -Path $resourcesDir | Out-Null
}

Write-Host "Downloading DB-IP City Lite MMDB..."
Invoke-WebRequest -Uri $url -OutFile $gzPath

Write-Host "Decompressing to $mmdbPath ..."
$inStream = [System.IO.File]::OpenRead($gzPath)
try {
  $gzip = New-Object System.IO.Compression.GzipStream($inStream, [System.IO.Compression.CompressionMode]::Decompress)
  try {
    $outStream = [System.IO.File]::Create($mmdbPath)
    try {
      $gzip.CopyTo($outStream)
    } finally {
      $outStream.Dispose()
    }
  } finally {
    $gzip.Dispose()
  }
} finally {
  $inStream.Dispose()
}

Remove-Item $gzPath -Force
Write-Host "Done. Wrote $mmdbPath"
