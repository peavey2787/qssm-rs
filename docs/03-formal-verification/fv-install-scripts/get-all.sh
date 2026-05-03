#!/bin/bash
set -e

# Configuration
RETRIES=5
WAIT=5
TOTAL=0
SUCCESS=0
SKIPPED=0
FAILED=()
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

echo "=== Current directory: $(pwd) ==="
echo "This script can wipe everything here EXCEPT script files."
read -p "Do you want to wipe the directory before downloading? (y/N): " WIPE

if [[ "$WIPE" =~ ^[Yy]$ ]]; then
    echo "=== Wiping directory (preserving scripts) ==="
    for f in * .*; do
        case "$f" in
            .|..|"get-all.sh"|"install-all.sh"|"minimal-install.sh") ;;
            *) rm -rf -- "$f" ;;
        esac
    done
fi

# --- System packages ---
echo "=== Installing system packages via apt ==="
sudo apt update
sudo apt install -y \
    build-essential m4 pkg-config git curl ca-certificates \
    libgmp-dev zlib1g-dev libffi-dev libpcre2-dev \
    python3 python3-dev libssl-dev libncurses-dev \
    binutils binutils-dev gcc g++ libc6-dev \
    cmake ninja-build ocaml-dune opam

download_smart_size() {
    local url="$1"
    local out="$2"
    TOTAL=$((TOTAL + 1))

    if [ -f "$out" ] && [ -s "$out" ]; then
        echo "✅ SKIP: $out already exists."
        SUCCESS=$((SUCCESS + 1))
        SKIPPED=$((SKIPPED + 1))
        return 0
    fi

    for i in $(seq 1 $RETRIES); do
        echo "=== [Attempt $i/$RETRIES] Downloading $out ==="
        if wget --no-check-certificate --max-redirect=5 -L -U "$UA" -t 1 -T 30 "$url" -O "$out"; then
            local size
            size=$(stat -c%s "$out" 2>/dev/null || echo 0)
            
            # FIXED: Smarter size check. SymFPU is ~36KB, others are >100KB.
            # We check if size is > 10KB to allow SymFPU but catch broken 0-byte redirects.
            if [ "$size" -gt 10000 ]; then
                echo "✅ SUCCESS: $out downloaded ($(du -h "$out" | cut -f1))."
                SUCCESS=$((SUCCESS + 1))
                return 0
            else
                echo "❌ ERROR: $out is too small (${size} bytes). Broken link?"
                rm -f "$out"
            fi
        else
            echo "⚠️ Network error. Retrying in ${WAIT}s..."
            sleep $WAIT
        fi
    done

    echo "🚫 FATAL: Failed to obtain $out."
    FAILED+=("$out ($url)")
    return 1
}

echo "=== Downloading Tarballs ==="
download_smart_size "https://deb.debian.org/debian/pool/main/p/pcre3/pcre3_8.39.orig.tar.bz2" "pcre-8.39.tar.bz2"
download_smart_size "https://github.com/ocaml/opam/releases/download/2.2.0/opam-full-2.2.0.tar.gz" "opam-full-2.2.0.tar.gz"
download_smart_size "https://github.com/EasyCrypt/easycrypt/archive/refs/tags/r2025.03.tar.gz" "easycrypt-r2025.03.tar.gz"
download_smart_size "https://codeload.github.com/coq/coq/tar.gz/refs/tags/V8.17.1" "coq-8.17.1.tar.gz"
download_smart_size "https://why3.gitlabpages.inria.fr/releases/why3-1.6.0.tar.gz" "why3-1.6.0.tar.gz"
download_smart_size "https://codeload.github.com/Z3Prover/z3/tar.gz/refs/tags/z3-4.13.0" "z3-4.13.0.tar.gz"
download_smart_size "https://codeload.github.com/cvc5/cvc5/tar.gz/refs/tags/cvc5-1.0.8" "cvc5-1.0.8.tar.gz"
download_smart_size "https://github.com/OCamlPro/alt-ergo/releases/download/v2.4.3-free/alt-ergo-2.4.3-free.tar.gz" "alt-ergo-2.4.3-free.tar.gz"
download_smart_size "https://github.com/arminbiere/cadical/archive/refs/tags/rel-1.5.3.tar.gz" "cadical-1.5.3.tar.gz"
download_smart_size "https://github.com/martin-cs/symfpu/archive/refs/heads/CVC4.tar.gz" "symfpu-cvc4.tar.gz"

# --- Collect OPAM Dependencies ---
echo "=== Collecting OPAM dependencies for Offline Use ==="
export OPAMROOT="$(pwd)/.opam_tmp"
mkdir -p "$OPAMROOT"
opam init --bare --disable-sandboxing -y
opam switch create temp 4.14.1 -y
echo "=== Fetching dependency sources into cache ==="
opam install --download-only -y yojson menhir cmdliner stdlib-shims zarith gmp ocplib-simplex.0.4.1 seq psmt2-frontend camlzip conf-zlib conf-libpcre

echo "=== Exporting OPAM Cache ==="
mkdir -p ./opam-cache
find "$OPAMROOT" -name "*.tar.gz" -exec cp {} ./opam-cache/ \;
find "$OPAMROOT" -name "*.tgz" -exec cp {} ./opam-cache/ \;
rm -rf "$OPAMROOT"

echo -e "\nSummary: $SUCCESS/$TOTAL files verified."
if [ "${#FAILED[@]}" -ne 0 ]; then
    echo "❌ Failed downloads:"
    printf ' - %s\n' "${FAILED[@]}"
else
    echo "✅ All files obtained successfully."
fi
echo "OPAM Cache ready in ./opam-cache/"