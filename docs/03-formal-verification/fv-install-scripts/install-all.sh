#!/bin/bash
set -e

echo "=== FULL OFFLINE FV STACK INSTALLER ==="

if [ ! -f "opam-full-2.2.0.tar.gz" ]; then
    echo "❌ Error: Tarballs not found. Run ./get-all.sh first."
    exit 1
fi

export OPAMROOT="$HOME/.opam"

# --- Build PCRE ---
echo "=== Building PCRE 8.39 ==="
rm -rf pcre_build && mkdir pcre_build
tar xf pcre-8.39.tar.bz2 -C pcre_build --strip-components=1
cd pcre_build
./configure --prefix=/usr/local --enable-utf --enable-unicode-properties
make -j"$(nproc)"
sudo make install
sudo ldconfig
cd ..

export C_INCLUDE_PATH=/usr/local/include:$C_INCLUDE_PATH
export LIBRARY_PATH=/usr/local/lib:$LIBRARY_PATH
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# --- OPAM Initialization ---
echo "=== Initializing OPAM (bare) ==="
if [ ! -d "$OPAMROOT" ]; then
    opam init --disable-sandboxing --bare -y
fi
eval "$(opam env)"

# --- Switch Management ---
echo "=== Creating OCaml Switch 'easycrypt' (4.14.1) ==="
if opam switch list --short | grep -q "^easycrypt$"; then
    opam switch remove easycrypt -y
fi
opam switch create easycrypt ocaml-base-compiler.4.14.1 -y
eval "$(opam env --switch=easycrypt)"

echo "=== Creating fake conf-libpcre.2 package ==="
mkdir -p fake-conf-libpcre.2
cat > fake-conf-libpcre.2/opam << 'EOF'
opam-version: "2.0"
name: "conf-libpcre"
version: "2"
synopsis: "Fake PCRE1 system package for offline builds"
build: [
  ["sh" "-c" "echo 'PCRE OK'"]
]
EOF

opam pin add conf-libpcre.2 ./fake-conf-libpcre.2 -y


# --- Restore OPAM cache ---
echo "=== Restoring OPAM Cache ==="
mkdir -p "$OPAMROOT/download-cache"
if [ -d "./opam-cache" ]; then
    cp -rn ./opam-cache/* "$OPAMROOT/download-cache/" || true
fi

# --- Install OCaml deps from cache ---
echo "=== Installing OCaml dependencies ==="
opam install -y gmp zarith yojson menhir cmdliner stdlib-shims ocplib-simplex.0.4.1 seq psmt2-frontend camlzip conf-zlib

# --- EasyCrypt deps via opam pin ---
opam pin add easycrypt ./easycrypt-r2025.03.tar.gz -y --no-action
opam install --deps-only easycrypt -y --no-depexts

# --- Build EasyCrypt ---
echo "=== Building & Installing EasyCrypt r2025.03 ==="
rm -rf ec_build && mkdir ec_build
tar xf easycrypt-r2025.03.tar.gz -C ec_build --strip-components=1
cd ec_build

echo "=== Building EasyCrypt with dune ==="
opam exec -- dune build @install

echo "=== Installing EasyCrypt ==="
opam exec -- dune install

# Copy binary manually for global access
if [ -f "_build/default/src/ec.exe" ]; then
    sudo cp _build/default/src/ec.exe /usr/local/bin/easycrypt
    sudo chmod +x /usr/local/bin/easycrypt
else
    echo "❌ ERROR: EasyCrypt binary not found after build"
    exit 1
fi

cd ..

# --- Build Coq ---
rm -rf coq_build && mkdir coq_build
tar xf coq-8.17.1.tar.gz -C coq_build --strip-components=1
cd coq_build
opam exec -- ./configure -prefix /usr/local
opam exec -- dune build -p coq-core,coq-stdlib,coq
opam exec -- dune install coq-core coq-stdlib coq
cd ..

# --- Build Z3 ---
rm -rf z3_build && mkdir z3_build
tar xf z3-4.13.0.tar.gz -C z3_build --strip-components=1
cd z3_build
opam exec -- python3 scripts/mk_make.py
cd build
opam exec -- make -j"$(nproc)"
sudo make install
cd ../..

# --- Build CaDiCaL ---
echo "=== Building CaDiCaL ==="
rm -rf cadical_build && mkdir cadical_build
tar xf cadical-1.5.3.tar.gz -C cadical_build --strip-components=1
cd cadical_build
./configure
make -j"$(nproc)"
sudo cp build/libcadical.a /usr/local/lib/
sudo cp src/cadical.hpp /usr/local/include/
sudo ldconfig
cd ..

# --- Build SymFPU ---
echo "=== Building SymFPU ==="
rm -rf symfpu_build && mkdir symfpu_build
tar xf symfpu-cvc4.tar.gz -C symfpu_build --strip-components=1
sudo mkdir -p /usr/local/include/symfpu
sudo cp -r symfpu_build/* /usr/local/include/symfpu/
sudo chmod -R 755 /usr/local/include/symfpu
sudo ldconfig

# --- Build CVC5 1.0.8 (Manual CMake Mode) ---
echo "=== Building CVC5 1.0.8 ==="
rm -rf cvc5_build && mkdir cvc5_build
tar -xf cvc5-1.0.8.tar.gz -C cvc5_build --strip-components=1
cd cvc5_build
mkdir -p build && cd build
opam exec -- cmake .. \
    -DCMAKE_BUILD_TYPE=Production \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_UNIT_TESTING=OFF \
    -DUSE_POLY=OFF \
    -DUSE_CADICAL=ON \
    -DCADICAL_LIBRARIES=/usr/local/lib/libcadical.a \
    -DCADICAL_INCLUDE_DIR=/usr/local/include \
    -DUSE_SYMFPU=ON \
    -DSYMFPU_INCLUDE_DIR=/usr/local/include/symfpu
opam exec -- make -j"$(nproc)"
sudo make install
cd ../..

# --- Build Alt-Ergo ---
echo "=== Building Alt-Ergo 2.4.3-free ==="
rm -rf alt_build && mkdir alt_build
tar xf alt-ergo-2.4.3-free.tar.gz -C alt_build --strip-components=1
cd alt_build
opam exec -- ./configure
opam exec -- make -j"$(nproc)"
# Manual install for 2.4.3-free binary
echo "=== Installing Alt-Ergo manually ==="
sudo cp _build/install/default/bin/alt-ergo /usr/local/bin/alt-ergo
sudo chmod +x /usr/local/bin/alt-ergo
cd ..

# --- Build Why3 ---
rm -rf why3_build && mkdir why3_build
tar xf why3-1.6.0.tar.gz -C why3_build --strip-components=1
cd why3_build
opam exec -- ./configure --prefix=/usr/local
opam exec -- make -j"$(nproc)"
sudo make install
cd ..

echo "=== Finalizing Why3 prover detection ==="
opam exec -- why3 config detect
# Update solvers
easycrypt why3config

# Final check: Does it see the theories now?
echo "=== Checking EasyCrypt Load Path ==="
opam exec -- easycrypt config | grep "load-path"

echo "✅ STACK FULLY INSTALLED"