#!/bin/bash
set -e

echo "=== FULL OFFLINE FV STACK INSTALLER (CLEAN OPAM RESET) ==="

if [ ! -f "opam-full-2.2.0.tar.gz" ]; then
    echo "❌ Error: Tarballs not found. Run ./get-all.sh first."
    exit 1
fi

export OPAMROOT="$HOME/.opam"

echo "=== HARD RESET: Removing entire OPAM root at $OPAMROOT ==="
sudo rm -rf "$OPAMROOT"

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
echo "=== Initializing OPAM (bare, fresh) ==="
opam init --disable-sandboxing --bare -y
eval "$(opam env)"

# --- Switch Management ---
echo "=== Creating OCaml Switch 'easycrypt' (4.14.1) ==="
opam switch create easycrypt ocaml-base-compiler.4.14.1 -y
eval "$(opam env --switch=easycrypt)"

echo "=== Creating fake conf-libpcre.2 package ==="
rm -rf fake-conf-libpcre.2
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

# --- Install OCaml deps ---
echo "=== Installing OCaml dependencies ==="
opam install -y gmp zarith yojson menhir cmdliner stdlib-shims ocplib-simplex.0.4.1 seq psmt2-frontend camlzip conf-zlib

# --- EasyCrypt deps ---
echo "=== Pinning EasyCrypt archive ==="
opam pin add easycrypt ./easycrypt-r2025.03.tar.gz -y --no-action
opam install --deps-only easycrypt -y --no-depexts

# --- Build EasyCrypt ---
echo "=== Building & Installing EasyCrypt r2025.03 ==="
rm -rf ec_build && mkdir ec_build
tar xf easycrypt-r2025.03.tar.gz -C ec_build --strip-components=1
cd ec_build

echo "=== Building EasyCrypt with dune ==="
opam exec -- dune build @install

echo "=== Installing EasyCrypt via dune ==="
opam exec -- dune install

# --- Install EasyCrypt standard library ---
EC_SHARE_DIR="$(opam var share)/easycrypt"

echo "=== Installing EasyCrypt standard library to $EC_SHARE_DIR ==="
sudo rm -rf "$EC_SHARE_DIR"
sudo mkdir -p "$EC_SHARE_DIR/theories"
sudo mkdir -p "$EC_SHARE_DIR/plugins"
sudo chown -R "$USER":"$USER" "$EC_SHARE_DIR"

cp -r theories/* "$EC_SHARE_DIR/theories/"
if [ -d plugins ]; then
    cp -r plugins/* "$EC_SHARE_DIR/plugins/"
fi

sudo chown -R "$USER":"$USER" "$EC_SHARE_DIR"

# --- Install EasyCrypt binary globally ---
if [ -f "_build/default/src/ec.exe" ]; then
    sudo cp _build/default/src/ec.exe /usr/local/bin/easycrypt
    sudo chmod +x /usr/local/bin/easycrypt
else
    echo "❌ ERROR: EasyCrypt binary not found after build"
    exit 1
fi

cd ..

# --- Write EasyCrypt config file (CORRECT FOR THIS VERSION) ---
echo "=== Writing EasyCrypt config ==="
EC_CONF="$HOME/.easycrypt"
mkdir -p "$EC_CONF"

cat > "$EC_CONF/config" <<EOF
[loader]
I = $(opam var share)/easycrypt/theories
EOF

echo "=== EasyCrypt config written to $EC_CONF/config ==="


# --- Build Coq ---
echo "=== Building Coq 8.17.1 ==="
rm -rf coq_build && mkdir coq_build
tar xf coq-8.17.1.tar.gz -C coq_build --strip-components=1
cd coq_build
opam exec -- ./configure -prefix /usr/local
opam exec -- dune build -p coq-core,coq-stdlib,coq
opam exec -- dune install coq-core coq-stdlib coq
cd ..

# --- Build Z3 ---
echo "=== Building Z3 4.13.0 ==="
rm -rf z3_build && mkdir z3_build
tar xf z3-4.13.0.tar.gz -C z3_build --strip-components=1
cd z3_build
opam exec -- python3 scripts/mk_make.py
cd build
opam exec -- make -j"$(nproc)"
sudo make install
cd ../..

# --- Build CaDiCaL ---
echo "=== Building CaDiCaL 1.5.3 ==="
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
echo "=== Installing SymFPU headers ==="
rm -rf symfpu_build && mkdir symfpu_build
tar xf symfpu-cvc4.tar.gz -C symfpu_build --strip-components=1
sudo mkdir -p /usr/local/include/symfpu
sudo cp -r symfpu_build/* /usr/local/include/symfpu/
sudo chmod -R 755 /usr/local/include/symfpu
sudo ldconfig

# --- Build CVC5 ---
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
sudo cp _build/install/default/bin/alt-ergo /usr/local/bin/alt-ergo
sudo chmod +x /usr/local/bin/alt-ergo
cd ..

# --- Build Why3 ---
echo "=== Building Why3 1.6.0 ==="
rm -rf why3_build && mkdir why3_build
tar xf why3-1.6.0.tar.gz -C why3_build --strip-components=1
cd why3_build
opam exec -- ./configure --prefix=/usr/local
opam exec -- make -j"$(nproc)"
sudo make install
cd ..

echo "=== Finalizing Why3 prover detection ==="
opam exec -- why3 config detect
easycrypt why3config

echo "=== Checking EasyCrypt Load Path ==="
sudo ln -sf ~/.opam/easycrypt/bin/easycrypt /usr/local/bin/easycrypt
easycrypt config || true

echo "✅ STACK FULLY INSTALLED (FRESH OPAM, CLEAN SWITCH, CONFIGURED EASYCRYPT)"