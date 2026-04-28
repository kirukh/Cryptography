#!/usr/bin/env bash
# ============================================================================
# setup_liboqs.sh
#
# Baut liboqs MIT XMSS-Stateful-Support und installiert liboqs-python.
# Auszufuehren in WSL2 (Ubuntu 22.04).
#
# Achtung: Der Build dauert ein paar Minuten.
# ============================================================================

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="${PROJECT_ROOT}/vendor"
PREFIX="${PROJECT_ROOT}/vendor/install"

mkdir -p "${VENDOR_DIR}"

# ---------------------------------------------------------------------------
# 1. liboqs (C-Bibliothek) MIT XMSS bauen
# ---------------------------------------------------------------------------
if [ ! -d "${VENDOR_DIR}/liboqs" ]; then
    echo ">>> Klone liboqs ..."
    git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git \
        "${VENDOR_DIR}/liboqs"
fi

echo ">>> Baue liboqs mit XMSS-Stateful-Support ..."
cd "${VENDOR_DIR}/liboqs"
rm -rf build
mkdir build && cd build

# Wichtig: die HAZARDOUS-Flags sind noetig, weil liboqs den Stateful-Support
# bewusst als "gefaehrlich" markiert. Genau das ist unser Diskussionspunkt.
cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
    -DOQS_ENABLE_SIG_STFL_XMSS=ON \
    -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON \
    -DBUILD_SHARED_LIBS=ON \
    ..

ninja
ninja install

# ---------------------------------------------------------------------------
# 2. liboqs-python installieren
# ---------------------------------------------------------------------------
if [ ! -d "${VENDOR_DIR}/liboqs-python" ]; then
    echo ">>> Klone liboqs-python ..."
    git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git \
        "${VENDOR_DIR}/liboqs-python"
fi

echo ">>> Installiere liboqs-python ..."
cd "${VENDOR_DIR}/liboqs-python"

# liboqs-python sucht liboqs zur Laufzeit ueber LD_LIBRARY_PATH oder
# das Default-System-Verzeichnis. Wir legen einen Hinweis ab.
pip install .

# Damit Python-Code liboqs zur Laufzeit findet:
echo ""
echo ">>> Setze diese Umgebungsvariable in deiner Shell (oder in .bashrc):"
echo "    export LD_LIBRARY_PATH=\"${PREFIX}/lib:\${LD_LIBRARY_PATH:-}\""
echo ""
echo ">>> Fertig. Teste mit:"
echo "    cd ${PROJECT_ROOT}"
echo "    python -m src.smoke_test"
