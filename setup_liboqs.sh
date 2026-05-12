#!/usr/bin/env bash
# ============================================================================
# setup_liboqs.sh
#
# Baut liboqs MIT XMSS-Stateful-Support und installiert liboqs-python.
# Auszufuehren in WSL2 (Ubuntu 22.04).
#
# Hinweis zur Versionierung:
#   - liboqs wird auf Tag 0.15.0 gepinnt (Stand: 2025).
#   - liboqs-python wird auf Tag 0.14.0 gepinnt (letzte Release-Version).
#   - Die Versionen sind absichtlich nicht identisch - liboqs-python wird
#     weniger haeufig getaggt. liboqs-python 0.14.0 ist mit liboqs 0.15.0
#     kompatibel; beim Import erscheint nur eine UserWarning, die
#     funktional irrelevant ist.
# ============================================================================

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="${PROJECT_ROOT}/vendor"
PREFIX="${PROJECT_ROOT}/vendor/install"

LIBOQS_TAG="0.15.0"
LIBOQS_PYTHON_TAG="0.14.0"

mkdir -p "${VENDOR_DIR}"

# ---------------------------------------------------------------------------
# 1. liboqs (C-Bibliothek) MIT XMSS bauen
# ---------------------------------------------------------------------------
if [ ! -d "${VENDOR_DIR}/liboqs" ]; then
    echo ">>> Klone liboqs ${LIBOQS_TAG} ..."
    git clone --depth 1 --branch "${LIBOQS_TAG}" \
        https://github.com/open-quantum-safe/liboqs.git \
        "${VENDOR_DIR}/liboqs"
fi

echo ">>> Baue liboqs mit XMSS-Stateful-Support ..."
cd "${VENDOR_DIR}/liboqs"
rm -rf build
mkdir build && cd build

# Die HAZARDOUS-Flags sind noetig, weil liboqs den Stateful-Support
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
    echo ">>> Klone liboqs-python ${LIBOQS_PYTHON_TAG} ..."
    git clone --depth 1 --branch "${LIBOQS_PYTHON_TAG}" \
        https://github.com/open-quantum-safe/liboqs-python.git \
        "${VENDOR_DIR}/liboqs-python"
fi

echo ">>> Installiere liboqs-python ..."
cd "${VENDOR_DIR}/liboqs-python"
pip install .

echo ""
echo ">>> Setze diese Umgebungsvariable in deiner Shell:"
echo "    export LD_LIBRARY_PATH=\"${PREFIX}/lib:\${LD_LIBRARY_PATH:-}\""
echo ""
echo ">>> Fertig. Teste mit:"
echo "    cd ${PROJECT_ROOT}"
echo "    python -m src.smoke_test"
