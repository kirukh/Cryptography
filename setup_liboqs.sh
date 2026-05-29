#!/usr/bin/env bash
# ============================================================================
# setup_liboqs.sh
#
# Baut liboqs MIT XMSS-Stateful-Support und installiert liboqs-python.
# Auszufuehren in WSL2 (Ubuntu 22.04).
#
# Hinweis zur Versionierung:
#   - liboqs wird auf Tag 0.15.0 gepinnt (Stand: 2025).
#   - liboqs-python wird aus 'main' geklont (--depth 1, kein Branch).
#     Begruendung: zum Zeitpunkt der Arbeit existieren keine
#     liboqs-python-Release-Tags, die mit liboqs 0.15.0 kompatibel
#     sind. Beim Import erscheint eine UserWarning ueber die
#     Versions-Differenz - funktional irrelevant.
#   - Falls Reproduzierbarkeit auf den Tag genau gewuenscht ist, kann
#     im Anschluss in vendor/liboqs-python ein 'git rev-parse HEAD' den
#     verwendeten Commit-Hash dokumentieren.
# ============================================================================

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="${PROJECT_ROOT}/vendor"
PREFIX="${PROJECT_ROOT}/vendor/install"

LIBOQS_TAG="0.15.0"

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
# 2. liboqs-python installieren (aus main; siehe Kopf-Kommentar)
# ---------------------------------------------------------------------------
if [ ! -d "${VENDOR_DIR}/liboqs-python" ]; then
    echo ">>> Klone liboqs-python (main; kein kompatibler Tag verfuegbar) ..."
    git clone --depth 1 \
        https://github.com/open-quantum-safe/liboqs-python.git \
        "${VENDOR_DIR}/liboqs-python"
fi

# Verwendeten Commit dokumentieren - hilft bei spaeterer Reproduktion.
LIBOQS_PYTHON_COMMIT="$(cd "${VENDOR_DIR}/liboqs-python" && git rev-parse HEAD)"
echo ">>> liboqs-python Commit: ${LIBOQS_PYTHON_COMMIT}"

echo ">>> Installiere liboqs-python ..."
cd "${VENDOR_DIR}/liboqs-python"
pip install .

echo ""
echo ">>> Setze diese Umgebungsvariable in deiner Shell:"
echo "    export LD_LIBRARY_PATH=\"${PREFIX}/lib:\${LD_LIBRARY_PATH:-}\""
echo ""
echo ">>> Verwendete Versionen (fuer Ausarbeitung / Reproduktion):"
echo "    liboqs            : tag ${LIBOQS_TAG}"
echo "    liboqs-python     : main @ ${LIBOQS_PYTHON_COMMIT}"
echo ""
echo ">>> Fertig. Teste mit:"
echo "    cd ${PROJECT_ROOT}"
echo "    python -m src.smoke_test"