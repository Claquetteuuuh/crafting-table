#!/bin/bash
set -e

NIM_FILE=$1
PASS_NAME=$2

echo "[1/5] Compilation des Passes LLVM..."
ls -la /app/llvm-pass
clang++ -shared -fPIC $(llvm-config --cxxflags) ./llvm-pass/*.cpp -o /app/MyPlugin.so $(llvm-config --ldflags --libs)
if [ $? -ne 0 ]; then
    echo "Erreur compilation clang++"
    exit 1
fi
ls -la /app/MyPlugin.so

echo "[2/5] Nettoyage et Génération de l'IR LLVM..."
# --- CETTE LIGNE EST CRUCIALE ---
mkdir -p ir_output
rm -rf ir_output/*

# Génération de l'IR par Nim (-f pour forcer)
nim c -f -d:ssl -d:release -d:mingw --os:windows --cpu:amd64 --cc:clang \
  --passC:"-S -emit-llvm -target x86_64-w64-mingw32" \
  --nimcache:ir_output "$NIM_FILE" || true

echo "[3/5] Fusion des modules IR..."
# On vérifie qu'on a bien des fichiers à lier
if [ -z "$(ls -A ir_output/*.o 2>/dev/null)" ]; then
    echo "Erreur : Aucun fichier IR trouvé dans ir_output/"
    exit 1
fi
llvm-link ir_output/*.o -S -o /tmp/full.ll

echo "[4/5] Application du pipeline : $PASS_NAME"
opt -load-pass-plugin=/app/MyPlugin.so -passes="$PASS_NAME" /tmp/full.ll -S -o /tmp/opt.ll

echo "[5/5] Compilation du .exe final..."
LIBGCC_PATH=$(find /usr/lib/gcc/x86_64-w64-mingw32 -name "10-win32" | head -n 1)
clang -target x86_64-w64-mingw32 /tmp/opt.ll -o ./output_final.exe \
  -L"$LIBGCC_PATH" -L/usr/x86_64-w64-mingw32/lib/ \
  -fuse-ld=/usr/bin/ld.lld-14 -static \
  -lkernel32 -luser32 -lpsapi -lshlwapi -lws2_32 -lmsvcrt -lole32 -luuid

echo "==========================================="
echo "SUCCÈS : 'output_final.exe' généré."