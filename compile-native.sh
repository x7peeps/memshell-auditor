#!/bin/bash
# 编译 native JVMTI 模块（macOS .dylib）
set -e
JAVA_HOME="/Library/Java/JavaVirtualMachines/temurin-26.jdk/Contents/Home"
SRC="src/main/native/nativejvmti.c"
OUT="target/native"
mkdir -p "$OUT"

echo "[*] 编译 native JVMTI 模块..."
clang -dynamiclib -O2 -fPIC \
    -I"$JAVA_HOME/include" \
    -I"$JAVA_HOME/include/darwin" \
    -o "$OUT/libnativejvmti.dylib" \
    "$SRC" \
    -framework JavaVM 2>&1 || {
    # 备用：不需要框架
    clang -dynamiclib -O2 -fPIC \
        -I"$JAVA_HOME/include" \
        -I"$JAVA_HOME/include/darwin" \
        -o "$OUT/libnativejvmti.dylib" \
        "$SRC"
}

ls -la "$OUT/libnativejvmti.dylib"
echo "[✓] native 模块编译完成: $OUT/libnativejvmti.dylib"
