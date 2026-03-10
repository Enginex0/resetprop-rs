#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$SCRIPT_DIR/out"

declare -A ABI_TARGET=(
    [arm64-v8a]=aarch64-linux-android
    [armeabi-v7a]=armv7-linux-androideabi
)

find_ndk() {
    if [ -n "${ANDROID_NDK_HOME:-}" ] && [ -d "$ANDROID_NDK_HOME" ]; then
        echo "$ANDROID_NDK_HOME"; return 0
    fi
    if [ -n "${ANDROID_HOME:-}" ] && [ -d "$ANDROID_HOME/ndk" ]; then
        local latest
        latest=$(ls -1 "$ANDROID_HOME/ndk" 2>/dev/null | sort -V | tail -1)
        if [ -n "$latest" ] && [ -d "$ANDROID_HOME/ndk/$latest/toolchains" ]; then
            echo "$ANDROID_HOME/ndk/$latest"; return 0
        fi
    fi
    if [ -n "${NDK_HOME:-}" ] && [ -d "$NDK_HOME" ]; then
        echo "$NDK_HOME"; return 0
    fi
    for sdk in "$HOME/Android/Sdk/ndk" "$HOME/Library/Android/sdk/ndk"; do
        if [ -d "$sdk" ]; then
            local latest
            latest=$(ls -1 "$sdk" 2>/dev/null | sort -V | tail -1)
            if [ -n "$latest" ] && [ -d "$sdk/$latest/toolchains" ]; then
                echo "$sdk/$latest"; return 0
            fi
        fi
    done
    for path in "/opt/android-ndk" "/opt/android-ndk-r26d" "/opt/android-ndk-r25b"; do
        if [ -d "$path/toolchains" ]; then
            echo "$path"; return 0
        fi
    done
    return 1
}

NDK_HOME=$(find_ndk) || { echo "FATAL: Android NDK not found." >&2; exit 1; }
NDK_BIN="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
[ -d "$NDK_BIN" ] || { echo "FATAL: NDK toolchain not found at $NDK_BIN" >&2; exit 1; }

export PATH="$NDK_BIN:$PATH"
export CC_aarch64_linux_android="$NDK_BIN/aarch64-linux-android26-clang"
export CC_armv7_linux_androideabi="$NDK_BIN/armv7a-linux-androideabi26-clang"
export AR_aarch64_linux_android="$NDK_BIN/llvm-ar"
export AR_armv7_linux_androideabi="$NDK_BIN/llvm-ar"

echo "NDK: $NDK_HOME"

for abi in "${!ABI_TARGET[@]}"; do
    target="${ABI_TARGET[$abi]}"
    rustup target list --installed | grep -q "$target" || rustup target add "$target"
done

STRIP="$NDK_BIN/llvm-strip"
[ -x "$STRIP" ] || STRIP=$(command -v llvm-strip 2>/dev/null || command -v strip 2>/dev/null || true)

cd "$SCRIPT_DIR"
mkdir -p "$OUT_DIR"

built=0
for abi in "${!ABI_TARGET[@]}"; do
    target="${ABI_TARGET[$abi]}"
    echo "=== Building $abi ($target) ==="

    if cargo build --release --target "$target"; then
        src="target/$target/release/resetprop"
        dst="$OUT_DIR/resetprop-$abi"
        cp "$src" "$dst"
        [ -n "$STRIP" ] && [ -x "$STRIP" ] && "$STRIP" "$dst"
        built=$((built + 1))
        echo "  $abi: $(du -h "$dst" | cut -f1)"
    else
        echo "FAILED: $abi" >&2
        exit 1
    fi
done

echo ""
echo "=== Done: $built targets ==="
ls -lh "$OUT_DIR"/resetprop-*
