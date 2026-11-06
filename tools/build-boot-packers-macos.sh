#!/bin/sh
# Build the boot packer and unpacker as universal (arm64 + x86_64) macOS
# executables with the Xcode command line tools. Same sources and inih
# defines as the CMake build; no CMake needed.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <build-dir> <output-dir>" >&2
    exit 2
fi

build_dir=$1
output_dir=$2
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/boot-packers" && pwd)
mkdir -p "$build_dir" "$output_dir"
build_dir=$(CDPATH= cd -- "$build_dir" && pwd)
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)

: "${MACOSX_DEPLOYMENT_TARGET:=12.0}"
export MACOSX_DEPLOYMENT_TARGET

build() {
    arch=$1
    name=$2
    shift 2
    mkdir -p "$build_dir/$arch"
    (
        cd "$source_dir"
        clang -arch "$arch" -std=c11 -O2 \
            -Iinc -Ilib/inih \
            -DINI_USE_STACK=0 -DINI_ALLOW_REALLOC=1 -DINI_MAX_LINE=8192 \
            -o "$build_dir/$arch/$name" "$@"
    )
}

for arch in arm64 x86_64; do
    build "$arch" MultiBootKernelPatcher \
        src/patcher.c src/pack.c src/image_format.c src/pack_config.c src/utils.c lib/inih/ini.c
    build "$arch" UnpackTool \
        src/unpack.c src/image_format.c src/utils.c
done

for name in MultiBootKernelPatcher UnpackTool; do
    lipo -create -output "$output_dir/$name" \
        "$build_dir/arm64/$name" "$build_dir/x86_64/$name"
done
