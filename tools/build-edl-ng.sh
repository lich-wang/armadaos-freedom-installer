#!/bin/sh
set -eu

# The optional runtime identifier defaults to win-x64 (the Windows installer); the macOS window build
# passes osx-arm64.
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 <output-dir> [runtime-id]" >&2
    exit 2
fi

output=$1
runtime=${2:-win-x64}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(CDPATH= cd -- "$script_dir/edl-ng" && pwd)
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)

dotnet publish "$source_dir/QCEDL.CLI/QCEDL.CLI.csproj" \
    -c Release \
    -r "$runtime" \
    --self-contained true \
    -p:PublishAot=false \
    -p:EnableCompressionInSingleFile=true \
    -p:UseSharedCompilation=false \
    -o "$output"
