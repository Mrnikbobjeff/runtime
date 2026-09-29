#!/usr/bin/env bash
# Prepares everything needed to fuzz the shipped .NET System.Text.RegularExpressions and
# System.Text.Json assemblies with SharpFuzz + AFL++. Idempotent; all state lives in .work/.
#
#   1. .NET 8 SDK + AFL++ (apt), used only to build the harness and run the sharpfuzz tool.
#   2. A private dotnet root containing the target .NET runtime (default: 11.0 RC1) taken
#      from the Microsoft.NETCore.App.Runtime.linux-x64 package on nuget.org, plus the
#      matching reference pack to compile against.
#   3. SharpFuzz.CommandLine, and StripR2R (tools/StripR2R), which rewrites the ReadyToRun
#      framework assemblies as IL-only so SharpFuzz agrees to instrument them.
#   4. Instrumented copies of the target assemblies installed into the private root.
#   5. The harness, built into .work/harness.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$HERE/.work"
DOTNET_VERSION="${DOTNET_VERSION:-11.0.0-rc.1.26425.128}"
SHARPFUZZ_VERSION="${SHARPFUZZ_VERSION:-2.3.0}"
TARGET_ASSEMBLIES=(System.Text.RegularExpressions System.Text.Json)
NUGET="https://api.nuget.org/v3-flatcontainer"

mkdir -p "$WORK"
cd "$WORK"

log() { printf '\n==> %s\n' "$*"; }

# 1. Toolchain -------------------------------------------------------------------------------
if ! command -v dotnet >/dev/null || ! command -v afl-fuzz >/dev/null || ! command -v unzip >/dev/null; then
    log "Installing dotnet-sdk-8.0, afl++ and unzip via apt"
    SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
    $SUDO apt-get update -qq
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq dotnet-sdk-8.0 afl++ unzip
fi
HOST_DOTNET="$(readlink -f "$(command -v dotnet)")"

# 2. Private .NET runtime root -----------------------------------------------------------------
fetch_pkg() { # id version dest
    local id="$1" ver="$2" dest="$3"
    if [ ! -d "$dest" ]; then
        log "Downloading $id $ver"
        curl -fsSL -o "$dest.nupkg" "$NUGET/$id/$ver/$id.$ver.nupkg"
        mkdir -p "$dest" && unzip -q -o "$dest.nupkg" -d "$dest" && rm "$dest.nupkg"
    fi
}
fetch_pkg microsoft.netcore.app.runtime.linux-x64 "$DOTNET_VERSION" "$WORK/runtime-pack"
fetch_pkg microsoft.netcore.app.ref "$DOTNET_VERSION" "$WORK/ref"

ROOT="$WORK/dotnet"
FX="$ROOT/shared/Microsoft.NETCore.App/$DOTNET_VERSION"
if [ ! -f "$FX/System.Private.CoreLib.dll" ]; then
    log "Assembling private dotnet root in $ROOT"
    mkdir -p "$FX" "$ROOT/host/fxr/$DOTNET_VERSION"
    cp "$WORK"/runtime-pack/runtimes/linux-x64/lib/net*/* "$FX/"
    cp "$WORK"/runtime-pack/runtimes/linux-x64/native/* "$FX/"
    mv "$FX/libhostfxr.so" "$ROOT/host/fxr/$DOTNET_VERSION/"
    cp "$HOST_DOTNET" "$ROOT/dotnet"
fi

# 3. Tools -------------------------------------------------------------------------------------
if [ ! -x "$WORK/tools/sharpfuzz" ]; then
    log "Installing SharpFuzz.CommandLine $SHARPFUZZ_VERSION"
    dotnet tool install SharpFuzz.CommandLine --version "$SHARPFUZZ_VERSION" --tool-path "$WORK/tools"
fi

log "Building StripR2R"
dotnet build "$HERE/tools/StripR2R/StripR2R.csproj" -c Release -o "$WORK/stripr2r" -v q -nologo

# 4. Instrument the target assemblies ----------------------------------------------------------
mkdir -p "$WORK/pristine" "$WORK/instrumented"
for asm in "${TARGET_ASSEMBLIES[@]}"; do
    marker="$WORK/instrumented/$asm.$DOTNET_VERSION.done"
    if [ -f "$marker" ]; then
        continue
    fi
    log "Instrumenting $asm"
    [ -f "$WORK/pristine/$asm.dll" ] || cp "$FX/$asm.dll" "$WORK/pristine/$asm.dll"
    dotnet "$WORK/stripr2r/StripR2R.dll" "$WORK/pristine/$asm.dll" "$WORK/instrumented/$asm.dll"
    "$WORK/tools/sharpfuzz" "$WORK/instrumented/$asm.dll"
    cp "$WORK/instrumented/$asm.dll" "$FX/$asm.dll"
    touch "$marker"
done

# 5. Harness -----------------------------------------------------------------------------------
log "Building SharpFuzzHarness"
dotnet build "$HERE/SharpFuzzHarness/SharpFuzzHarness.csproj" -c Release -o "$WORK/harness" -v q -nologo \
    -p:DotNetVersion="$DOTNET_VERSION" -p:NetRefDir="$(echo "$WORK"/ref/ref/net*/)"

log "Smoke test"
export DOTNET_ROOT="$ROOT" PATH="$ROOT:$PATH"
dotnet "$WORK/harness/SharpFuzzHarness.dll" regex --repro "$HERE"/seeds/regex/extra-00 >/dev/null
dotnet "$WORK/harness/SharpFuzzHarness.dll" json --repro "$HERE"/seeds/json/seed-00 >/dev/null
echo "Ready: .NET $DOTNET_VERSION with instrumented ${TARGET_ASSEMBLIES[*]}"
