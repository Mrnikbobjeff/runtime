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
WORK="${SHARPFUZZ_WORK:-$HERE/.work}"
DOTNET_VERSION="${DOTNET_VERSION:-11.0.0-rc.1.26425.128}"
SHARPFUZZ_VERSION="${SHARPFUZZ_VERSION:-2.3.0}"
TARGET_ASSEMBLIES=(System.Text.RegularExpressions System.Text.Json System.Linq System.Collections System.Collections.Immutable
    System.Private.Uri System.Runtime.Numerics System.Formats.Asn1 System.Reflection.Metadata
    System.Net.ServerSentEvents System.Data.Common System.Diagnostics.DiagnosticSource System.Net.Mail
    System.Text.Encoding.CodePages System.Memory System.Net.Primitives System.Web.HttpUtility System.Linq.AsyncEnumerable
    System.Private.Xml System.Private.DataContractSerialization)
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

# System.Private.CoreLib: SharpFuzz requires an explicit type list for CoreLib, so instrument
# every top-level type except the runtime-infrastructure prefixes in corelib-exclude.txt
# (those recurse during startup). The exclusions are also passed as SharpFuzz "-prefix"
# arguments so nested types and look-alike names stay excluded. Re-instruments whenever
# corelib-exclude.txt changes. INSTRUMENT_CORELIB=0 keeps the stock CoreLib.
if [ "${INSTRUMENT_CORELIB:-1}" != 0 ]; then
    # Bump the recipe version when the instrumentation steps change.
    exclude_hash="$(sha256sum "$HERE/corelib-exclude.txt" | cut -c1-16)"
    marker="$WORK/instrumented/System.Private.CoreLib.$DOTNET_VERSION.$exclude_hash.r2.done"
    if [ ! -f "$marker" ]; then
        log "Instrumenting System.Private.CoreLib"
        rm -f "$WORK"/instrumented/System.Private.CoreLib.*.done
        [ -f "$WORK/pristine/System.Private.CoreLib.dll" ] || cp "$FX/System.Private.CoreLib.dll" "$WORK/pristine/"
        dotnet "$WORK/stripr2r/StripR2R.dll" "$WORK/pristine/System.Private.CoreLib.dll" "$WORK/instrumented/System.Private.CoreLib.dll"
        mapfile -t excludes < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' "$HERE/corelib-exclude.txt" | grep -v '^$')
        # Top-level types minus everything starting with an excluded prefix (case-insensitive,
        # like SharpFuzz's own matcher).
        dotnet "$WORK/stripr2r/StripR2R.dll" --list-types "$WORK/instrumented/System.Private.CoreLib.dll" \
            | awk -v list="$(printf '%s\n' "${excludes[@]}")" '
                BEGIN { n = split(tolower(list), ex, "\n") }
                { t = tolower($0); for (i = 1; i <= n; i++) if (ex[i] != "" && index(t, ex[i]) == 1) next; print }' \
            > "$WORK/instrumented/corelib-types.txt"
        echo "$(wc -l < "$WORK/instrumented/corelib-types.txt") CoreLib types selected for instrumentation"
        exclude_arg="-$(IFS=,; echo "${excludes[*]}")"
        "$WORK/tools/sharpfuzz" "$WORK/instrumented/System.Private.CoreLib.dll" \
            "$(paste -sd, "$WORK/instrumented/corelib-types.txt")" "$exclude_arg"
        dotnet "$WORK/stripr2r/StripR2R.dll" --thread-static-trace "$WORK/instrumented/System.Private.CoreLib.dll"
        cp "$WORK/instrumented/System.Private.CoreLib.dll" "$FX/System.Private.CoreLib.dll"
        touch "$marker"
    fi
elif [ -f "$WORK/pristine/System.Private.CoreLib.dll" ] && ! cmp -s "$WORK/pristine/System.Private.CoreLib.dll" "$FX/System.Private.CoreLib.dll"; then
    log "Restoring stock System.Private.CoreLib"
    cp "$WORK/pristine/System.Private.CoreLib.dll" "$FX/System.Private.CoreLib.dll"
    rm -f "$WORK"/instrumented/System.Private.CoreLib.*.done
fi

# System.Numerics.Tensors ships as a NuGet package, not in the shared framework. The harness
# references an instrumented copy of it, so it lands next to the harness. TENSORS_DLL=<path to a
# net11.0 System.Numerics.Tensors.dll> fuzzes a local build (e.g. a PR branch) instead.
fetch_pkg system.numerics.tensors "$DOTNET_VERSION" "$WORK/tensors-pkg"
TENSORS_SRC="${TENSORS_DLL:-$(echo "$WORK"/tensors-pkg/lib/net11.0/System.Numerics.Tensors.dll)}"
tensors_hash="$(sha256sum "$TENSORS_SRC" | cut -c1-16)"
if [ ! -f "$WORK/instrumented/System.Numerics.Tensors.$tensors_hash.done" ]; then
    log "Instrumenting System.Numerics.Tensors from $TENSORS_SRC"
    rm -f "$WORK"/instrumented/System.Numerics.Tensors.*.done
    dotnet "$WORK/stripr2r/StripR2R.dll" "$TENSORS_SRC" "$WORK/instrumented/System.Numerics.Tensors.dll"
    "$WORK/tools/sharpfuzz" "$WORK/instrumented/System.Numerics.Tensors.dll"
    touch "$WORK/instrumented/System.Numerics.Tensors.$tensors_hash.done"
fi

# Other out-of-band (NuGet-only) packages the harness references, instrumented the same way.
OOB_PACKAGES=(System.Formats.Cbor System.IO.Hashing)
for id in "${OOB_PACKAGES[@]}"; do
    lower="$(echo "$id" | tr '[:upper:]' '[:lower:]')"
    fetch_pkg "$lower" "$DOTNET_VERSION" "$WORK/pkg-$lower"
    marker="$WORK/instrumented/$id.$DOTNET_VERSION.oob.done"
    if [ ! -f "$marker" ]; then
        log "Instrumenting $id (NuGet package)"
        src="$WORK/pkg-$lower/lib/net11.0/$id.dll"
        [ -f "$src" ] || src="$(ls "$WORK/pkg-$lower"/lib/net1*.0/$id.dll | tail -1)"
        dotnet "$WORK/stripr2r/StripR2R.dll" "$src" "$WORK/instrumented/$id.dll"
        "$WORK/tools/sharpfuzz" "$WORK/instrumented/$id.dll"
        touch "$marker"
    fi
done

# 5. Harness -----------------------------------------------------------------------------------
log "Building SharpFuzzHarness"
dotnet build "$HERE/SharpFuzzHarness/SharpFuzzHarness.csproj" -c Release -o "$WORK/harness" -v q -nologo \
    -p:DotNetVersion="$DOTNET_VERSION" -p:NetRefDir="$(echo "$WORK"/ref/ref/net*/)" \
    -p:TensorsDll="$WORK/instrumented/System.Numerics.Tensors.dll" -p:OobDir="$WORK/instrumented/"

log "Smoke test"
export DOTNET_ROOT="$ROOT" PATH="$ROOT:$PATH"
dotnet "$WORK/harness/SharpFuzzHarness.dll" regex --repro "$HERE"/seeds/regex/extra-00 >/dev/null
dotnet "$WORK/harness/SharpFuzzHarness.dll" json --repro "$HERE"/seeds/json/seed-00 >/dev/null
if [ "${INSTRUMENT_CORELIB:-1}" != 0 ]; then
    TZ=UTC dotnet "$WORK/harness/SharpFuzzHarness.dll" number --repro "$HERE"/seeds/number/seed-000 >/dev/null
    echo "Ready: .NET $DOTNET_VERSION with instrumented ${TARGET_ASSEMBLIES[*]} System.Private.CoreLib"
else
    echo "Ready: .NET $DOTNET_VERSION with instrumented ${TARGET_ASSEMBLIES[*]}"
fi
