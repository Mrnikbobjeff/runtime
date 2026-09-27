using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using SharpFuzz;

namespace SharpFuzzHarness;

/// <summary>
/// Connects the coverage map of an instrumented System.Private.CoreLib to AFL.
/// </summary>
/// <remarks>
/// sharpfuzz can't make CoreLib reference SharpFuzz.Common, so it embeds a private copy of
/// <c>SharpFuzz.Common.Trace</c> in CoreLib, whose static constructor points it at a scratch buffer.
/// <c>Fuzzer.OutOfProcess</c> only attaches <c>SharpFuzz.Common.Trace</c> to the AFL shared
/// memory, so without this CoreLib coverage never reaches AFL.
///
/// CoreLib is also used by the harness plumbing (stream copies, the fork-server pipes, the
/// thread that watches the parent process), so the CoreLib trace only points at the AFL map
/// while the target runs (<see cref="Enter"/> / <see cref="Leave"/>). Everything else writes
/// into the scratch buffer, which keeps that plumbing out of the coverage and stability numbers.
/// </remarks>
internal static unsafe class CoreLibTrace
{
    private static readonly Action<nint>? s_setSharedMem;
    private static readonly Action? s_resetPrevLocation;
    private static readonly nint s_scratch = (nint)NativeMemory.AllocZeroed(1 << 16);

    static CoreLibTrace()
    {
        // sharpfuzz creates the type with an empty namespace and the name "SharpFuzz.Common.Trace",
        // which Assembly.GetType(string) can't find, so look it up by FullName instead.
        Type? trace = typeof(object).Assembly.GetTypes().FirstOrDefault(t => t.FullName == "SharpFuzz.Common.Trace");
        FieldInfo? sharedMem = trace?.GetField("SharedMem", BindingFlags.Public | BindingFlags.Static);
        FieldInfo? prevLocation = trace?.GetField("PrevLocation", BindingFlags.Public | BindingFlags.Static);
        if (sharedMem is null || prevLocation is null)
        {
            return; // CoreLib isn't instrumented.
        }

        var set = new DynamicMethod("SetCoreLibSharedMem", null, [typeof(nint)], typeof(CoreLibTrace).Module, skipVisibility: true);
        ILGenerator il = set.GetILGenerator();
        il.Emit(OpCodes.Ldarg_0);
        il.Emit(OpCodes.Stsfld, sharedMem);
        il.Emit(OpCodes.Ret);
        s_setSharedMem = set.CreateDelegate<Action<nint>>();

        var reset = new DynamicMethod("ResetCoreLibPrevLocation", null, Type.EmptyTypes, typeof(CoreLibTrace).Module, skipVisibility: true);
        il = reset.GetILGenerator();
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Stsfld, prevLocation);
        il.Emit(OpCodes.Ret);
        s_resetPrevLocation = reset.CreateDelegate<Action>();

        s_setSharedMem(s_scratch);
    }

    public static bool IsInstrumented => s_setSharedMem is not null;

    /// <summary>Starts recording CoreLib coverage into the map SharpFuzz.Common.Trace uses.</summary>
    public static void Enter()
    {
        if (s_setSharedMem is not null)
        {
            s_resetPrevLocation!();
            s_setSharedMem((nint)SharpFuzz.Common.Trace.SharedMem);
        }
    }

    /// <summary>Stops recording CoreLib coverage.</summary>
    public static void Leave() => s_setSharedMem?.Invoke(s_scratch);

    /// <summary>
    /// Runs <paramref name="target"/> once with all coverage (CoreLib and SharpFuzz.Common) going to
    /// the scratch buffer, then once more recording into the AFL map. CoreLib is full of caches that
    /// are filled on first use (the small-number string cache, parsed format strings, ArrayPool
    /// buckets, Enum name tables, ...), so the first run of an input takes paths the following runs
    /// don't, and AFL's calibration marks all of them unstable. Recording only the second run makes
    /// coverage a function of the input again. An exception from the first run propagates as is.
    /// </summary>
    public static void RunWithWarmup(ReadOnlySpanAction target, ReadOnlySpan<byte> data)
    {
        byte* map = SharpFuzz.Common.Trace.SharedMem;
        SharpFuzz.Common.Trace.SharedMem = (byte*)s_scratch;
        try
        {
            target(data);
        }
        finally
        {
            SharpFuzz.Common.Trace.SharedMem = map;
            SharpFuzz.Common.Trace.PrevLocation = 0;
        }

        Run(target, data);
    }

    /// <summary>Runs <paramref name="target"/> once, recording CoreLib coverage.</summary>
    public static void Run(ReadOnlySpanAction target, ReadOnlySpan<byte> data)
    {
        Enter();
        try
        {
            target(data);
        }
        finally
        {
            Leave();
        }
    }
}
