using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace SharpFuzzHarness;

/// <summary>
/// Buffers placed right against an inaccessible (PROT_NONE) page, so a read or write one element past
/// the end (or before the start) of a span faults instead of silently touching neighbouring memory:
/// a poor man's AddressSanitizer for code that reads spans through Unsafe / vector loads. A fault in
/// managed code is a fatal AccessViolation, which AFL records as a crash.
/// </summary>
/// <remarks>
/// Linux only. The pool has <see cref="Slots"/> slots of <see cref="SlotBytes"/> bytes, each between two
/// guard pages; buffers are handed out round-robin, so up to <see cref="Slots"/> can be live at once.
/// </remarks>
internal static unsafe class Guarded
{
    public const int Slots = 64;
    public const int SlotBytes = 1 << 18;

    /// <summary>SHARPFUZZ_GUARD=1 turns the guarded placement on in the targets that support it.</summary>
    public static readonly bool Enabled = Environment.GetEnvironmentVariable("SHARPFUZZ_GUARD") == "1";

    private static readonly int s_page = Environment.SystemPageSize;
    private static byte* s_base;
    private static int s_next;

    [DllImport("libc", SetLastError = true)]
    private static extern nint mmap(nint addr, nuint length, int prot, int flags, int fd, nint offset);

    [DllImport("libc", SetLastError = true)]
    private static extern int mprotect(nint addr, nuint length, int prot);

    private const int ProtNone = 0, ProtReadWrite = 3, MapPrivateAnonymous = 0x02 | 0x20;

    private static int Stride => SlotBytes + s_page;

    private static byte* Base
    {
        get
        {
            if (s_base == null)
            {
                // [guard][slot 0][guard][slot 1][guard] ... [slot n-1][guard]
                nuint total = (nuint)(Slots * Stride + s_page);
                nint p = mmap(0, total, ProtReadWrite, MapPrivateAnonymous, -1, 0);
                if (p == -1)
                {
                    throw new InvalidOperationException($"mmap failed: {Marshal.GetLastPInvokeError()}");
                }

                for (int i = 0; i <= Slots; i++)
                {
                    if (mprotect(p + i * Stride, (nuint)s_page, ProtNone) != 0)
                    {
                        throw new InvalidOperationException($"mprotect failed: {Marshal.GetLastPInvokeError()}");
                    }
                }

                s_base = (byte*)p;
            }

            return s_base;
        }
    }

    /// <summary>The next slot's start (right after a guard page); it ends SlotBytes later, right before the next one.</summary>
    private static byte* NextSlot() => Base + (s_next++ % Slots) * Stride + s_page;

    /// <summary>
    /// A buffer of <paramref name="bytes"/> bytes that ends at a guard page, or starts right after one
    /// when <paramref name="atStart"/> is set. The contents are left as they are.
    /// </summary>
    public static byte* Allocate(long bytes, bool atStart)
    {
        if (bytes > SlotBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(bytes), $"{bytes} bytes don't fit a {SlotBytes}-byte guarded slot");
        }

        byte* start = NextSlot();
        return atStart ? start : start + SlotBytes - bytes;
    }

    /// <summary>A copy of <paramref name="values"/> (of a type without references) in guarded memory.</summary>
    public static Span<T> Copy<T>(ReadOnlySpan<T> values, bool atStart)
    {
        byte* p = Allocate((long)values.Length * Unsafe.SizeOf<T>(), atStart);
        Span<T> span = MemoryMarshal.CreateSpan(ref Unsafe.AsRef<T>(p), values.Length);
        values.CopyTo(span);
        return span;
    }

    /// <summary>A copy of <paramref name="values"/> in guarded memory, as a Memory (for code that keeps spans in closures).</summary>
    public static Memory<T> CopyMemory<T>(ReadOnlySpan<T> values, bool atStart)
    {
        byte* p = Allocate((long)values.Length * Unsafe.SizeOf<T>(), atStart);
        var manager = new Manager<T>(p, values.Length);
        values.CopyTo(manager.GetSpan());
        return manager.Memory;
    }

    private sealed class Manager<T>(byte* pointer, int length) : MemoryManager<T>
    {
        public override Span<T> GetSpan() => MemoryMarshal.CreateSpan(ref Unsafe.AsRef<T>(pointer), length);

        public override MemoryHandle Pin(int elementIndex = 0) => new(pointer + (long)elementIndex * Unsafe.SizeOf<T>());

        public override void Unpin()
        {
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
