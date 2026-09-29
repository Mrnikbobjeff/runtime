#nullable disable warnings
using System.Collections;
using System.Numerics;

namespace SharpFuzzHarness;

/// <summary>
/// Managed-array code built on Unsafe / Memmove / vectors: BitArray (constructors, And / Or / Xor / Not,
/// shifts, CopyTo into int / byte / bool arrays, HasAllSet / HasAnySet, Length changes) against a bool[]
/// model; Array.Copy with primitive widening, Buffer.BlockCopy, Array.Reverse / Fill / IndexOf /
/// LastIndexOf over ranges; BitOperations against scalar models. Arrays can't sit against a guard page,
/// so every destination has sentinel elements on both sides of the range written, which must survive.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     operation; bytes 1-3 parameters
///   rest       the data
/// </remarks>
public static class ArraysTarget
{
    private const int Pad = 9;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte op = input.Byte();
        byte p1 = input.Byte(), p2 = input.Byte(), p3 = input.Byte();
        byte[] bytes = input.Rest().ToArray();
        if (bytes.Length > 4096)
        {
            return;
        }

        string what = $"op {op % 4} {p1:X2}{p2:X2}{p3:X2}, {bytes.Length} bytes 0x{Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 32)))}";
        switch (op % 4)
        {
            case 0: Bits(bytes, p1, p2, p3, what); break;
            case 1: Copies(bytes, p1, p2, p3, what); break;
            case 2: Ranges(bytes, p1, p2, p3, what); break;
            default: Operations(bytes, what); break;
        }
    }

    private static bool[] Model(BitArray b)
    {
        bool[] m = new bool[b.Length];
        for (int i = 0; i < m.Length; i++)
        {
            m[i] = b[i];
        }

        return m;
    }

    private static void Same(bool[] model, BitArray actual, string step, string what)
    {
        Check.Equal(model.Length, actual.Length, $"BitArray length after {step}: {what}");
        for (int i = 0; i < model.Length; i++)
        {
            if (model[i] != actual[i])
            {
                Check.That(false, $"BitArray bit {i} of {model.Length} after {step} is {actual[i]}: {what}");
            }
        }
    }

    private static void Bits(byte[] bytes, byte p1, byte p2, byte p3, string what)
    {
        int length = Math.Min(bytes.Length * 8, 1 + p1 * 7 % 1500);
        bool[] model = new bool[length];
        for (int i = 0; i < length; i++)
        {
            model[i] = (bytes[i / 8] >> (i % 8) & 1) != 0;
        }

        // Constructors: from bool[], byte[], int[].
        var a = new BitArray(model);
        Same(model, a, "ctor(bool[])", what);
        byte[] packed = new byte[(length + 7) / 8];
        bytes.AsSpan(0, packed.Length).CopyTo(packed);
        var fromBytes = new BitArray(packed) { Length = length };
        Same(model, fromBytes, "ctor(byte[])", what);
        int[] ints = new int[(length + 31) / 32];
        Buffer.BlockCopy(packed, 0, ints, 0, packed.Length);
        var fromInts = new BitArray(ints) { Length = length };
        Same(model, fromInts, "ctor(int[])", what);

        // A second operand from the rest of the data.
        bool[] other = new bool[length];
        for (int i = 0; i < length; i++)
        {
            other[i] = (bytes[(bytes.Length - 1 - i / 8 % bytes.Length + bytes.Length) % bytes.Length] >> (i % 8 ^ p3 & 7) & 1) != 0;
        }

        var b = new BitArray(other);
        var input = new FuzzInput(bytes);
        for (int step = 0; step < 8 && input.Remaining > 0; step++)
        {
            byte op = input.Byte();
            int n = input.Byte() * (1 + (p2 & 3)) % (length + 3);
            string name = (op % 8) switch { 0 => "And", 1 => "Or", 2 => "Xor", 3 => "Not", 4 => $"LeftShift({n})", 5 => $"RightShift({n})", 6 => $"Length = {n}", _ => $"SetAll / Set({n})" };
            switch (op % 8)
            {
                case 0: a.And(b); for (int i = 0; i < model.Length; i++) model[i] &= other[i]; break;
                case 1: a.Or(b); for (int i = 0; i < model.Length; i++) model[i] |= other[i]; break;
                case 2: a.Xor(b); for (int i = 0; i < model.Length; i++) model[i] ^= other[i]; break;
                case 3: a.Not(); for (int i = 0; i < model.Length; i++) model[i] = !model[i]; break;
                case 4:
                    a.LeftShift(n);
                    for (int i = model.Length - 1; i >= 0; i--) model[i] = i - n >= 0 && model[i - n];
                    break;
                case 5:
                    a.RightShift(n);
                    for (int i = 0; i < model.Length; i++) model[i] = i + n < model.Length && model[i + n];
                    break;
                case 6:
                {
                    // Shrink and grow back: the bits beyond the shorter length must come back cleared.
                    int shorter = Math.Min(n, a.Length);
                    a.Length = shorter;
                    a.Length = model.Length;
                    for (int i = shorter; i < model.Length; i++) model[i] = false;
                    break;
                }

                default:
                    if (n < model.Length)
                    {
                        a.Set(n, !a[n]);
                        model[n] = !model[n];
                    }
                    else
                    {
                        a.SetAll((op & 8) != 0);
                        Array.Fill(model, (op & 8) != 0);
                    }

                    break;
            }

            Same(model, a, name, what);
            Check.Equal(model.All(x => x), a.HasAllSet(), $"HasAllSet after {name}: {what}");
            Check.Equal(model.Any(x => x), a.HasAnySet(), $"HasAnySet after {name}: {what}");
        }

        // CopyTo into bool[] / byte[] / int[] at an offset, with sentinels around the range.
        int offset = p3 % 5;
        bool[] boolDest = Enumerable.Repeat(true, Pad + offset + length + Pad).ToArray();
        Array.Fill(boolDest, false, 0, Pad);
        Array.Fill(boolDest, false, Pad + offset + length, Pad);
        a.CopyTo(boolDest, Pad + offset);
        Check.That(boolDest.AsSpan(Pad + offset, length).SequenceEqual(model), $"CopyTo(bool[]): {what}");
        Check.That(boolDest.AsSpan(0, Pad).IndexOf(true) < 0 && boolDest.AsSpan(Pad + offset + length).IndexOf(true) < 0 && boolDest.AsSpan(Pad, offset).IndexOf(false) < 0,
            $"CopyTo(bool[], {Pad + offset}) wrote outside [{Pad + offset}, {Pad + offset + length}): {what}");

        int byteCount = (length + 7) / 8;
        byte[] byteDest = Enumerable.Repeat((byte)0xA5, Pad + byteCount + Pad).ToArray();
        a.CopyTo(byteDest, Pad);
        for (int i = 0; i < length; i++)
        {
            Check.Equal(model[i], (byteDest[Pad + i / 8] >> (i % 8) & 1) != 0, $"CopyTo(byte[]) bit {i}: {what}");
        }

        Check.That(byteDest.AsSpan(0, Pad).IndexOfAnyExcept((byte)0xA5) < 0 && byteDest.AsSpan(Pad + byteCount).IndexOfAnyExcept((byte)0xA5) < 0, $"CopyTo(byte[]) wrote outside its range: {what}");
        int intCount = (length + 31) / 32;
        int[] intDest = Enumerable.Repeat(0x5A5A5A5A, Pad + intCount + Pad).ToArray();
        a.CopyTo(intDest, Pad);
        Check.That(intDest.AsSpan(0, Pad).IndexOfAnyExcept(0x5A5A5A5A) < 0 && intDest.AsSpan(Pad + intCount).IndexOfAnyExcept(0x5A5A5A5A) < 0, $"CopyTo(int[]) wrote outside its range: {what}");
        for (int i = 0; i < length; i++)
        {
            Check.Equal(model[i], (intDest[Pad + i / 32] >> (i % 32) & 1) != 0, $"CopyTo(int[]) bit {i}: {what}");
        }

        var clone = (BitArray)a.Clone();
        Same(model, clone, "Clone", what);
    }

    /// <summary>Array.Copy with primitive widening, and Buffer.BlockCopy, into arrays with sentinels.</summary>
    private static void Copies(byte[] bytes, byte p1, byte p2, byte p3, string what)
    {
        if (bytes.Length < 8)
        {
            return;
        }

        int count = Math.Min(bytes.Length / 8, p1 % 300);
        int srcIndex = p2 % 4, dstIndex = Pad + p3 % 4;
        sbyte[] sb = new sbyte[count + srcIndex];
        for (int i = 0; i < sb.Length; i++) sb[i] = (sbyte)bytes[i % Math.Max(1, bytes.Length)];
        short[] sh = sb.Select(x => (short)(x * 257)).ToArray();
        int[] it = sb.Select(x => x * 16777619).ToArray();
        float[] fl = it.Select(x => (float)x).ToArray();

        WidenTo<sbyte, int>(sb, srcIndex, count, dstIndex, x => x, what);
        WidenTo<sbyte, long>(sb, srcIndex, count, dstIndex, x => x, what);
        WidenTo<sbyte, double>(sb, srcIndex, count, dstIndex, x => x, what);
        WidenTo<short, int>(sh, srcIndex, count, dstIndex, x => x, what);
        WidenTo<short, float>(sh, srcIndex, count, dstIndex, x => x, what);
        WidenTo<int, long>(it, srcIndex, count, dstIndex, x => x, what);
        WidenTo<int, double>(it, srcIndex, count, dstIndex, x => x, what);
        WidenTo<float, double>(fl, srcIndex, count, dstIndex, x => x, what);
        WidenTo<byte, ushort>(bytes, srcIndex, Math.Min(count, bytes.Length - srcIndex), dstIndex, x => x, what);
        WidenTo<byte, char>(bytes, srcIndex, Math.Min(count, bytes.Length - srcIndex), dstIndex, x => (char)x, what);

        // Buffer.BlockCopy between different element types at byte offsets.
        int byteCount = Math.Min(bytes.Length - srcIndex, count * 3);
        long[] dest = Enumerable.Repeat(0x1122334455667788L, Pad + (byteCount + 7) / 8 + Pad).ToArray();
        int dstByte = Pad * 8 + p3 % 8;
        Buffer.BlockCopy(bytes, srcIndex, dest, dstByte, byteCount);
        byte[] view = new byte[dest.Length * 8];
        Buffer.BlockCopy(dest, 0, view, 0, view.Length);
        Check.That(view.AsSpan(dstByte, byteCount).SequenceEqual(bytes.AsSpan(srcIndex, byteCount)), $"Buffer.BlockCopy content: {what}");
        byte[] sentinel = BitConverter.GetBytes(0x1122334455667788L);
        for (int i = 0; i < view.Length; i++)
        {
            if (i < dstByte || i >= dstByte + byteCount)
            {
                Check.Equal(sentinel[i % 8], view[i], $"Buffer.BlockCopy wrote byte {i} outside [{dstByte}, {dstByte + byteCount}): {what}");
            }
        }
    }

    private static void WidenTo<TFrom, TTo>(TFrom[] source, int srcIndex, int count, int dstIndex, Func<TFrom, TTo> widen, string what)
    {
        if (count <= 0 || srcIndex + count > source.Length)
        {
            return;
        }

        TTo[] dest = new TTo[dstIndex + count + Pad];
        TTo fill = typeof(TTo) == typeof(double) ? (TTo)(object)double.NaN : typeof(TTo) == typeof(float) ? (TTo)(object)float.NaN : (TTo)Convert.ChangeType(113, typeof(TTo));
        Array.Fill(dest, fill);
        Array.Copy(source, srcIndex, dest, dstIndex, count);
        for (int i = 0; i < dest.Length; i++)
        {
            bool inside = i >= dstIndex && i < dstIndex + count;
            TTo expected = inside ? widen(source[srcIndex + i - dstIndex]) : fill;
            if (!EqualityComparer<TTo>.Default.Equals(expected, dest[i]))
            {
                Check.That(false, $"Array.Copy {typeof(TFrom).Name}[] -> {typeof(TTo).Name}[] ({srcIndex}, {dstIndex}, {count}): element {i} is {dest[i]}, expected {expected}: {what}");
            }
        }
    }

    /// <summary>Array.Reverse / Fill / IndexOf / LastIndexOf / Clear over ranges.</summary>
    private static void Ranges(byte[] bytes, byte p1, byte p2, byte p3, string what)
    {
        foreach (int size in (int[])[1, 2, 4, 8])
        {
            int n = bytes.Length / size;
            if (n == 0)
            {
                continue;
            }

            int start = p1 % n, length = Math.Min(n - start, p2 % (n + 1));
            switch (size)
            {
                case 1: Range<byte>(bytes.ToArray(), start, length, bytes[^1], what); break;
                case 2: Range<short>(System.Runtime.InteropServices.MemoryMarshal.Cast<byte, short>(bytes.AsSpan(0, n * 2)).ToArray(), start, length, (short)(bytes[^1] | p3 << 8), what); break;
                case 4: Range<int>(System.Runtime.InteropServices.MemoryMarshal.Cast<byte, int>(bytes.AsSpan(0, n * 4)).ToArray(), start, length, bytes[^1] | p3 << 8, what); break;
                default: Range<long>(System.Runtime.InteropServices.MemoryMarshal.Cast<byte, long>(bytes.AsSpan(0, n * 8)).ToArray(), start, length, bytes[^1], what); break;
            }
        }
    }

    private static void Range<T>(T[] array, int start, int length, T value, string what) where T : IEquatable<T>
    {
        T[] original = array.ToArray();
        int expectedIndex = -1, expectedLast = -1;
        for (int i = start; i < start + length; i++)
        {
            if (array[i].Equals(value))
            {
                expectedIndex = expectedIndex < 0 ? i : expectedIndex;
                expectedLast = i;
            }
        }

        Check.Equal(expectedIndex, Array.IndexOf(array, value, start, length), $"Array.IndexOf<{typeof(T).Name}>({start}, {length}): {what}");
        Check.Equal(length == 0 ? -1 : expectedLast, length == 0 ? -1 : Array.LastIndexOf(array, value, start + length - 1, length), $"Array.LastIndexOf<{typeof(T).Name}>: {what}");
        Array.Reverse(array, start, length);
        for (int i = 0; i < array.Length; i++)
        {
            T expected = i >= start && i < start + length ? original[start + length - 1 - (i - start)] : original[i];
            if (!expected.Equals(array[i]))
            {
                Check.That(false, $"Array.Reverse<{typeof(T).Name}>({start}, {length}) element {i}: {what}");
            }
        }

        Array.Fill(array, value, start, length);
        for (int i = 0; i < array.Length; i++)
        {
            if (!(i >= start && i < start + length ? array[i].Equals(value) : array[i].Equals(original[i])))
            {
                Check.That(false, $"Array.Fill<{typeof(T).Name}>({start}, {length}) element {i}: {what}");
            }
        }

        Array.Clear(array, start, length);
        for (int i = 0; i < array.Length; i++)
        {
            if (!(i >= start && i < start + length ? array[i].Equals(default) : array[i].Equals(original[i])))
            {
                Check.That(false, $"Array.Clear<{typeof(T).Name}>({start}, {length}) element {i}: {what}");
            }
        }
    }

    /// <summary>BitOperations against scalar models.</summary>
    private static void Operations(byte[] bytes, string what)
    {
        for (int i = 0; i + 8 <= bytes.Length && i < 256; i += 8)
        {
            ulong x = BitConverter.ToUInt64(bytes, i);
            uint y = (uint)x;
            int r = bytes[i] % 70 - 3;
            Check.Equal(Enumerable.Range(0, 64).Count(k => (x >> k & 1) != 0), BitOperations.PopCount(x), $"PopCount({x:X}): {what}");
            Check.Equal(x == 0 ? 64 : Enumerable.Range(0, 64).First(k => (x >> (63 - k) & 1) != 0), BitOperations.LeadingZeroCount(x), $"LeadingZeroCount({x:X}): {what}");
            Check.Equal(y == 0 ? 32 : Enumerable.Range(0, 32).First(k => (y >> k & 1) != 0), BitOperations.TrailingZeroCount(y), $"TrailingZeroCount({y:X}): {what}");
            Check.Equal(x == 0 ? 0 : 63 - BitOperations.LeadingZeroCount(x), BitOperations.Log2(x), $"Log2({x:X}): {what}");
            Check.Equal(x << (r & 63) | x >> (64 - (r & 63) & 63), BitOperations.RotateLeft(x, r), $"RotateLeft({x:X}, {r}): {what}");
            Check.Equal(y >> (r & 31) | y << (32 - (r & 31) & 31), BitOperations.RotateRight(y, r), $"RotateRight({y:X}, {r}): {what}");
            Check.Equal(x != 0 && (x & (x - 1)) == 0, BitOperations.IsPow2(x), $"IsPow2({x:X}): {what}");
            uint up = y == 0 ? 0 : y > 0x80000000 ? 0 : (uint)(1L << (32 - BitOperations.LeadingZeroCount(y - 1)));
            Check.Equal(y <= 1 ? (y == 0 ? 0u : 1u) : up, BitOperations.RoundUpToPowerOf2(y), $"RoundUpToPowerOf2({y:X}): {what}");
        }
    }
}
