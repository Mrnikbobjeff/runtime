#nullable disable warnings
using System.Buffers;
using System.Buffers.Binary;
using System.Collections;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// Fuzzes the vectorized span and array helpers over primitive element types against plain loops:
/// MemoryExtensions (IndexOf*, LastIndexOf*, IndexOfAny*, *InRange, Count, Contains*, SequenceEqual,
/// SequenceCompareTo, StartsWith/EndsWith, CommonPrefixLength, Replace, Reverse, Sort, BinarySearch),
/// System.Text.Ascii, BitArray and the vectorized LINQ Sum / Min / Max / Average.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     element type (see <see cref="Run"/>)
///   byte 1     operation
///   byte 2     low 3 bits: misalignment offset; 0x80 compact values (one byte per element, values 0-15
///              plus the type's MinValue / MaxValue, so searches hit and repeat)
///   byte 3     k: number of search values / length of the needle / position parameter
///   rest       elements; the last k are the search values or needle, the others the haystack
/// The fuzz.sh secondaries run with AVX-512 or AVX2 disabled, so all vector widths are covered.
/// </remarks>
public static class SpanOpsTarget
{
    private const int MaxBytes = 4096;

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte type = input.Byte();
        byte op = input.Byte();
        byte flags = input.Byte();
        byte k = input.Byte();
        ReadOnlySpan<byte> payload = input.Rest();
        if (payload.Length > MaxBytes)
        {
            return;
        }

        switch (type % 15)
        {
            case 0: Elements<byte>(payload, op, flags, k); break;
            case 1: Elements<sbyte>(payload, op, flags, k); break;
            case 2: Elements<char>(payload, op, flags, k); break;
            case 3: Elements<short>(payload, op, flags, k); break;
            case 4: Elements<ushort>(payload, op, flags, k); break;
            case 5: Elements<int>(payload, op, flags, k); break;
            case 6: Elements<uint>(payload, op, flags, k); break;
            case 7: Elements<long>(payload, op, flags, k); break;
            case 8: Elements<ulong>(payload, op, flags, k); break;
            case 9: Elements<float>(payload, op, flags, k); break;
            case 10: Elements<double>(payload, op, flags, k); break;
            case 11: Elements<nint>(payload, op, flags, k); break;
            case 12: AsciiOps(payload, op, flags); break;
            case 13: BitArrayOps(payload, op, k); break;
            default: Linq(payload, op, flags); break;
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Element decoding

    private static T[] Decode<T>(ReadOnlySpan<byte> payload, byte flags)
        where T : unmanaged, INumberBase<T>, IMinMaxValue<T>
    {
        if ((flags & 0x80) == 0)
        {
            return MemoryMarshal.Cast<byte, T>(payload.Slice(0, payload.Length / Marshal.SizeOf<T>() * Marshal.SizeOf<T>())).ToArray();
        }

        var values = new T[payload.Length];
        for (int i = 0; i < values.Length; i++)
        {
            byte b = payload[i];
            values[i] = (b & 0x30) switch
            {
                0x30 when typeof(T) == typeof(float) => (T)(object)((b & 1) == 0 ? float.NaN : -0.0f),
                0x30 when typeof(T) == typeof(double) => (T)(object)((b & 1) == 0 ? double.NaN : -0.0),
                0x30 => (b & 1) != 0 ? T.MaxValue : T.MinValue,
                _ => T.CreateTruncating(b & 0x0F),
            };
        }

        return values;
    }

    /// <summary>A copy of <paramref name="values"/> at an offset in a larger array, to vary alignment.</summary>
    private static Span<T> Place<T>(T[] values, int offset)
    {
        var buffer = new T[values.Length + offset + 3];
        values.CopyTo(buffer, offset);
        return buffer.AsSpan(offset, values.Length);
    }

    private static bool Eq<T>(T a, T b) => EqualityComparer<T>.Default.Equals(a, b);

    // ---------------------------------------------------------------------------------------------
    // MemoryExtensions over T

    private static void Elements<T>(ReadOnlySpan<byte> payload, byte op, byte flags, byte k)
        where T : unmanaged, INumberBase<T>, IMinMaxValue<T>, IEquatable<T>, IComparable<T>
    {
        T[] all = Decode<T>(payload, flags);
        int count = Math.Min(k % 9, all.Length);
        T[] haystackArray = all[..^count];
        T[] values = all[^count..];
        int offset = flags & 7;
        ReadOnlySpan<T> hay = Place(haystackArray, offset);
        string what = $"{typeof(T).Name}[{hay.Length}] {Show(haystackArray)} values {Show(values)} (offset {offset})";
        T v0 = count > 0 ? values[0] : default, v1 = count > 1 ? values[1] : v0, v2 = count > 2 ? values[2] : v1;

        switch (op % 34)
        {
            case 0: Same(hay.IndexOf(v0), First(hay, x => Eq(x, v0)), "IndexOf", what); break;
            case 1: Same(hay.LastIndexOf(v0), Last(hay, x => Eq(x, v0)), "LastIndexOf", what); break;
            case 2: Same(hay.IndexOfAny(v0, v1), First(hay, x => Eq(x, v0) || Eq(x, v1)), "IndexOfAny(2)", what); break;
            case 3: Same(hay.IndexOfAny(v0, v1, v2), First(hay, x => Eq(x, v0) || Eq(x, v1) || Eq(x, v2)), "IndexOfAny(3)", what); break;
            case 4: Same(hay.IndexOfAny(values), First(hay, x => values.Any(v => Eq(x, v))), "IndexOfAny(span)", what); break;
            case 5: Same(hay.LastIndexOfAny(values), Last(hay, x => values.Any(v => Eq(x, v))), "LastIndexOfAny(span)", what); break;
            case 6: Same(hay.IndexOfAnyExcept(v0), First(hay, x => !Eq(x, v0)), "IndexOfAnyExcept(1)", what); break;
            case 7: Same(hay.IndexOfAnyExcept(v0, v1, v2), First(hay, x => !Eq(x, v0) && !Eq(x, v1) && !Eq(x, v2)), "IndexOfAnyExcept(3)", what); break;
            case 8: Same(hay.IndexOfAnyExcept(values), First(hay, x => !values.Any(v => Eq(x, v))), "IndexOfAnyExcept(span)", what); break;
            case 9: Same(hay.LastIndexOfAnyExcept(v0, v1), Last(hay, x => !Eq(x, v0) && !Eq(x, v1)), "LastIndexOfAnyExcept(2)", what); break;
            case 10: Same(hay.IndexOfAnyInRange(v0, v1), First(hay, x => x.CompareTo(v0) >= 0 && x.CompareTo(v1) <= 0), "IndexOfAnyInRange", what); break;
            case 11: Same(hay.IndexOfAnyExceptInRange(v0, v1), First(hay, x => !(x.CompareTo(v0) >= 0 && x.CompareTo(v1) <= 0)), "IndexOfAnyExceptInRange", what); break;
            case 12: Same(hay.LastIndexOfAnyInRange(v0, v1), Last(hay, x => x.CompareTo(v0) >= 0 && x.CompareTo(v1) <= 0), "LastIndexOfAnyInRange", what); break;
            case 13: Same(hay.LastIndexOfAnyExceptInRange(v0, v1), Last(hay, x => !(x.CompareTo(v0) >= 0 && x.CompareTo(v1) <= 0)), "LastIndexOfAnyExceptInRange", what); break;
            case 14:
                Same(hay.Contains(v0) ? 1 : 0, First(hay, x => Eq(x, v0)) >= 0 ? 1 : 0, "Contains", what);
                Same(hay.ContainsAny(values) ? 1 : 0, First(hay, x => values.Any(v => Eq(x, v))) >= 0 ? 1 : 0, "ContainsAny(span)", what);
                Same(hay.ContainsAnyExcept(v0, v1) ? 1 : 0, First(hay, x => !Eq(x, v0) && !Eq(x, v1)) >= 0 ? 1 : 0, "ContainsAnyExcept(2)", what);
                break;
            case 15:
                Same(hay.Count(v0), hay.ToArray().Count(x => Eq(x, v0)), "Count(value)", what);
                Same(hay.Count(values.AsSpan()), CountSub(hay, values), "Count(span)", what);
                break;
            case 16: Same(hay.IndexOf(values), FindSub(hay, values, last: false), "IndexOf(span)", what); break;
            case 17: Same(hay.LastIndexOf(values), FindSub(hay, values, last: true), "LastIndexOf(span)", what); break;
            case 18: Compare(hay, values, what); break;
            case 19:
                // Replace in place and into a destination (overlapping when the offset allows).
                T[] expected = hay.ToArray().Select(x => Eq(x, v0) ? v1 : x).ToArray();
                Span<T> inPlace = Place(haystackArray, offset);
                inPlace.Replace(v0, v1);
                Check.That(inPlace.SequenceEqual(expected), $"Replace({Show(v0)}, {Show(v1)}) in place gives {Show(inPlace.ToArray())} for {what}");
                Span<T> destination = Place(new T[hay.Length], (offset + 1) % 8);
                hay.Replace(destination, v0, v1);
                Check.That(destination.SequenceEqual(expected), $"Replace(source, destination, {Show(v0)}, {Show(v1)}) gives {Show(destination.ToArray())} for {what}");
                break;
            case 20:
                Span<T> reversed = Place(haystackArray, offset);
                reversed.Reverse();
                Check.That(reversed.SequenceEqual(haystackArray.Reverse().ToArray()), $"Reverse gives {Show(reversed.ToArray())} for {what}");
                break;
            case 21: Sorting(haystackArray, values, what); break;
            case 22:
                // Overlapping copies must behave like memmove.
                if (hay.Length > 1)
                {
                    int shift = 1 + k % Math.Min(hay.Length - 1, 40);
                    T[] buffer = haystackArray.ToArray();
                    buffer.AsSpan(0, buffer.Length - shift).CopyTo(buffer.AsSpan(shift));
                    T[] expectedCopy = haystackArray[..shift].Concat(haystackArray[..^shift]).ToArray();
                    Check.That(buffer.AsSpan().SequenceEqual(expectedCopy), $"overlapping CopyTo forward by {shift} for {what}");
                    buffer = haystackArray.ToArray();
                    buffer.AsSpan(shift).CopyTo(buffer);
                    expectedCopy = haystackArray[shift..].Concat(haystackArray[^shift..]).ToArray();
                    Check.That(buffer.AsSpan().SequenceEqual(expectedCopy), $"overlapping CopyTo backward by {shift} for {what}");
                }

                break;
            case 23:
                Span<T> filled = Place(haystackArray, offset);
                filled.Fill(v0);
                Same(filled.IndexOfAnyExcept(v0), -1, "Fill then IndexOfAnyExcept", what);
                Same(Array.IndexOf(haystackArray, v0), First(hay, x => Eq(x, v0)), "Array.IndexOf", what);
                Same(Array.LastIndexOf(haystackArray, v0), Last(hay, x => Eq(x, v0)), "Array.LastIndexOf", what);
                break;
            case 26:
                // 4 and 5 values take their own vectorized paths for byte/char/short-sized T.
                T[] four = [v0, v1, v2, count > 3 ? values[3] : v2];
                T[] five = [.. four, count > 4 ? values[4] : v0];
                Same(hay.IndexOfAny(four), First(hay, x => four.Any(v => Eq(x, v))), "IndexOfAny(4 values)", what);
                Same(hay.IndexOfAny(five), First(hay, x => five.Any(v => Eq(x, v))), "IndexOfAny(5 values)", what);
                Same(hay.LastIndexOfAny(five), Last(hay, x => five.Any(v => Eq(x, v))), "LastIndexOfAny(5 values)", what);
                Same(hay.IndexOfAnyExcept(four), First(hay, x => !four.Any(v => Eq(x, v))), "IndexOfAnyExcept(4 values)", what);
                Same(hay.LastIndexOfAnyExcept(five), Last(hay, x => !five.Any(v => Eq(x, v))), "LastIndexOfAnyExcept(5 values)", what);
                break;
            case 27:
                SplitCheck(hay.Split(v0), haystackArray, (a, i) => Eq(a[i], v0) ? 1 : 0, $"Split({Show(v0)})", what);
                // Documented: for char, an empty separator span means "all Unicode whitespace" (like string.Split).
                bool whiteSpace = typeof(T) == typeof(char) && values.Length == 0;
                SplitCheck(hay.SplitAny(values), haystackArray, (a, i) => (whiteSpace ? char.IsWhiteSpace((char)(object)a[i]) : values.Any(v => Eq(a[i], v))) ? 1 : 0, "SplitAny(values)", what);
                if (values.Length > 0)
                {
                    SplitCheck(hay.Split(values.AsSpan()), haystackArray, (a, i) => i + values.Length <= a.Length && MatchAt<T>(a, values, i) ? values.Length : 0, "Split(sequence)", what);
                }

                break;
            case 28:
            {
                int start = First(hay, x => !values.Any(v => Eq(x, v)));
                int end = Last(hay, x => !values.Any(v => Eq(x, v)));
                int expectedStart = start < 0 ? hay.Length : start;
                Check.That(hay.TrimStart(values).Length == hay.Length - expectedStart, $"TrimStart(values) length {hay.TrimStart(values).Length}, expected {hay.Length - expectedStart}, for {what}");
                Check.That(hay.TrimEnd(values).Length == end + 1, $"TrimEnd(values) length {hay.TrimEnd(values).Length}, expected {end + 1}, for {what}");
                Check.That(hay.Trim(values).Length == (start < 0 ? 0 : end - start + 1), $"Trim(values) length {hay.Trim(values).Length} for {what}");
                Check.That(hay.Trim(v0).Length == hay.TrimStart(v0).TrimEnd(v0).Length, $"Trim({Show(v0)}) != TrimStart.TrimEnd for {what}");
                break;
            }

            case 29: ReverseEndianness(haystackArray, offset, what); break;
            case 30:
            {
                // Sub-range Array.Sort / Array.Reverse / Array.Fill leave the rest of the array alone.
                int index = hay.Length == 0 ? 0 : k % hay.Length;
                int length = (k * 7) % (hay.Length - index + 1);
                T[] sorted = haystackArray.ToArray();
                Array.Sort(sorted, index, length);
                T[] expectedRange = [.. haystackArray[..index], .. haystackArray[index..(index + length)].OrderBy(x => x, Comparer<T>.Default), .. haystackArray[(index + length)..]];
                Check.That(sorted.AsSpan().SequenceEqual(expectedRange), $"Array.Sort(index {index}, length {length}) gives {Show(sorted)} for {what}");
                T[] reversedRange = haystackArray.ToArray();
                Array.Reverse(reversedRange, index, length);
                expectedRange = [.. haystackArray[..index], .. haystackArray[index..(index + length)].Reverse(), .. haystackArray[(index + length)..]];
                Check.That(reversedRange.AsSpan().SequenceEqual(expectedRange), $"Array.Reverse(index {index}, length {length}) for {what}");
                T[] filledRange = haystackArray.ToArray();
                Array.Fill(filledRange, v0, index, length);
                expectedRange = [.. haystackArray[..index], .. Enumerable.Repeat(v0, length), .. haystackArray[(index + length)..]];
                Check.That(filledRange.AsSpan().SequenceEqual(expectedRange), $"Array.Fill(index {index}, length {length}) for {what}");
                int inRange = First<T>(haystackArray.AsSpan(index, length), x => Eq(x, v0));
                Same(Array.IndexOf(haystackArray, v0, index, length), inRange >= 0 ? inRange + index : -1, "Array.IndexOf(value, index, count)", what);
                break;
            }

            case 31:
                Same(hay.ContainsAnyInRange(v0, v1) ? 1 : 0, First(hay, x => x.CompareTo(v0) >= 0 && x.CompareTo(v1) <= 0) >= 0 ? 1 : 0, "ContainsAnyInRange", what);
                Same(hay.ContainsAnyExceptInRange(v0, v1) ? 1 : 0, First(hay, x => !(x.CompareTo(v0) >= 0 && x.CompareTo(v1) <= 0)) >= 0 ? 1 : 0, "ContainsAnyExceptInRange", what);
                Same(hay.LastIndexOfAny(v0, v1, v2), Last(hay, x => Eq(x, v0) || Eq(x, v1) || Eq(x, v2)), "LastIndexOfAny(3)", what);
                Same(hay.LastIndexOfAnyExcept(v0), Last(hay, x => !Eq(x, v0)), "LastIndexOfAnyExcept(1)", what);
                break;
            default:
                if (typeof(T) != typeof(byte) && typeof(T) != typeof(char))
                {
                    Same(hay.IndexOfAnyExcept(values), First(hay, x => !values.Any(v => Eq(x, v))), "IndexOfAnyExcept(span)", what);
                    break;
                }

                Same(hay.IndexOfAny(SearchValuesFor(values)), First(hay, x => values.Any(v => Eq(x, v))), "IndexOfAny(SearchValues)", what);
                Same(hay.LastIndexOfAnyExcept(SearchValuesFor(values)), Last(hay, x => !values.Any(v => Eq(x, v))), "LastIndexOfAnyExcept(SearchValues)", what);
                break;
        }
    }

    /// <summary>
    /// Compares a span split enumerator with a reference split: <paramref name="separatorAt"/> returns
    /// the separator length at a position (0 if none). Like string.Split without options, every
    /// separator ends a range, so n separators give n + 1 ranges (possibly empty).
    /// </summary>
    private static void SplitCheck<T>(MemoryExtensions.SpanSplitEnumerator<T> actual, T[] source, Func<T[], int, int> separatorAt, string name, string what)
        where T : IEquatable<T>
    {
        var expected = new List<Range>();
        int start = 0;
        for (int i = 0; i < source.Length;)
        {
            int length = separatorAt(source, i);
            if (length > 0)
            {
                expected.Add(start..i);
                i += length;
                start = i;
            }
            else
            {
                i++;
            }
        }

        expected.Add(start..source.Length);
        var ranges = new List<Range>();
        foreach (Range r in actual)
        {
            ranges.Add(r);
            if (ranges.Count > source.Length + 2)
            {
                break;
            }
        }

        Check.That(ranges.Select(r => r.GetOffsetAndLength(source.Length)).SequenceEqual(expected.Select(r => r.GetOffsetAndLength(source.Length))),
            $"{name} gives [{string.Join(", ", ranges.Take(12))}], expected [{string.Join(", ", expected.Take(12))}] for {what}");
    }

    private static void ReverseEndianness<T>(T[] values, int offset, string what)
    {
        switch (values)
        {
            case short[] a: CheckReverse(a, offset, BinaryPrimitives.ReverseEndianness, BinaryPrimitives.ReverseEndianness, what); break;
            case ushort[] a: CheckReverse(a, offset, BinaryPrimitives.ReverseEndianness, BinaryPrimitives.ReverseEndianness, what); break;
            case int[] a: CheckReverse(a, offset, BinaryPrimitives.ReverseEndianness, BinaryPrimitives.ReverseEndianness, what); break;
            case uint[] a: CheckReverse(a, offset, BinaryPrimitives.ReverseEndianness, BinaryPrimitives.ReverseEndianness, what); break;
            case long[] a: CheckReverse(a, offset, BinaryPrimitives.ReverseEndianness, BinaryPrimitives.ReverseEndianness, what); break;
            case ulong[] a: CheckReverse(a, offset, BinaryPrimitives.ReverseEndianness, BinaryPrimitives.ReverseEndianness, what); break;
            case nint[] a: CheckReverse(a, offset, BinaryPrimitives.ReverseEndianness, BinaryPrimitives.ReverseEndianness, what); break;
        }
    }

    private delegate void SpanReverse<T>(ReadOnlySpan<T> source, Span<T> destination);

    private static void CheckReverse<T>(T[] values, int offset, SpanReverse<T> spans, Func<T, T> scalar, string what)
    {
        T[] expected = values.Select(scalar).ToArray();
        Span<T> destination = Place(new T[values.Length], (offset + 3) % 8);
        spans(Place(values, offset), destination);
        Check.That(destination.SequenceEqual(expected), $"BinaryPrimitives.ReverseEndianness(span, span) differs for {what}");
        Span<T> inPlace = Place(values, offset);
        spans(inPlace, inPlace);
        Check.That(inPlace.SequenceEqual(expected), $"BinaryPrimitives.ReverseEndianness in place differs for {what}");
    }

    private static SearchValues<T> SearchValuesFor<T>(T[] values)
        where T : IEquatable<T>
    {
        // SearchValues exists for byte and char only.
        if (typeof(T) == typeof(byte))
        {
            return (SearchValues<T>)(object)SearchValues.Create((byte[])(object)values);
        }

        if (typeof(T) == typeof(char))
        {
            return (SearchValues<T>)(object)SearchValues.Create(new string((char[])(object)values));
        }

        throw new NotSupportedException();
    }

    private static void Compare<T>(ReadOnlySpan<T> hay, T[] values, string what)
        where T : unmanaged, IEquatable<T>, IComparable<T>
    {
        // Compare the haystack with a copy that differs (maybe) in one place.
        T[] other = hay.ToArray();
        if (other.Length > 0 && values.Length > 0)
        {
            other[values.Length * 7919 % other.Length] = values[0];
        }

        int diff = First<T>(hay, (x, i) => !Eq(x, other[i]));
        Same(hay.SequenceEqual(other) ? 1 : 0, diff < 0 ? 1 : 0, "SequenceEqual", what);
        int expectedCompare = diff < 0 ? 0 : hay[diff].CompareTo(other[diff]);
        Same(Math.Sign(hay.SequenceCompareTo(other)), Math.Sign(expectedCompare), "SequenceCompareTo", what);
        Same(hay.CommonPrefixLength(other), diff < 0 ? hay.Length : diff, "CommonPrefixLength", what);
        Same(hay.StartsWith(values) ? 1 : 0, hay.Length >= values.Length && hay[..values.Length].ToArray().Zip(values).All(p => Eq(p.First, p.Second)) ? 1 : 0, "StartsWith", what);
        Same(hay.EndsWith(values) ? 1 : 0, hay.Length >= values.Length && hay[^values.Length..].ToArray().Zip(values).All(p => Eq(p.First, p.Second)) ? 1 : 0, "EndsWith", what);
        Same(hay.SequenceEqual(other, EqualityComparer<T>.Default) ? 1 : 0, diff < 0 ? 1 : 0, "SequenceEqual(comparer)", what);
    }

    private static void Sorting<T>(T[] items, T[] values, string what)
        where T : unmanaged, IEquatable<T>, IComparable<T>
    {
        T[] expected = items.OrderBy(x => x, Comparer<T>.Default).ToArray();
        T[] sorted = items.ToArray();
        sorted.AsSpan().Sort();
        Check.That(sorted.AsSpan().SequenceEqual(expected), $"Span.Sort gives {Show(sorted)} for {what}");

        // Sort(keys, items): keys end up sorted and every (key, item) pair survives.
        int[] payload = Enumerable.Range(0, items.Length).ToArray();
        T[] keys = items.ToArray();
        keys.AsSpan().Sort(payload.AsSpan());
        Check.That(keys.AsSpan().SequenceEqual(expected) && payload.Order().SequenceEqual(Enumerable.Range(0, items.Length)) && payload.Select(i => items[i]).Zip(keys).All(p => Eq(p.First, p.Second)),
            $"Span.Sort(keys, items) scrambles pairs for {what}");

        foreach (T value in values.Append(items.Length > 0 ? items[0] : default))
        {
            int index = sorted.AsSpan().BinarySearch(value);
            if (index >= 0)
            {
                Check.That(Eq(sorted[index], value) || sorted[index].CompareTo(value) == 0, $"BinarySearch({Show(value)}) = {index} points at {Show(sorted[index])} for {what}");
            }
            else
            {
                int insert = ~index;
                Check.That(insert <= sorted.Length && (insert == 0 || sorted[insert - 1].CompareTo(value) < 0) && (insert == sorted.Length || sorted[insert].CompareTo(value) > 0),
                    $"BinarySearch({Show(value)}) = ~{insert}, not the insertion point, for {what}");
            }
        }
    }

    private static int First<T>(ReadOnlySpan<T> span, Func<T, bool> match)
    {
        for (int i = 0; i < span.Length; i++)
        {
            if (match(span[i]))
            {
                return i;
            }
        }

        return -1;
    }

    private static int First<T>(ReadOnlySpan<T> span, Func<T, int, bool> match)
    {
        for (int i = 0; i < span.Length; i++)
        {
            if (match(span[i], i))
            {
                return i;
            }
        }

        return -1;
    }

    private static int Last<T>(ReadOnlySpan<T> span, Func<T, bool> match)
    {
        for (int i = span.Length - 1; i >= 0; i--)
        {
            if (match(span[i]))
            {
                return i;
            }
        }

        return -1;
    }

    private static bool MatchAt<T>(ReadOnlySpan<T> hay, T[] needle, int at)
    {
        for (int j = 0; j < needle.Length; j++)
        {
            if (!Eq(hay[at + j], needle[j]))
            {
                return false;
            }
        }

        return true;
    }

    private static int FindSub<T>(ReadOnlySpan<T> hay, T[] needle, bool last)
    {
        if (needle.Length == 0)
        {
            return last ? hay.Length : 0;
        }

        int found = -1;
        for (int i = 0; i + needle.Length <= hay.Length; i++)
        {
            if (MatchAt(hay, needle, i))
            {
                found = i;
                if (!last)
                {
                    break;
                }
            }
        }

        return found;
    }

    private static int CountSub<T>(ReadOnlySpan<T> hay, T[] needle)
    {
        if (needle.Length == 0)
        {
            return 0;
        }

        int n = 0;
        for (int i = 0; i + needle.Length <= hay.Length;)
        {
            if (MatchAt(hay, needle, i))
            {
                n++;
                i += needle.Length; // non-overlapping occurrences
            }
            else
            {
                i++;
            }
        }

        return n;
    }

    // ---------------------------------------------------------------------------------------------
    // System.Text.Ascii

    private static void AsciiOps(ReadOnlySpan<byte> payload, byte op, byte flags)
    {
        // The APIs see offset spans (to vary alignment); the references work on the arrays.
        byte[] byteArray = payload.ToArray();
        char[] charArray = MemoryMarshal.Cast<byte, char>(payload.Slice(0, payload.Length & ~1)).ToArray();
        Span<byte> bytes = Place(byteArray, flags & 7);
        Span<char> chars = Place(charArray, (flags >> 3) & 7);
        string what = $"Ascii over bytes {Check.Show(byteArray)} / chars {Check.Show(new string(charArray))}";
        int firstNonAsciiByte = Array.FindIndex(byteArray, b => b >= 0x80);
        int firstNonAsciiChar = Array.FindIndex(charArray, c => c >= 0x80);

        switch (op % 6)
        {
            case 0:
                Same(Ascii.IsValid(bytes) ? 1 : 0, firstNonAsciiByte < 0 ? 1 : 0, "Ascii.IsValid(bytes)", what);
                Same(Ascii.IsValid(chars) ? 1 : 0, firstNonAsciiChar < 0 ? 1 : 0, "Ascii.IsValid(chars)", what);
                break;
            case 1:
            {
                // UTF-16 -> ASCII narrowing stops at the first non-ASCII char.
                byte[] destination = new byte[charArray.Length];
                OperationStatus status = Ascii.FromUtf16(chars, destination, out int written);
                int expected = firstNonAsciiChar < 0 ? charArray.Length : firstNonAsciiChar;
                Check.That(status == (firstNonAsciiChar < 0 ? OperationStatus.Done : OperationStatus.InvalidData) && written == expected &&
                    destination.AsSpan(0, written).SequenceEqual(charArray.Take(written).Select(c => (byte)c).ToArray()),
                    $"Ascii.FromUtf16 {status} written {written}, expected {expected}, for {what}");
                break;
            }

            case 2:
            {
                // ASCII -> UTF-16 widening stops at the first non-ASCII byte.
                char[] destination = new char[byteArray.Length];
                OperationStatus status = Ascii.ToUtf16(bytes, destination, out int written);
                int expected = firstNonAsciiByte < 0 ? byteArray.Length : firstNonAsciiByte;
                Check.That(status == (firstNonAsciiByte < 0 ? OperationStatus.Done : OperationStatus.InvalidData) && written == expected &&
                    destination.AsSpan(0, written).SequenceEqual(byteArray.Take(written).Select(b => (char)b).ToArray()),
                    $"Ascii.ToUtf16 {status} written {written}, expected {expected}, for {what}");
                break;
            }

            case 3:
            {
                byte[] upper = new byte[byteArray.Length];
                OperationStatus status = Ascii.ToUpper(bytes, upper, out int written);
                int expected = firstNonAsciiByte < 0 ? byteArray.Length : firstNonAsciiByte;
                Check.That(status == (firstNonAsciiByte < 0 ? OperationStatus.Done : OperationStatus.InvalidData) && written == expected &&
                    upper.AsSpan(0, written).SequenceEqual(byteArray.Take(written).Select(b => b is >= (byte)'a' and <= (byte)'z' ? (byte)(b - 32) : b).ToArray()),
                    $"Ascii.ToUpper(bytes) {status} written {written} for {what}");
                Span<char> lower = Place(charArray, (flags >> 3) & 7);
                status = Ascii.ToLowerInPlace(lower, out written);
                expected = firstNonAsciiChar < 0 ? charArray.Length : firstNonAsciiChar;
                Check.That(status == (firstNonAsciiChar < 0 ? OperationStatus.Done : OperationStatus.InvalidData) && written == expected &&
                    lower[..written].SequenceEqual(charArray.Take(written).Select(c => c is >= 'A' and <= 'Z' ? (char)(c + 32) : c).ToArray()),
                    $"Ascii.ToLowerInPlace(chars) {status} written {written} for {what}");
                break;
            }

            case 4:
            {
                // EqualsIgnoreCase against a case-flipped copy (differs only in ASCII letters' case).
                byte[] flipped = byteArray.Select(b => char.IsAsciiLetter((char)b) ? (byte)(b ^ 0x20) : b).ToArray();
                bool expected = firstNonAsciiByte < 0;
                Same(Ascii.EqualsIgnoreCase(bytes, flipped) ? 1 : 0, expected ? 1 : 0, "Ascii.EqualsIgnoreCase(bytes, flipped)", what);
                Same(Ascii.Equals(bytes, bytes) ? 1 : 0, expected ? 1 : 0, "Ascii.Equals(bytes, bytes)", what);
                char[] flippedChars = charArray.Select(c => char.IsAsciiLetter(c) ? (char)(c ^ 0x20) : c).ToArray();
                Same(Ascii.EqualsIgnoreCase(chars, flippedChars) ? 1 : 0, firstNonAsciiChar < 0 ? 1 : 0, "Ascii.EqualsIgnoreCase(chars, flipped)", what);
                break;
            }

            default:
            {
                Range trimmed = Ascii.Trim(bytes);
                int start = Array.FindIndex(byteArray, b => !IsAsciiWhite(b));
                int end = Array.FindLastIndex(byteArray, b => !IsAsciiWhite(b));
                (int expectedStart, int expectedLength) = start < 0 ? (0, 0) : (start, end - start + 1);
                (int offset, int length) = trimmed.GetOffsetAndLength(bytes.Length);
                Check.That(length == expectedLength && (length == 0 || offset == expectedStart), $"Ascii.Trim gives {offset}+{length}, expected {expectedStart}+{expectedLength}, for {what}");
                break;
            }
        }
    }

    private static bool IsAsciiWhite(byte b) => b is (byte)' ' or (byte)'\t' or (byte)'\n' or (byte)'\v' or (byte)'\f' or (byte)'\r';

    // ---------------------------------------------------------------------------------------------
    // BitArray (System.Collections), whose bulk operations are vectorized

    private static void BitArrayOps(ReadOnlySpan<byte> payload, byte op, byte k)
    {
        int half = payload.Length / 2 / 4 * 4;
        int[] a = MemoryMarshal.Cast<byte, int>(payload[..half]).ToArray();
        int[] b = MemoryMarshal.Cast<byte, int>(payload[half..(2 * half)]).ToArray();
        int length = a.Length * 32 - k % 32; // not a multiple of 32
        if (length < 0)
        {
            return;
        }

        bool[] bitsA = Bits(a, length), bitsB = Bits(b, length);
        var x = new BitArray(a) { Length = length };
        var y = new BitArray(b) { Length = length };
        string what = $"BitArray of {length} bits";
        Check.That(Read(x).SequenceEqual(bitsA), $"new BitArray(int[]) bits differ for {what}");
        Check.That(Read(new BitArray(bitsA)).SequenceEqual(bitsA), $"new BitArray(bool[]) bits differ for {what}");
        bool[] expected;
        switch (op % 7)
        {
            case 0: x.And(y); expected = bitsA.Zip(bitsB, (p, q) => p & q).ToArray(); break;
            case 1: x.Or(y); expected = bitsA.Zip(bitsB, (p, q) => p | q).ToArray(); break;
            case 2: x.Xor(y); expected = bitsA.Zip(bitsB, (p, q) => p ^ q).ToArray(); break;
            case 3: x.Not(); expected = bitsA.Select(p => !p).ToArray(); break;
            case 4:
            {
                int shift = k % (length + 2);
                x.LeftShift(shift);
                expected = Enumerable.Range(0, length).Select(i => i >= shift && bitsA[i - shift]).ToArray();
                break;
            }

            case 5:
            {
                int shift = k % (length + 2);
                x.RightShift(shift);
                expected = Enumerable.Range(0, length).Select(i => i + shift < length && bitsA[i + shift]).ToArray();
                break;
            }

            default:
                Same(x.HasAllSet() ? 1 : 0, bitsA.All(p => p) ? 1 : 0, "BitArray.HasAllSet", what);
                Same(x.HasAnySet() ? 1 : 0, bitsA.Any(p => p) ? 1 : 0, "BitArray.HasAnySet", what);
                expected = bitsA;
                break;
        }

        bool[] actual = Read(x);
        Check.That(actual.SequenceEqual(expected), $"BitArray op {op % 7} (k {k}) gives wrong bits at {Enumerable.Range(0, actual.Length).FirstOrDefault(i => actual[i] != expected[i], -1)} for {what}");
        var copy = new int[(length + 31) / 32];
        x.CopyTo(copy, 0);
        Check.That(Bits(copy, length).SequenceEqual(expected), $"BitArray.CopyTo(int[]) after op {op % 7} differs for {what}");
    }

    private static bool[] Bits(int[] words, int length) => Enumerable.Range(0, length).Select(i => (words[i / 32] >> (i % 32) & 1) != 0).ToArray();

    private static bool[] Read(BitArray bits)
    {
        var result = new bool[bits.Length];
        bits.CopyTo(result, 0);
        for (int i = 0; i < bits.Length; i++)
        {
            Check.That(bits[i] == result[i], $"BitArray indexer and CopyTo(bool[]) disagree at {i}");
        }

        return result;
    }

    // ---------------------------------------------------------------------------------------------
    // Vectorized LINQ aggregates over integer arrays

    private static void Linq(ReadOnlySpan<byte> payload, byte op, byte flags)
    {
        switch (op % 4)
        {
            case 0: LinqOf<int>(Decode<int>(payload, flags)); break;
            case 1: LinqOf<long>(Decode<long>(payload, flags)); break;
            case 2: LinqOf<short>(Decode<short>(payload, flags)); break;
            default: LinqOf<uint>(Decode<uint>(payload, flags)); break;
        }
    }

    private static void LinqOf<T>(T[] values)
        where T : unmanaged, IBinaryInteger<T>, IMinMaxValue<T>
    {
        string what = $"{typeof(T).Name}[{values.Length}] {Show(values)}";
        if (values.Length == 0)
        {
            Check.That(Throws<InvalidOperationException>(() => values.Min()) && Throws<InvalidOperationException>(() => values.Max()), $"Min/Max of an empty array didn't throw InvalidOperationException");
            return;
        }

        T min = values[0], max = values[0];
        Int128 sum = 0;
        foreach (T v in values)
        {
            min = T.Min(min, v);
            max = T.Max(max, v);
            sum += Int128.CreateTruncating(v);
        }

        Same(values.Min(), min, "Enumerable.Min", what);
        Same(values.Max(), max, "Enumerable.Max", what);
        if (typeof(T) == typeof(int) || typeof(T) == typeof(long))
        {
            // Enumerable.Sum accumulates with checked arithmetic, so it throws as soon as a running
            // sum (left to right) leaves the range, even if the total would fit.
            bool overflows = false;
            Int128 running = 0;
            foreach (T v in values)
            {
                running += Int128.CreateTruncating(v);
                overflows |= running < Int128.CreateTruncating(T.MinValue) || running > Int128.CreateTruncating(T.MaxValue);
            }

            T actual = default;
            bool threw = Throws<OverflowException>(() => actual = typeof(T) == typeof(int) ? (T)(object)((int[])(object)values).Sum() : (T)(object)((long[])(object)values).Sum());

            // Known (LINQ-SUM-1): with at least 4 vectors of input, Sum tracks overflow per SIMD lane,
            // so whether it throws depends on the vector width and length rather than on the total
            // or the running sum. When it returns, the result must still be the exact total.
            if (!s_reportKnownIssues && Vector.IsHardwareAccelerated && values.Length >= Vector<T>.Count * 4)
            {
                Check.That(threw || Int128.CreateTruncating(actual) == sum, $"Enumerable.Sum {actual}, exact sum {sum} for {what}");
                overflows = threw;
            }

            Check.That(threw == overflows && (threw || Int128.CreateTruncating(actual) == sum), $"Enumerable.Sum {(threw ? "threw OverflowException" : actual.ToString())}, exact sum {sum} for {what}");
        }

        if (typeof(T) == typeof(int))
        {
            double average = ((int[])(object)values).Average();
            Check.That(average == (double)(long)sum / values.Length,
                $"Enumerable.Average {average:R}, expected {(double)sum / values.Length:R} for {what}");
        }
    }

    // ---------------------------------------------------------------------------------------------

    private static bool Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (TException)
        {
            return true;
        }
    }

    private static void Same<T>(T actual, T expected, string name, string what) =>
        Check.That(Eq(actual, expected), $"{name} = {Show(actual)}, expected {Show(expected)}, for {what}");

    private static string Show<T>(T value) => value switch
    {
        float f => f.ToString("R"),
        double d => d.ToString("R"),
        char c => $"'\\u{(int)c:X4}'",
        _ => value?.ToString() ?? "null",
    };

    private static string Show<T>(T[] values) =>
        "[" + string.Join(", ", values.Take(24).Select(v => Show(v))) + (values.Length > 24 ? $", ... ({values.Length})]" : "]");
}
