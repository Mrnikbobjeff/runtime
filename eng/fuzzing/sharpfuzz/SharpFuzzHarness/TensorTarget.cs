#nullable disable warnings
#pragma warning disable SYSLIB5001 // Tensor types are experimental
using System.Buffers;
using System.Numerics;
using System.Numerics.Tensors;

namespace SharpFuzzHarness;

/// <summary>
/// Fuzzes System.Numerics.Tensors TensorSpan&lt;T&gt; / Tensor&lt;T&gt; shapes: construction from lengths and
/// strides, element addressing, slicing, filling, spans and reshaping, against a direct model of
/// strided addressing (element [i0, i1, ...] lives at start + i0 * stride0 + i1 * stride1 + ...).
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     rank - 1 (low 2 bits); bits 2-3 constructor; 0x10 explicit strides
///   byte 1     array length; byte 2 start
///   per dim    length byte, stride byte (small values, or special large / negative ones)
///   rest       slice ranges, span request, reshape / unsqueeze / reverse parameters
/// Checks: an accepted shape never addresses memory outside the array (the property everything
/// else relies on); Lengths / Strides / FlattenedLength are as given; enumeration, FlattenTo and the
/// indexers see the modeled elements; Slice gives the modeled sub-tensor; Fill writes exactly the
/// addressed elements; TryGetSpan only returns memory that is the requested elements; Reshape,
/// Squeeze, Unsqueeze, Reverse, ReverseDimension and Sum agree with the flattened elements.
/// </remarks>
public static class TensorTarget
{
    private const int MaxElements = 4096;

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        int rank = 1 + (mode & 3);
        int ctor = mode >> 2 & 3;
        bool withStrides = (mode & 0x10) != 0;
        int arrayLength = input.Byte();
        int start = input.Byte() % (arrayLength + 2);
        var lengths = new nint[rank];
        var strides = new nint[rank];
        for (int k = 0; k < rank; k++)
        {
            lengths[k] = Value(input.Byte());
            strides[k] = Value(input.Byte());
        }

        int[] array = Enumerable.Range(1000, arrayLength).ToArray();
        string what = $"ctor {ctor}, array[{arrayLength}], start {start}, lengths [{string.Join(", ", lengths)}], strides {(withStrides ? $"[{string.Join(", ", strides)}]" : "default")}";
        ReadOnlySpan<nint> givenStrides = withStrides ? strides : default;

        TensorSpan<int> ts;
        int baseOffset = ctor == 0 ? 0 : start;
        try
        {
            ts = ctor switch
            {
                0 => new TensorSpan<int>(array, lengths, givenStrides),
                1 => new TensorSpan<int>(array, start, lengths, givenStrides),
                2 => new TensorSpan<int>(array.AsSpan(start), lengths, givenStrides),
                _ => Tensor.Create(array, start, lengths, givenStrides).AsTensorSpan(),
            };
        }
        catch (Exception e) when (e is ArgumentException or OverflowException)
        {
            return;
        }

        Check.Equal(rank, ts.Rank, $"Rank for {what}");
        Check.That(ts.Lengths.SequenceEqual(lengths), $"Lengths [{string.Join(", ", ts.Lengths.ToArray())}] for {what}");
        if (withStrides)
        {
            Check.That(ts.Strides.SequenceEqual(strides), $"Strides [{string.Join(", ", ts.Strides.ToArray())}] for {what}");
        }

        nint[] effectiveStrides = ts.Strides.ToArray();
        what += $" (strides [{string.Join(", ", effectiveStrides)}])";
        BigInteger flattened = lengths.Aggregate(BigInteger.One, (p, l) => p * l);
        Check.Equal(flattened, (BigInteger)ts.FlattenedLength, $"FlattenedLength for {what}");

        // Memory safety: every addressable element must lie inside the array.
        if (flattened > 0)
        {
            BigInteger maxOffset = baseOffset + lengths.Zip(effectiveStrides).Aggregate(BigInteger.Zero, (s, p) => s + (BigInteger)(p.First - 1) * p.Second);
            Check.That(maxOffset < arrayLength, $"shape addresses element {maxOffset} of a {arrayLength}-element array: {what}");
        }

        if (flattened > MaxElements)
        {
            _ = ts.ToString();
            return;
        }

        int[] offsets = Offsets(lengths, effectiveStrides, baseOffset);
        int[] expected = offsets.Select(o => array[o]).ToArray();
        Elements(ts, expected, what);
        if (lengths.Any(l => l > MaxElements))
        {
            return; // an empty tensor with a huge dimension
        }

        // The indexers at the last element and one past the end of each dimension.
        if (offsets.Length > 0)
        {
            nint[] last = lengths.Select(l => l - 1).ToArray();
            Check.Equal(expected[^1], ts[last], $"indexer at the last element for {what}");
            for (int k = 0; k < rank; k++)
            {
                nint[] outside = (nint[])last.Clone();
                outside[k] = lengths[k];
                bool threw = false;
                try
                {
                    _ = ts[outside];
                }
                catch (Exception e) when (e is IndexOutOfRangeException or ArgumentOutOfRangeException)
                {
                    threw = true;
                }

                Check.That(threw, $"indexer [{string.Join(", ", outside)}] past dimension {k} didn't throw for {what}");
            }
        }

        _ = ts.ToString();
        Slice(ts, ref input, lengths, offsets, array, what);
        FillOnly(ctor, arrayLength, start, lengths, givenStrides, offsets, what);
        GetSpan(ts, ref input, lengths, offsets, array, what);
        Reshaping(ts, ref input, lengths, expected, what);
    }

    private static nint Value(byte b) => b switch
    {
        < 0xE0 => b % 8,
        0xE0 => -1,
        0xE1 => nint.MaxValue,
        0xE2 => (nint)1 << 31,
        0xE3 => (nint)1 << 32,
        0xE4 => (nint)1 << 62,
        0xE5 => ((nint)1 << 62) + 1,
        0xE6 => nint.MinValue,
        0xE7 => int.MaxValue,
        0xE8 => (nint)3 << 61,
        0xE9 => (nint)1 << 33,
        0xEA => nint.MaxValue / 2 + 1,
        0xEB => nint.MaxValue / 3 + 1,
        _ => 8 + (b - 0xEC) * 5,
    };

    /// <summary>Offsets of the elements in row-major order.</summary>
    private static int[] Offsets(nint[] lengths, nint[] strides, int baseOffset)
    {
        var result = new List<int>();
        var index = new nint[lengths.Length];
        if (lengths.Any(l => l == 0))
        {
            return [];
        }

        while (true)
        {
            nint offset = baseOffset;
            for (int k = 0; k < lengths.Length; k++)
            {
                offset += index[k] * strides[k];
            }

            result.Add((int)offset);
            int d = lengths.Length - 1;
            while (d >= 0 && ++index[d] == lengths[d])
            {
                index[d--] = 0;
            }

            if (d < 0)
            {
                return result.ToArray();
            }
        }
    }

    private static void Elements(TensorSpan<int> ts, int[] expected, string what)
    {
        var seen = new List<int>();
        foreach (int v in ts)
        {
            seen.Add(v);
            Check.That(seen.Count <= expected.Length, $"enumeration yields more than {expected.Length} elements for {what}");
        }

        Check.SequenceEqual<int>(expected, seen.ToArray(), $"enumerated elements for {what}");
        int[] flat = new int[expected.Length];
        ts.FlattenTo(flat);
        Check.SequenceEqual<int>(expected, flat, $"FlattenTo for {what}");
        if (expected.Length > 0)
        {
            Check.That(!ts.TryFlattenTo(new int[expected.Length - 1]), $"TryFlattenTo into a short buffer succeeded for {what}");
        }

        if (expected.Length == 0)
        {
            return; // a dense tensor with the same (possibly huge) lengths may not be representable
        }

        int[] dense = new int[expected.Length];
        ts.CopyTo(new TensorSpan<int>(dense, ts.Lengths));
        Check.SequenceEqual<int>(expected, dense, $"CopyTo a dense tensor for {what}");
        Check.That(ts.SequenceEqual(new ReadOnlyTensorSpan<int>(dense, ts.Lengths)), $"SequenceEqual with a dense copy for {what}");
    }

    private static void Slice(TensorSpan<int> ts, ref FuzzInput input, nint[] lengths, int[] offsets, int[] array, string what)
    {
        int rank = lengths.Length;
        var ranges = new NRange[rank];
        var starts = new nint[rank];
        var newLengths = new nint[rank];
        bool valid = true;
        for (int k = 0; k < rank; k++)
        {
            byte a = input.Byte(), b = input.Byte();
            var from = new NIndex(a % (lengths[k] + 3), (a & 0x80) != 0);
            var to = new NIndex(b % (lengths[k] + 3), (b & 0x80) != 0);
            ranges[k] = new NRange(from, to);
            nint s = from.IsFromEnd ? lengths[k] - from.Value : from.Value;
            nint e = to.IsFromEnd ? lengths[k] - to.Value : to.Value;
            valid &= 0 <= s && s <= e && e <= lengths[k];
            starts[k] = s;
            newLengths[k] = e - s;
        }

        string sliceWhat = $"Slice({string.Join(", ", ranges)}) of {what}";
        TensorSpan<int> slice;
        try
        {
            slice = ts.Slice(ranges);
        }
        catch (Exception e) when (e is ArgumentOutOfRangeException or IndexOutOfRangeException or ArgumentException)
        {
            Check.That(!valid, $"{e.GetType().Name} for a valid range: {sliceWhat}");
            return;
        }

        Check.That(valid, $"no exception for an invalid range: {sliceWhat}");
        Check.That(slice.Lengths.SequenceEqual(newLengths), $"slice Lengths [{string.Join(", ", slice.Lengths.ToArray())}], expected [{string.Join(", ", newLengths)}]: {sliceWhat}");

        // Slice element [j] is element [starts + j] of the original.
        int[] expected = SubOffsets(lengths, starts, newLengths).Select(i => array[offsets[i]]).ToArray();
        Elements(slice, expected, sliceWhat);
    }

    /// <summary>Row-major positions (in the original tensor) of the elements of a sub-box.</summary>
    private static IEnumerable<int> SubOffsets(nint[] lengths, nint[] starts, nint[] subLengths)
    {
        if (subLengths.Any(l => l == 0))
        {
            yield break;
        }

        var index = new nint[lengths.Length];
        while (true)
        {
            nint flat = 0;
            for (int k = 0; k < lengths.Length; k++)
            {
                flat = flat * lengths[k] + starts[k] + index[k];
            }

            yield return (int)flat;
            int d = lengths.Length - 1;
            while (d >= 0 && ++index[d] == subLengths[d])
            {
                index[d--] = 0;
            }

            if (d < 0)
            {
                yield break;
            }
        }
    }

    /// <summary>Fill writes exactly the addressed elements.</summary>
    private static void FillOnly(int ctor, int arrayLength, int start, nint[] lengths, ReadOnlySpan<nint> strides, int[] offsets, string what)
    {
        int[] copy = Enumerable.Range(1000, arrayLength).ToArray();
        TensorSpan<int> ts = ctor switch
        {
            0 => new TensorSpan<int>(copy, lengths, strides),
            1 => new TensorSpan<int>(copy, start, lengths, strides),
            2 => new TensorSpan<int>(copy.AsSpan(start), lengths, strides),
            _ => Tensor.Create(copy, start, lengths, strides).AsTensorSpan(),
        };
        ts.Fill(-1);
        if (ctor == 3 && offsets.Length > 0 && !copy.Contains(-1))
        {
            return; // Tensor.Create copied the array
        }

        var addressed = new HashSet<int>(offsets);
        for (int i = 0; i < copy.Length; i++)
        {
            Check.That((copy[i] == -1) == addressed.Contains(i), $"after Fill, array[{i}] = {copy[i]} (addressed: {addressed.Contains(i)}) for {what}");
        }

        ts.Clear();
        Check.That(offsets.All(o => copy[o] == 0), $"Clear left elements set for {what}");
    }

    private static void GetSpan(TensorSpan<int> ts, ref FuzzInput input, nint[] lengths, int[] offsets, int[] array, string what)
    {
        if (offsets.Length == 0)
        {
            return;
        }

        int first = input.Byte() % offsets.Length;
        int length = input.Byte() % (offsets.Length + 2);
        var startIndex = new nint[lengths.Length];
        for (int k = lengths.Length - 1, f = first; k >= 0; k--)
        {
            startIndex[k] = f % lengths[k];
            f = (int)(f / lengths[k]);
        }

        string spanWhat = $"TryGetSpan([{string.Join(", ", startIndex)}], {length}) of {what}";
        if (!ts.TryGetSpan(startIndex, length, out Span<int> span))
        {
            return;
        }

        // The span must be the next `length` elements in row-major order, in consecutive memory.
        Check.Equal(length, span.Length, $"span length: {spanWhat}");
        Check.That(first + length <= offsets.Length, $"span runs past the last element: {spanWhat}");
        for (int i = 0; i < length; i++)
        {
            Check.Equal(array[offsets[first + i]], span[i], $"span[{i}]: {spanWhat}");
        }
    }

    private static void Reshaping(TensorSpan<int> ts, ref FuzzInput input, nint[] lengths, int[] expected, string what)
    {
        byte op = input.Byte();
        int rank = lengths.Length;
        try
        {
            switch (op % 5)
            {
                case 0:
                {
                    nint[] shape = new nint[1 + input.Byte() % 4];
                    for (int k = 0; k < shape.Length; k++)
                    {
                        shape[k] = input.Byte() % 9;
                    }

                    if (shape.Length > 0 && (input.Byte() & 1) != 0)
                    {
                        shape[0] = -1;
                    }

                    TensorSpan<int> reshaped;
                    try
                    {
                        reshaped = Tensor.Reshape(ts, shape);
                    }
                    catch (ArgumentException)
                    {
                        return;
                    }
                    catch (Exception e) when (!s_reportKnownIssues && e is DivideByZeroException or IndexOutOfRangeException)
                    {
                        // Known (TENSOR-RESHAPE-1): Reshape to a shape with -1 and a 0 length divides by
                        // zero; some shapes of an empty tensor index out of range.
                        return;
                    }

                    Elements(reshaped, expected, $"Reshape([{string.Join(", ", shape)}]) of {what}");
                    break;
                }

                case 1:
                    // Known (TENSOR-SQUEEZE-1): squeezing a tensor whose lengths are all 1 gives an empty
                    // rank-1 tensor, losing its element.
                    if (s_reportKnownIssues || lengths.Any(l => l != 1))
                    {
                        Elements(Tensor.Squeeze(ts), expected, $"Squeeze of {what}");
                    }

                    Elements(Tensor.Unsqueeze(ts, input.Byte() % (rank + 1)), expected, $"Unsqueeze of {what}");
                    break;
                case 2:
                    Check.SequenceEqual<int>(expected.Reverse().ToArray(), Tensor.Reverse<int>(ts).ToArray(), $"Reverse of {what}");
                    break;
                case 3:
                {
                    int dimension = input.Byte() % rank;
                    Tensor<int> reversed = Tensor.ReverseDimension<int>(ts, dimension);
                    Check.That(reversed.Lengths.SequenceEqual(lengths), $"ReverseDimension({dimension}) lengths of {what}");
                    // Element [.., i_d, ..] of the result is element [.., len_d - 1 - i_d, ..] of the source.
                    var index = new nint[rank];
                    foreach (int v in reversed)
                    {
                        nint flat = 0;
                        for (int k = 0; k < rank; k++)
                        {
                            flat = flat * lengths[k] + (k == dimension ? lengths[k] - 1 - index[k] : index[k]);
                        }

                        Check.Equal(expected[flat], v, $"ReverseDimension({dimension}) element [{string.Join(", ", index)}] of {what}");
                        for (int d = rank - 1; d >= 0 && ++index[d] == lengths[d]; d--)
                        {
                            index[d] = 0;
                        }
                    }

                    break;
                }

                default:
                    Check.Equal(expected.Aggregate(0, (s, v) => unchecked(s + v)), Tensor.Sum<int>(ts), $"Sum of {what}");
                    break;
            }
        }
        catch (Exception e) when (e is not ConsistencyException && (e is ArgumentException) && rank > 0 && lengths.Any(l => l == 0))
        {
            // Some operations reject empty tensors.
        }
    }
}
