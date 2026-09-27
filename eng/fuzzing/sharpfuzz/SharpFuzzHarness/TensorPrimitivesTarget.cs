#nullable disable warnings
using System.Numerics;
using System.Numerics.Tensors;
using System.Runtime.InteropServices;

namespace SharpFuzzHarness;

/// <summary>
/// Fuzzes System.Numerics.Tensors.TensorPrimitives against scalar references built from the element
/// type's own operators (T.Max, T.Abs, x + y, ...), for every primitive element type.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     element type (see <see cref="Run"/>)
///   byte 1     operation (per category: common, floating-point or integer)
///   byte 2     flags: 0x01 in place (destination is x), 0x02 misaligned (offset spans), 0x04 y one
///              element short, 0x08 destination one element short, 0x10 compact values (one byte per
///              element, mapped to special values and small numbers), 0x20 destination overlaps x
///              shifted by one element
///   byte 3     shift amount / conversion target / rounding mode
///   rest       element data, split into x (first half) and y (second half)
/// Element-wise operations, min/max reductions, IndexOf* and conversions must match the reference
/// exactly (NaN payloads aside), including which exception is thrown. Floating-point sums and dot
/// products must lie within the worst-case rounding error bound of any summation order. Mismatched
/// lengths, short destinations and partially overlapping destinations must throw ArgumentException.
/// The secondaries in fuzz.sh run with AVX-512 or AVX2 disabled, so all vector widths are covered.
/// </remarks>
public static class TensorPrimitivesTarget
{
    private const int MaxBytes = 4096;

    private delegate void Unary<T>(ReadOnlySpan<T> x, Span<T> destination);
    private delegate void Binary<T>(ReadOnlySpan<T> x, ReadOnlySpan<T> y, Span<T> destination);
    private delegate void BinaryScalar<T>(ReadOnlySpan<T> x, T y, Span<T> destination);
    private delegate TResult Reduce<T, TResult>(ReadOnlySpan<T> x);
    private delegate TResult Reduce2<T, TResult>(ReadOnlySpan<T> x, ReadOnlySpan<T> y);
    private delegate void Converter<TFrom, TTo>(ReadOnlySpan<TFrom> source, Span<TTo> destination);

    [Flags]
    private enum Mode : byte
    {
        InPlace = 0x01, Misaligned = 0x02, ShortY = 0x04, ShortDestination = 0x08, Compact = 0x10, Overlap = 0x20,
    }

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte type = input.Byte();
        byte op = input.Byte();
        var mode = (Mode)input.Byte();
        byte extra = input.Byte();
        ReadOnlySpan<byte> payload = input.Rest();
        if (payload.Length > MaxBytes)
        {
            return;
        }

        switch (type % 13)
        {
            case 0: Floating<float>(payload, op, mode, extra); break;
            case 1: Floating<double>(payload, op, mode, extra); break;
            case 2: Floating<Half>(payload, op, mode, extra); break;
            case 3: Integer<sbyte>(payload, op, mode, extra); break;
            case 4: Integer<byte>(payload, op, mode, extra); break;
            case 5: Integer<short>(payload, op, mode, extra); break;
            case 6: Integer<ushort>(payload, op, mode, extra); break;
            case 7: Integer<int>(payload, op, mode, extra); break;
            case 8: Integer<uint>(payload, op, mode, extra); break;
            case 9: Integer<long>(payload, op, mode, extra); break;
            case 10: Integer<ulong>(payload, op, mode, extra); break;
            case 11: Integer<nint>(payload, op, mode, extra); break;
            default: Integer<nuint>(payload, op, mode, extra); break;
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Input decoding

    private static T[] Values<T>(ReadOnlySpan<byte> payload, Mode mode, Func<byte, T> compact)
        where T : unmanaged
    {
        if ((mode & Mode.Compact) != 0)
        {
            var values = new T[payload.Length];
            for (int i = 0; i < values.Length; i++)
            {
                values[i] = compact(payload[i]);
            }

            return values;
        }

        return MemoryMarshal.Cast<byte, T>(payload.Slice(0, payload.Length / Marshal.SizeOf<T>() * Marshal.SizeOf<T>())).ToArray();
    }

    private static T FloatingValue<T>(byte b)
        where T : IBinaryFloatingPointIeee754<T>, IMinMaxValue<T> => (b & 0x1F) switch
    {
        0 => T.NaN,
        1 => -T.NaN,
        2 => T.Zero,
        3 => T.NegativeZero,
        4 => T.PositiveInfinity,
        5 => T.NegativeInfinity,
        6 => T.MaxValue,
        7 => T.MinValue,
        8 => T.Epsilon,
        9 => -T.Epsilon,
        10 => T.One,
        11 => -T.One,
        12 => T.BitDecrement(T.MaxValue),
        13 => T.CreateTruncating(0.5),
        _ => T.CreateTruncating((sbyte)b) / T.CreateTruncating(4),
    };

    private static T IntegerValue<T>(byte b)
        where T : IBinaryInteger<T>, IMinMaxValue<T> => (b & 0x0F) switch
    {
        0 => T.MinValue,
        1 => T.MaxValue,
        2 => T.MinValue + T.One,
        3 => T.MaxValue - T.One,
        4 => T.Zero,
        _ => T.CreateTruncating((sbyte)b),
    };

    /// <summary>Copies <paramref name="values"/> into a larger array at an offset (misaligned mode) and returns that window.</summary>
    private static Memory<T> Place<T>(T[] values, Mode mode, int salt)
    {
        int offset = (mode & Mode.Misaligned) != 0 ? 1 + salt % 7 : 0;
        var buffer = new T[values.Length + offset + 8];
        values.CopyTo(buffer, offset);
        return buffer.AsMemory(offset, values.Length);
    }

    // ---------------------------------------------------------------------------------------------
    // Categories

    private static void Floating<T>(ReadOnlySpan<byte> payload, byte op, Mode mode, byte extra)
        where T : unmanaged, IBinaryFloatingPointIeee754<T>, IMinMaxValue<T>
    {
        T[] all = Values(payload, mode, FloatingValue<T>);
        var c = new Case<T>(all, mode, extra);
        const int CommonOps = 27;
        if (op % 48 < CommonOps)
        {
            Common(c, op % 48);
            return;
        }

        switch (op % 48 - CommonOps)
        {
            case 0: c.Binary("MaxNumber", TensorPrimitives.MaxNumber<T>, T.MaxNumber); break;
            case 1: c.Binary("MinNumber", TensorPrimitives.MinNumber<T>, T.MinNumber); break;
            case 2: c.Binary("MaxMagnitudeNumber", TensorPrimitives.MaxMagnitudeNumber<T>, T.MaxMagnitudeNumber); break;
            case 3: c.Binary("MinMagnitudeNumber", TensorPrimitives.MinMagnitudeNumber<T>, T.MinMagnitudeNumber); break;
            case 4: c.Fold("MaxNumber", TensorPrimitives.MaxNumber<T>, T.MaxNumber, emptyThrows: true, nanIgnored: true); break;
            case 5: c.Fold("MinNumber", TensorPrimitives.MinNumber<T>, T.MinNumber, emptyThrows: true, nanIgnored: true); break;
            case 6: c.Fold("MaxMagnitudeNumber", TensorPrimitives.MaxMagnitudeNumber<T>, T.MaxMagnitudeNumber, emptyThrows: true, nanIgnored: true); break;
            case 7: c.Fold("MinMagnitudeNumber", TensorPrimitives.MinMagnitudeNumber<T>, T.MinMagnitudeNumber, emptyThrows: true, nanIgnored: true); break;
            case 8: c.Unary("Floor", TensorPrimitives.Floor<T>, T.Floor); break;
            case 9: c.Unary("Ceiling", TensorPrimitives.Ceiling<T>, T.Ceiling); break;
            case 10: c.Unary("Truncate", TensorPrimitives.Truncate<T>, T.Truncate); break;
            case 11:
                var rounding = (MidpointRounding)(extra % 5);
                c.Unary($"Round({rounding})", (x, d) => TensorPrimitives.Round(x, rounding, d), v => T.Round(v, rounding));
                break;
            case 12: c.Unary("Sqrt", TensorPrimitives.Sqrt<T>, T.Sqrt); break;
            case 13: c.Binary("FusedMultiplyAdd(x, y, x)", (x, y, d) => TensorPrimitives.FusedMultiplyAdd(x, y, x, d), (a, b) => T.FusedMultiplyAdd(a, b, a)); break;
            case 14: c.BinaryScalar("FusedMultiplyAdd(x, s, y)", (x, s, d) => TensorPrimitives.FusedMultiplyAdd(x, s, x, d), (a, s) => T.FusedMultiplyAdd(a, s, a)); break;
            case 15: c.Unary("Reciprocal", TensorPrimitives.Reciprocal<T>, v => T.One / v); break;
            case 16: c.BinaryScalar("CopySign(x, s)", TensorPrimitives.CopySign<T>, T.CopySign); break;
            case 17: c.BinaryScalar("MaxNumber(x, s)", TensorPrimitives.MaxNumber<T>, T.MaxNumber); break;
            case 18: c.BinaryScalar("Divide(x, s)", TensorPrimitives.Divide<T>, (a, s) => a / s); break;
            default: Conversions(c, extra); break;
        }
    }

    private static void Integer<T>(ReadOnlySpan<byte> payload, byte op, Mode mode, byte extra)
        where T : unmanaged, IBinaryInteger<T>, IMinMaxValue<T>
    {
        T[] all = Values(payload, mode, IntegerValue<T>);
        var c = new Case<T>(all, mode, extra);
        const int CommonOps = 27;
        if (op % 48 < CommonOps)
        {
            Common(c, op % 48);
            return;
        }

        int shift = extra % 80 - 8; // also negative and larger than the bit width
        switch (op % 48 - CommonOps)
        {
            case 0: c.Binary("BitwiseAnd", TensorPrimitives.BitwiseAnd<T>, (a, b) => a & b); break;
            case 1: c.Binary("BitwiseOr", TensorPrimitives.BitwiseOr<T>, (a, b) => a | b); break;
            case 2: c.Binary("Xor", TensorPrimitives.Xor<T>, (a, b) => a ^ b); break;
            case 3: c.Unary("OnesComplement", TensorPrimitives.OnesComplement<T>, a => ~a); break;
            case 4: c.Unary("PopCount", TensorPrimitives.PopCount<T>, T.PopCount); break;
            case 5: c.Unary("LeadingZeroCount", TensorPrimitives.LeadingZeroCount<T>, T.LeadingZeroCount); break;
            case 6: c.Unary("TrailingZeroCount", TensorPrimitives.TrailingZeroCount<T>, T.TrailingZeroCount); break;
            case 7: c.Unary($"ShiftLeft({shift})", (x, d) => TensorPrimitives.ShiftLeft(x, shift, d), a => a << shift); break;
            case 8: c.Unary($"ShiftRightArithmetic({shift})", (x, d) => TensorPrimitives.ShiftRightArithmetic(x, shift, d), a => a >> shift); break;
            case 9: c.Unary($"ShiftRightLogical({shift})", (x, d) => TensorPrimitives.ShiftRightLogical(x, shift, d), a => a >>> shift); break;
            case 10: c.Unary($"RotateLeft({shift})", (x, d) => TensorPrimitives.RotateLeft(x, shift, d), a => T.RotateLeft(a, shift)); break;
            case 11: c.Unary($"RotateRight({shift})", (x, d) => TensorPrimitives.RotateRight(x, shift, d), a => T.RotateRight(a, shift)); break;
            case 12: c.Reduce("PopCount", x => TensorPrimitives.PopCount(x), x => { long n = 0; foreach (T v in x) n += long.CreateTruncating(T.PopCount(v)); return n; }); break;
            case 13: c.Reduce2("HammingBitDistance", TensorPrimitives.HammingBitDistance<T>, (x, y) => { long n = 0; for (int i = 0; i < x.Length; i++) n += long.CreateTruncating(T.PopCount(x[i] ^ y[i])); return n; }); break;
            case 14: c.Reduce2("HammingDistance", TensorPrimitives.HammingDistance<T>, (x, y) => { int n = 0; for (int i = 0; i < x.Length; i++) n += x[i] == y[i] ? 0 : 1; return n; }); break;
            case 15: c.BinaryScalar("BitwiseAnd(x, s)", TensorPrimitives.BitwiseAnd<T>, (a, s) => a & s); break;
            case 16: c.BinaryScalar("Xor(x, s)", TensorPrimitives.Xor<T>, (a, s) => a ^ s); break;
            case 17: c.BinaryScalar("Divide(x, s)", TensorPrimitives.Divide<T>, (a, s) => a / s); break;
            default: Conversions(c, extra); break;
        }
    }

    /// <summary>Operations every numeric element type supports.</summary>
    private static void Common<T>(Case<T> c, int op)
        where T : unmanaged, INumber<T>, IMinMaxValue<T>
    {
        switch (op)
        {
            case 0: c.Binary("Add", TensorPrimitives.Add<T>, (a, b) => a + b); break;
            case 1: c.Binary("Subtract", TensorPrimitives.Subtract<T>, (a, b) => a - b); break;
            case 2: c.Binary("Multiply", TensorPrimitives.Multiply<T>, (a, b) => a * b); break;
            case 3: c.Binary("Divide", TensorPrimitives.Divide<T>, (a, b) => a / b); break;
            case 4: c.Binary("Max", TensorPrimitives.Max<T>, T.Max); break;
            case 5: c.Binary("Min", TensorPrimitives.Min<T>, T.Min); break;
            case 6: c.Binary("MaxMagnitude", TensorPrimitives.MaxMagnitude<T>, T.MaxMagnitude); break;
            case 7: c.Binary("MinMagnitude", TensorPrimitives.MinMagnitude<T>, T.MinMagnitude); break;
            case 8: c.Binary("CopySign", TensorPrimitives.CopySign<T>, T.CopySign); break;
            case 9: c.Unary("Abs", TensorPrimitives.Abs<T>, T.Abs); break;
            case 10: c.Unary("Negate", TensorPrimitives.Negate<T>, a => -a); break;
            case 11: c.Unary("Increment", TensorPrimitives.Increment<T>, a => a + T.One); break;
            case 12: c.BinaryScalar("Add(x, s)", TensorPrimitives.Add<T>, (a, s) => a + s); break;
            case 13: c.BinaryScalar("Multiply(x, s)", TensorPrimitives.Multiply<T>, (a, s) => a * s); break;
            case 14: c.BinaryScalar("Max(x, s)", TensorPrimitives.Max<T>, T.Max); break;
            case 15: c.BinaryScalar("MinMagnitude(x, s)", TensorPrimitives.MinMagnitude<T>, T.MinMagnitude); break;
            case 16: c.Fold("Max", TensorPrimitives.Max<T>, T.Max, emptyThrows: true); break;
            case 17: c.Fold("Min", TensorPrimitives.Min<T>, T.Min, emptyThrows: true); break;
            case 18: c.Fold("MaxMagnitude", TensorPrimitives.MaxMagnitude<T>, T.MaxMagnitude, emptyThrows: true); break;
            case 19: c.Fold("MinMagnitude", TensorPrimitives.MinMagnitude<T>, T.MinMagnitude, emptyThrows: true); break;
            case 20: c.IndexOf("IndexOfMax", TensorPrimitives.IndexOfMax<T>, T.Max); break;
            case 21: c.IndexOf("IndexOfMin", TensorPrimitives.IndexOfMin<T>, T.Min); break;
            case 22: c.IndexOf("IndexOfMaxMagnitude", TensorPrimitives.IndexOfMaxMagnitude<T>, T.MaxMagnitude); break;
            case 23: c.IndexOf("IndexOfMinMagnitude", TensorPrimitives.IndexOfMinMagnitude<T>, T.MinMagnitude); break;
            case 24: c.Sum("Sum", x => TensorPrimitives.Sum(x), null, v => v); break;
            case 25: c.Sum("SumOfSquares", x => TensorPrimitives.SumOfSquares(x), null, v => v * v); break;
            default:
                if (c.Extra % 3 == 0)
                {
                    c.Sum("SumOfMagnitudes", x => TensorPrimitives.SumOfMagnitudes(x), null, T.Abs);
                }
                else if (c.Extra % 3 == 1)
                {
                    c.Sum("Dot", null, (x, y) => TensorPrimitives.Dot(x, y), null);
                }
                else
                {
                    c.Fold("Product", TensorPrimitives.Product<T>, (a, b) => a * b, emptyThrows: true, exactForFloats: false);
                }

                break;
        }
    }

    private static void Conversions<TFrom>(Case<TFrom> c, byte extra)
        where TFrom : unmanaged, INumber<TFrom>, IMinMaxValue<TFrom>
    {
        switch (extra % 13)
        {
            case 0: Convert<TFrom, float>(c, extra); break;
            case 1: Convert<TFrom, double>(c, extra); break;
            case 2: Convert<TFrom, Half>(c, extra); break;
            case 3: Convert<TFrom, sbyte>(c, extra); break;
            case 4: Convert<TFrom, byte>(c, extra); break;
            case 5: Convert<TFrom, short>(c, extra); break;
            case 6: Convert<TFrom, ushort>(c, extra); break;
            case 7: Convert<TFrom, int>(c, extra); break;
            case 8: Convert<TFrom, uint>(c, extra); break;
            case 9: Convert<TFrom, long>(c, extra); break;
            case 10: Convert<TFrom, ulong>(c, extra); break;
            case 11: Convert<TFrom, nint>(c, extra); break;
            default: Convert<TFrom, nuint>(c, extra); break;
        }
    }

    private static void Convert<TFrom, TTo>(Case<TFrom> c, byte extra)
        where TFrom : unmanaged, INumber<TFrom>, IMinMaxValue<TFrom>
        where TTo : unmanaged, INumberBase<TTo>
    {
        TFrom[] x = c.X.ToArray();
        string name;
        Converter<TFrom, TTo> vector;
        Func<TFrom, TTo> scalar;
        switch (extra / 13 % 3)
        {
            case 0: (name, vector, scalar) = ("ConvertSaturating", TensorPrimitives.ConvertSaturating<TFrom, TTo>, TTo.CreateSaturating); break;
            case 1: (name, vector, scalar) = ("ConvertTruncating", TensorPrimitives.ConvertTruncating<TFrom, TTo>, TTo.CreateTruncating); break;
            default: (name, vector, scalar) = ("ConvertChecked", TensorPrimitives.ConvertChecked<TFrom, TTo>, TTo.CreateChecked); break;
        }
        string what = $"{name}<{typeof(TFrom).Name}, {typeof(TTo).Name}> of {Show(x)}";

        var expected = new TTo[x.Length];
        Type expectedError = null;
        for (int i = 0; i < x.Length && expectedError is null; i++)
        {
            try
            {
                expected[i] = scalar(x[i]);
            }
            catch (OverflowException e)
            {
                expectedError = e.GetType();
            }
        }

        var actual = new TTo[x.Length];
        Type error = Try(() => vector(x, actual));
        Check.That(error == expectedError, $"{what} threw {error?.Name ?? "nothing"}, the scalar conversion {expectedError?.Name ?? "nothing"}");
        if (error is null)
        {
            CompareElements(expected, actual, what, i => Show(x[i]));
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Checks

    private sealed class Case<T>(T[] all, Mode mode, byte extra)
        where T : unmanaged, INumberBase<T>
    {
        private readonly T[] _x = all[..(all.Length / 2)];
        private readonly T[] _y = all[(all.Length / 2)..(all.Length / 2 * 2)];

        public ReadOnlySpan<T> X => _x;

        public byte Extra => extra;

        private T Scalar => _y.Length > 0 ? _y[extra % _y.Length] : T.One;

        public void Unary(string name, Unary<T> vector, Func<T, T> scalar) =>
            Elementwise(name, (x, _, d) => vector(x, d), (a, _) => scalar(a), usesY: false);

        public void Binary(string name, Binary<T> vector, Func<T, T, T> scalar) =>
            Elementwise(name, (x, y, d) => vector(x, y, d), scalar, usesY: true);

        public void BinaryScalar(string name, BinaryScalar<T> vector, Func<T, T, T> scalar)
        {
            T s = Scalar;
            Elementwise($"{name} with s = {Show(s)}", (x, _, d) => vector(x, s, d), (a, _) => scalar(a, s), usesY: false);
        }

        private void Elementwise(string name, Binary<T> vector, Func<T, T, T> scalar, bool usesY)
        {
            string what = $"{typeof(T).Name} {name} of x = {Show(_x)}" + (usesY ? $", y = {Show(_y)}" : "") + $" ({mode})";

            // Argument validation comes first: mismatched lengths, a short destination, and a
            // destination that partially overlaps an input are all ArgumentExceptions.
            if ((mode & Mode.ShortY) != 0 && usesY && _x.Length > 0)
            {
                Check.That(Try(() => vector(_x, _y.AsSpan(0, _x.Length - 1), new T[_x.Length])) == typeof(ArgumentException), $"{what}: y one element short didn't throw ArgumentException");
                return;
            }

            if ((mode & Mode.ShortDestination) != 0 && _x.Length > 0)
            {
                Check.That(Try(() => vector(_x, _y, new T[_x.Length - 1])) == typeof(ArgumentException), $"{what}: destination one element short didn't throw ArgumentException");
                return;
            }

            if ((mode & Mode.Overlap) != 0 && _x.Length > 1)
            {
                var buffer = new T[_x.Length + 1];
                _x.CopyTo(buffer, 0);
                Type overlap = Try(() => vector(buffer.AsSpan(0, _x.Length), _y, buffer.AsSpan(1, _x.Length)));
                Check.That(overlap == typeof(ArgumentException), $"{what}: destination overlapping x by one element threw {overlap?.Name ?? "nothing"}, not ArgumentException");
                return;
            }

            var expected = new T[_x.Length];
            Type expectedError = null;
            for (int i = 0; i < _x.Length && expectedError is null; i++)
            {
                try
                {
                    expected[i] = scalar(_x[i], _y[i]);
                }
                catch (Exception e) when (e is OverflowException or DivideByZeroException)
                {
                    expectedError = e.GetType();
                }
            }

            Memory<T> x = Place(_x, mode, extra);
            Memory<T> y = Place(_y, mode, extra + 3);
            Memory<T> destination = (mode & Mode.InPlace) != 0 ? x : Place(new T[_x.Length], mode, extra + 5);
            Type error = Try(() => vector(x.Span, y.Span, destination.Span));

            // Integer Divide: with both a zero divisor and a MinValue / -1 pair in the input, which of
            // DivideByZeroException / OverflowException surfaces depends on the processing order.
            if (name.StartsWith("Divide", StringComparison.Ordinal) && !IsFloating<T>() && expectedError is not null && error is not null &&
                (error == typeof(DivideByZeroException) || error == typeof(OverflowException)))
            {
                expectedError = error;
            }

            // Known (TENSORS-COPYSIGN-1): for signed integers, the vectorized CopySign turns
            // CopySign(MinValue, +) into MinValue instead of throwing OverflowException like
            // T.CopySign, the scalar tail (spans shorter than a vector) and TensorPrimitives.Abs do.
            if (name.StartsWith("CopySign", StringComparison.Ordinal) && !s_reportKnownIssues && expectedError == typeof(OverflowException) && error is null)
            {
                return;
            }

            Check.That(error == expectedError, $"{what} threw {error?.Name ?? "nothing"}, the scalar operation {expectedError?.Name ?? "nothing"}");
            if (error is null)
            {
                CompareElements(expected, destination.Span.ToArray(), what, i => usesY ? $"{Show(_x[i])}, {Show(_y[i])}" : Show(_x[i]));
            }
        }

        /// <summary>A reduction whose result is the left fold of <paramref name="scalar"/> (exact for max/min, which are associative and commutative).</summary>
        public void Fold(string name, Reduce<T, T> vector, Func<T, T, T> scalar, bool emptyThrows, bool exactForFloats = true, bool nanIgnored = false)
        {
            string what = $"{typeof(T).Name} {name} of {Show(_x)}";
            Memory<T> x = Place(_x, mode, extra);
            T actual = default;
            Type error = Try(() => actual = vector(x.Span));
            if (_x.Length == 0)
            {
                Check.That(error == (emptyThrows ? typeof(ArgumentException) : null), $"{what} of an empty span threw {error?.Name ?? "nothing"}");
                return;
            }

            Check.That(error is null, $"{what} threw {error?.Name}");
            if (!exactForFloats && IsFloating<T>())
            {
                return;
            }

            // Known (TENSORS-NUMBER-NAN-1): the MaxNumber / MinNumber / Max- and MinMagnitudeNumber
            // reductions share MinMaxCore with Max / Min, whose early exit returns NaN as soon as an
            // element is NaN, although these are documented to ignore NaN (IEEE 754 maximumNumber).
            if (nanIgnored && !s_reportKnownIssues && T.IsNaN(actual) && _x.Any(T.IsNaN))
            {
                return;
            }

            T expected = _x[0];
            for (int i = 1; i < _x.Length; i++)
            {
                expected = scalar(expected, _x[i]);
            }

            Check.That(Same(expected, actual), $"{what} = {Show(actual)}, the scalar fold gives {Show(expected)}");
        }

        /// <summary>
        /// IndexOfMax and friends: the index of the first element the scalar operation would pick,
        /// where a NaN wins immediately (it is what Max/Min return) and -1 for an empty span.
        /// </summary>
        public void IndexOf(string name, Reduce<T, int> vector, Func<T, T, T> pick)
        {
            string what = $"{typeof(T).Name} {name} of {Show(_x)}";
            int expected = _x.Length == 0 ? -1 : 0;
            T best = _x.Length == 0 ? default : _x[0];
            for (int i = 0; i < _x.Length; i++)
            {
                if (T.IsNaN(_x[i]))
                {
                    expected = i;
                    break;
                }

                if (i > 0 && !Same(pick(best, _x[i]), best))
                {
                    best = _x[i];
                    expected = i;
                }
            }

            Memory<T> x = Place(_x, mode, extra);
            int actual = 0;
            Type error = Try(() => actual = vector(x.Span));
            Check.That(error is null && actual == expected, $"{what} = {(error is null ? actual.ToString() : error.Name)}, expected {expected}");
        }

        public void Reduce<TResult>(string name, Reduce<T, TResult> vector, Func<T[], TResult> scalar)
        {
            string what = $"{typeof(T).Name} {name} of {Show(_x)}";
            Memory<T> x = Place(_x, mode, extra);
            TResult actual = default;
            Type error = Try(() => actual = vector(x.Span));
            TResult expected = scalar(_x);
            Check.That(error is null && EqualityComparer<TResult>.Default.Equals(actual, expected), $"{what} = {(error is null ? actual : error.Name)}, expected {expected}");
        }

        public void Reduce2<TResult>(string name, Reduce2<T, TResult> vector, Func<T[], T[], TResult> scalar)
        {
            string what = $"{typeof(T).Name} {name} of x = {Show(_x)}, y = {Show(_y)}";
            if ((mode & Mode.ShortY) != 0 && _x.Length > 0)
            {
                Check.That(Try(() => vector(_x, _y.AsSpan(0, _x.Length - 1))) == typeof(ArgumentException), $"{what}: y one element short didn't throw ArgumentException");
                return;
            }

            TResult actual = default;
            Type error = Try(() => actual = vector(Place(_x, mode, extra).Span, Place(_y, mode, extra + 3).Span));
            TResult expected = scalar(_x, _y);
            Check.That(error is null && EqualityComparer<TResult>.Default.Equals(actual, expected), $"{what} = {(error is null ? actual : error.Name)}, expected {expected}");
        }

        /// <summary>
        /// Sum-like reductions. Integers wrap, so they must match the scalar sum exactly. For
        /// floating point the result depends on the summation order, but any order is within
        /// (n + 1) * u * sum(|terms|) of the exact sum (u = unit roundoff), which a compensated sum
        /// in double approximates to far better than that.
        /// </summary>
        public void Sum(string name, Reduce<T, T> vector, Reduce2<T, T> vector2, Func<T, T> term)
        {
            bool dot = vector2 is not null;
            string what = $"{typeof(T).Name} {name} of x = {Show(_x)}" + (dot ? $", y = {Show(_y)}" : "");
            Memory<T> x = Place(_x, mode, extra);
            Memory<T> y = Place(_y, mode, extra + 3);
            T actual = default;
            Type error = Try(() => actual = dot ? vector2(x.Span, y.Span) : vector(x.Span));

            if (!IsFloating<T>())
            {
                // Integers wrap, except that SumOfMagnitudes throws OverflowException for MinValue
                // (T.Abs does).
                T expected = T.Zero;
                Type expectedError = Try(() =>
                {
                    for (int i = 0; i < _x.Length; i++)
                    {
                        expected += dot ? _x[i] * _y[i] : term(_x[i]);
                    }
                });
                Check.That(error == expectedError && (error is not null || Same(expected, actual)),
                    $"{what} = {(error is null ? Show(actual) : error.Name)}, expected {(expectedError is null ? Show(expected) : expectedError.Name)}");
                return;
            }

            Check.That(error is null, $"{what} threw {error?.Name}");

            double sum = 0, compensation = 0, magnitude = 0;
            for (int i = 0; i < _x.Length; i++)
            {
                double t = dot ? double.CreateTruncating(_x[i]) * double.CreateTruncating(_y[i]) : double.CreateTruncating(term(_x[i]));
                if (!double.IsFinite(t) || !T.IsFinite(dot ? _x[i] * _y[i] : term(_x[i])))
                {
                    return; // Non-finite terms: overflow in T depends on the order.
                }

                double s = sum + t;
                compensation += Math.Abs(sum) >= Math.Abs(t) ? sum - s + t : t - s + sum;
                sum = s;
                magnitude += Math.Abs(t);
            }

            double exact = sum + compensation;
            double max = typeof(T) == typeof(float) ? float.MaxValue : typeof(T) == typeof(double) ? double.MaxValue : (double)Half.MaxValue;
            if (magnitude > max / 4)
            {
                return; // Partial sums may overflow T in some orders.
            }

            double u = Math.ScaleB(1, typeof(T) == typeof(float) ? -24 : typeof(T) == typeof(double) ? -53 : -11);
            double subnormal = typeof(T) == typeof(float) ? float.Epsilon : typeof(T) == typeof(double) ? double.Epsilon : (double)Half.Epsilon;
            double bound = (_x.Length + 2) * u * magnitude + (_x.Length + 2) * subnormal;
            double got = double.CreateTruncating(actual);
            Check.That(Math.Abs(got - exact) <= bound, $"{what} = {Show(actual)}, exact {exact:R}, error {Math.Abs(got - exact):R} > bound {bound:R}");
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    private static bool IsFloating<T>() => typeof(T) == typeof(float) || typeof(T) == typeof(double) || typeof(T) == typeof(Half);

    private static Type Try(Action action)
    {
        try
        {
            action();
            return null;
        }
        catch (Exception e) when (e is ArgumentException or OverflowException or DivideByZeroException)
        {
            return e is ArgumentException ? typeof(ArgumentException) : e.GetType();
        }
    }

    /// <summary>Equal values with the same sign (so +0 != -0), or both NaN.</summary>
    private static bool Same<T>(T a, T b)
        where T : INumberBase<T> => T.IsNaN(a) ? T.IsNaN(b) : !T.IsNaN(b) && a == b && T.IsNegative(a) == T.IsNegative(b);

    private static void CompareElements<T>(T[] expected, T[] actual, string what, Func<int, string> inputAt)
        where T : INumberBase<T>
    {
        for (int i = 0; i < expected.Length; i++)
        {
            Check.That(Same(expected[i], actual[i]), $"{what}: element {i} ({inputAt(i)}) is {Show(actual[i])}, scalar gives {Show(expected[i])}");
        }
    }

    private static string Show<T>(T value) => value switch
    {
        float f => f.ToString("R"),
        double d => d.ToString("R"),
        Half h => ((float)h).ToString("R"),
        _ => value.ToString(),
    };

    private static string Show<T>(T[] values) =>
        "[" + string.Join(", ", values.Take(24).Select(v => Show(v))) + (values.Length > 24 ? $", ... ({values.Length} elements)]" : "]");
}
