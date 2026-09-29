#nullable disable warnings
using System.Globalization;
using System.Numerics;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Numerics.BigInteger (System.Runtime.Numerics): parsing, formatting and arithmetic.</summary>
/// <remarks>
/// Input layout:
///   byte 0-1   NumberStyles (masked to the defined bits)
///   byte 2     shift amount / small exponent
///   segment    first number (text)
///   segment    second number (text)
///   segment    format string
/// Checks: Parse / TryParse (string, UTF-16 span, UTF-8) agree, and agree with Int128 for
/// decimal inputs that fit; ToString / TryFormat (UTF-16, UTF-8) agree and standard formats
/// round-trip; + - * / % DivRem, shifts, bitwise operators, Pow and ModPow satisfy their
/// algebraic identities; byte array conversions round-trip.
/// </remarks>
public static class BigIntegerTarget
{
    // Parsing and multiplication are superlinear, so keep operands small enough for AFL's timeout.
    private const int MaxTextLength = 600;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        var styles = (NumberStyles)(input.UInt16() & 0x7FF);
        byte small = input.Byte();
        byte[] utf8A = input.SegmentBytes().ToArray();
        string textB = input.Segment();
        string format = input.Segment();
        if (utf8A.Length > MaxTextLength || textB.Length > MaxTextLength || format.Length > 8)
        {
            return;
        }

        string textA = Encoding.UTF8.GetString(utf8A);

        // Known (BIGINTEGER-EXP-1): BigInteger materializes huge exponents ("1e100000000" takes a minute).
        if ((styles & NumberStyles.AllowExponent) != 0 && (NumberTarget.HasHugeExponent(textA) || NumberTarget.HasHugeExponent(textB)) &&
            Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is null)
        {
            return;
        }
        var inv = NumberFormatInfo.InvariantInfo;
        BigInteger a = ParseAll(textA, utf8A, styles, inv) ?? Fallback(utf8A);
        BigInteger b = ParseAll(textB, Encoding.UTF8.GetBytes(textB), styles, inv) ?? Fallback(Encoding.UTF8.GetBytes(textB));

        // Exponents make small texts into huge values ("3E82024" has 270k bits), and formatting and
        // multiplying those takes seconds; keep the arithmetic and formatting checks to 16k bits.
        if (a.GetBitLength() > 16384 || b.GetBitLength() > 16384)
        {
            return;
        }

        Formats(a, format);
        foreach (string standard in (string[])["D", "X", "B", "N0", "E30", "R", "G", "C"])
        {
            Formats(a, standard);
        }

        RoundTrip(a, a.ToString("D", inv), NumberStyles.Integer);
        RoundTrip(a, a.ToString("N0", inv), NumberStyles.Number);
        RoundTrip(a, a.ToString("X", inv), NumberStyles.HexNumber);
        RoundTrip(a, a.ToString("B", inv), NumberStyles.BinaryNumber);

        Arithmetic(a, b, small);
        Bytes(a);
    }

    private static BigInteger Fallback(byte[] seed) => new BigInteger(seed.AsSpan(0, Math.Min(seed.Length, 64)), isUnsigned: false);

    private static BigInteger? ParseAll(string text, byte[] utf8, NumberStyles styles, NumberFormatInfo nfi)
    {
        string what = $"BigInteger {Check.Show(text)} styles={styles}";
        var parse = Outcome<BigInteger>.Of(() => BigInteger.Parse(text, styles, nfi), e => e is FormatException or ArgumentException);
        var tryParse = Outcome<(bool, BigInteger)>.Of(() => (BigInteger.TryParse(text, styles, nfi, out BigInteger v), v), e => e is ArgumentException);
        var alternatives = new List<(string, Outcome<(bool, BigInteger)>)>
        {
            ("TryParse(span)", Outcome<(bool, BigInteger)>.Of(() => (BigInteger.TryParse(text.AsSpan(), styles, nfi, out BigInteger v), v), e => e is ArgumentException)),
        };
        if (System.Text.Unicode.Utf8.IsValid(utf8))
        {
            alternatives.Add(("TryParse(UTF-8)", Outcome<(bool, BigInteger)>.Of(() => (BigInteger.TryParse(utf8, styles, nfi, out BigInteger v), v), e => e is ArgumentException)));
        }

        Check.ParseAgreement(what, EqualityComparer<BigInteger>.Default, parse, [typeof(FormatException)], tryParse, alternatives.ToArray());

        // Int128 shares the front end but not the digit accumulation.
        if (tryParse.Ok && (styles & (NumberStyles.AllowHexSpecifier | NumberStyles.AllowBinarySpecifier)) == 0 &&
            Int128.TryParse(text, styles, nfi, out Int128 narrow))
        {
            Check.That(tryParse.Value.Item1 && tryParse.Value.Item2 == narrow, $"Int128.TryParse {narrow} but BigInteger.TryParse {tryParse} for {what}");
        }

        return tryParse.Ok && tryParse.Value.Item1 ? tryParse.Value.Item2 : null;
    }

    private static void RoundTrip(BigInteger value, string text, NumberStyles styles)
    {
        bool ok = BigInteger.TryParse(text, styles, NumberFormatInfo.InvariantInfo, out BigInteger back);
        // Hex and binary are two's complement: a leading 0 digit keeps positive values positive.
        Check.That(ok && back == value, $"BigInteger {value} formatted as {Check.Show(text)} parses back as {(ok ? back.ToString() : "failure")} (styles={styles})");
    }

    private static void Formats(BigInteger value, string format)
    {
        var inv = NumberFormatInfo.InvariantInfo;
        var str = Outcome<string>.Of(() => value.ToString(format, inv), e => e is FormatException);
        string what = $"BigInteger {value} format={Check.Show(format)}";
        if (!str.Ok)
        {
            var tryFormat = Outcome<bool>.Of(() => value.TryFormat(new char[4096], out _, format, inv), e => e is FormatException);
            Check.That(!tryFormat.Ok, $"ToString threw {str} but TryFormat gave {tryFormat} for {what}");
            return;
        }

        string s = str.Value;
        char[] exact = new char[s.Length];
        Check.That(value.TryFormat(exact, out int n, format, inv) && n == s.Length && exact.AsSpan().SequenceEqual(s), $"TryFormat(char) into exact buffer failed for {what}");
        if (s.Length > 0)
        {
            Check.That(!value.TryFormat(new char[s.Length - 1], out _, format, inv), $"TryFormat(char) into short buffer succeeded for {what}");
        }

        // Known (UTF8FMT-1): UTF-8 formatting throws ArgumentOutOfRangeException from new Rune(char) for a
        // custom format containing a lone surrogate.
        if (format.AsSpan().IndexOfAnyInRange('\uD800', '\uDFFF') >= 0 && Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is null)
        {
            return;
        }

        byte[] expected = Encoding.UTF8.GetBytes(s);
        byte[] bytes = new byte[expected.Length];
        Check.That(value.TryFormat(bytes, out n, format, inv) && n == expected.Length && bytes.AsSpan().SequenceEqual(expected), $"TryFormat(UTF-8) into exact buffer failed for {what}");
        if (expected.Length > 0)
        {
            Check.That(!value.TryFormat(new byte[expected.Length - 1], out _, format, inv), $"TryFormat(UTF-8) into short buffer succeeded for {what}");
        }
    }

    private static void Arithmetic(BigInteger a, BigInteger b, byte small)
    {
        string what = $"a={a}, b={b}";
        Check.That(a + b - b == a && a - b + b == a && a + b == b + a, $"addition/subtraction identities fail for {what}");
        BigInteger product = a * b;
        Check.That(product == b * a && (a.IsZero || b.IsZero) == product.IsZero, $"multiplication identities fail for {what}");
        Check.That(BigInteger.Multiply(a, a) == BigInteger.Pow(a, 2), $"a*a != Pow(a, 2) for {what}");
        if (!b.IsZero)
        {
            (BigInteger q, BigInteger r) = BigInteger.DivRem(a, b);
            Check.That(q == a / b && r == a % b && q * b + r == a && BigInteger.Abs(r) < BigInteger.Abs(b) && (r.IsZero || r.Sign == a.Sign),
                $"DivRem ({q}, {r}) inconsistent for {what}");
            Check.That(product / b == a && product % b == 0, $"(a*b)/b != a for {what}");
        }

        int shift = small % 200;
        Check.That((a << shift) >> shift == a && a << shift == a * BigInteger.Pow(2, shift), $"shift by {shift} inconsistent for {what}");
        Check.That(a >> shift == BigInteger.Divide(a - (a.Sign < 0 ? BigInteger.Pow(2, shift) - 1 : 0), BigInteger.Pow(2, shift)),
            $"a >> {shift} isn't floor division for {what}");
        Check.That((a ^ b ^ b) == a && (a & b) + (a | b) == a + b && ~~a == a && ~a == -a - 1, $"bitwise identities fail for {what}");
        BigInteger gcd = BigInteger.GreatestCommonDivisor(a, b);
        Check.That(gcd.Sign >= 0 && (gcd.IsZero ? a.IsZero && b.IsZero : a % gcd == 0 && b % gcd == 0) && (b.IsZero || gcd == BigInteger.GreatestCommonDivisor(b, a % b)),
            $"GCD {gcd} inconsistent for {what}");

        if (!b.IsZero && a.Sign >= 0)
        {
            int e = small % 64;
            BigInteger m = BigInteger.Abs(b);
            BigInteger expected = BigInteger.One % m;
            BigInteger baseMod = a % m;
            for (int i = 0; i < e; i++)
            {
                expected = expected * baseMod % m;
            }

            Check.Equal(expected, BigInteger.ModPow(a, e, m), $"ModPow(a, {e}, |b|) for {what}");
        }

        Check.That(BigInteger.Log2(BigInteger.Abs(a) | 1) == (BigInteger.Abs(a) | 1).GetBitLength() - 1, $"Log2 != GetBitLength - 1 for {what}");
    }

    private static void Bytes(BigInteger a)
    {
        string what = $"BigInteger {a}";
        foreach (bool bigEndian in (bool[])[false, true])
        {
            byte[] signed = a.ToByteArray(isUnsigned: false, isBigEndian: bigEndian);
            Check.Equal(signed.Length, a.GetByteCount(), $"GetByteCount for {what}");
            Check.That(new BigInteger(signed, isUnsigned: false, isBigEndian: bigEndian) == a, $"ToByteArray(bigEndian={bigEndian}) doesn't round-trip for {what}");
            byte[] exact = new byte[signed.Length];
            Check.That(a.TryWriteBytes(exact, out int written, isUnsigned: false, isBigEndian: bigEndian) && written == signed.Length && exact.AsSpan().SequenceEqual(signed),
                $"TryWriteBytes != ToByteArray for {what}");
            Check.That(!a.TryWriteBytes(new byte[signed.Length - 1], out _, isUnsigned: false, isBigEndian: bigEndian), $"TryWriteBytes into a short buffer succeeded for {what}");
            if (a.Sign >= 0)
            {
                byte[] unsigned = a.ToByteArray(isUnsigned: true, isBigEndian: bigEndian);
                Check.That(new BigInteger(unsigned, isUnsigned: true, isBigEndian: bigEndian) == a, $"unsigned ToByteArray(bigEndian={bigEndian}) doesn't round-trip for {what}");
            }
        }
    }
}
