using System.Globalization;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>Consumes a fuzz input front to back. Reads past the end return zero / empty.</summary>
internal ref struct FuzzInput
{
    private ReadOnlySpan<byte> _data;

    public FuzzInput(ReadOnlySpan<byte> data) => _data = data;

    public readonly int Remaining => _data.Length;

    public byte Byte()
    {
        if (_data.IsEmpty)
        {
            return 0;
        }

        byte b = _data[0];
        _data = _data.Slice(1);
        return b;
    }

    public ushort UInt16() => (ushort)(Byte() | (Byte() << 8));

    public int Int32() => UInt16() | (UInt16() << 16);

    public ReadOnlySpan<byte> Bytes(int count)
    {
        count = Math.Min(count, _data.Length);
        ReadOnlySpan<byte> result = _data.Slice(0, count);
        _data = _data.Slice(count);
        return result;
    }

    public ReadOnlySpan<byte> Rest() => Bytes(_data.Length);

    /// <summary>Bytes up to (not including) the next '\0', or everything that is left.</summary>
    public ReadOnlySpan<byte> SegmentBytes()
    {
        int end = _data.IndexOf((byte)0);
        if (end < 0)
        {
            return Rest();
        }

        ReadOnlySpan<byte> result = _data.Slice(0, end);
        _data = _data.Slice(end + 1);
        return result;
    }

    /// <summary>The next '\0'-terminated segment decoded as UTF-8 (invalid sequences become U+FFFD).</summary>
    public string Segment() => Encoding.UTF8.GetString(SegmentBytes());
}

internal static class Check
{
    public static void That(bool condition, string message)
    {
        if (!condition)
        {
            throw new ConsistencyException(message);
        }
    }

    public static void Equal<T>(T expected, T actual, string what)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new ConsistencyException($"{what}: expected {Show(expected)}, got {Show(actual)}");
        }
    }

    public static void SequenceEqual<T>(ReadOnlySpan<T> expected, ReadOnlySpan<T> actual, string what)
        where T : IEquatable<T>
    {
        if (!expected.SequenceEqual(actual))
        {
            int i = 0;
            while (i < expected.Length && i < actual.Length && expected[i].Equals(actual[i]))
            {
                i++;
            }

            throw new ConsistencyException($"{what}: lengths {expected.Length}/{actual.Length}, first difference at {i}");
        }
    }

    /// <summary>
    /// Checks a Parse / TryParse family for agreement: every TryParse variant gives the same
    /// result; Parse succeeds with the same value exactly when TryParse does, and otherwise throws
    /// one of <paramref name="parseFailures"/>, or the same exception type TryParse threw
    /// (argument validation).
    /// </summary>
    public static void ParseAgreement<T>(
        string what,
        IEqualityComparer<T> comparer,
        Outcome<T> parse,
        Type[] parseFailures,
        Outcome<(bool Ok, T Value)> tryParse,
        params (string Name, Outcome<(bool Ok, T Value)> Result)[] alternatives)
    {
        var pairs = new PairComparer<T>(comparer);
        foreach (var (name, result) in alternatives)
        {
            That(tryParse.SameAs(result, pairs), $"TryParse {tryParse} != {name} {result} for {what}");
        }

        if (!tryParse.Ok)
        {
            That(parse.ErrorType == tryParse.ErrorType, $"TryParse threw {tryParse} but Parse gave {parse} for {what}");
        }
        else if (tryParse.Value.Ok)
        {
            That(parse.Ok && comparer.Equals(parse.Value!, tryParse.Value.Value), $"TryParse succeeded ({tryParse}) but Parse gave {parse} for {what}");
        }
        else
        {
            That(!parse.Ok && parseFailures.Contains(parse.ErrorType), $"TryParse failed but Parse gave {parse} for {what}");
        }
    }

    public sealed class PairComparer<T>(IEqualityComparer<T> inner) : IEqualityComparer<(bool, T)>
    {
        public bool Equals((bool, T) x, (bool, T) y) => x.Item1 == y.Item1 && (!x.Item1 || inner.Equals(x.Item2, y.Item2));
        public int GetHashCode((bool, T) obj) => 0;
    }

    /// <summary>Equality from a delegate, for types whose Equals is too coarse (DateTime.Kind, decimal scale, ...).</summary>
    public sealed class By<T>(Func<T, T, bool> equals) : IEqualityComparer<T>
    {
        public bool Equals(T? x, T? y) => equals(x!, y!);
        public int GetHashCode(T obj) => 0;
    }

    /// <summary>Stable (unlike string.GetHashCode) hash for deriving fallback values from an input.</summary>
    public static ulong Hash(ReadOnlySpan<byte> data)
    {
        ulong h = 0xCBF29CE484222325;
        foreach (byte b in data)
        {
            h = (h ^ b) * 0x100000001B3;
        }

        return h;
    }

    /// <summary>Printable form of a value for exception messages: strings are escaped and quoted.</summary>
    public static string Show<T>(T value) => value switch
    {
        null => "null",
        string s => Escape(s),
        byte[] b => "0x" + Convert.ToHexString(b.AsSpan(0, Math.Min(b.Length, 64))) + (b.Length > 64 ? "..." : ""),
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString() ?? "",
    };

    public static string Escape(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (char c in s.Length > 200 ? s.Substring(0, 200) : s)
        {
            if (c is >= ' ' and <= '~' and not '"' and not '\\')
            {
                sb.Append(c);
            }
            else
            {
                sb.Append($"\\u{(int)c:X4}");
            }
        }

        return sb.Append(s.Length > 200 ? "\"..." : "\"").ToString();
    }
}

/// <summary>
/// The outcome of an operation that may throw a documented exception: a value, or the exception.
/// Exceptions that <c>allowed</c> rejects are not caught and so surface as crashes.
/// </summary>
internal readonly record struct Outcome<T>(T? Value, Exception? Error)
{
    public bool Ok => Error is null;

    public Type? ErrorType => Error?.GetType();

    public static Outcome<T> Of(Func<T> f, Func<Exception, bool> allowed)
    {
        try
        {
            return new Outcome<T>(f(), null);
        }
        catch (Exception e) when (e is not ConsistencyException && allowed(e))
        {
            return new Outcome<T>(default, e);
        }
    }

    /// <summary>Same success/failure, same value when successful, same exception type when not.</summary>
    public bool SameAs(Outcome<T> other, IEqualityComparer<T>? comparer = null) =>
        Ok == other.Ok && (Ok ? (comparer ?? EqualityComparer<T>.Default).Equals(Value!, other.Value!) : ErrorType == other.ErrorType);

    public override string ToString() => Ok ? Check.Show(Value) : Error!.GetType().Name + ": " + Error.Message;
}
