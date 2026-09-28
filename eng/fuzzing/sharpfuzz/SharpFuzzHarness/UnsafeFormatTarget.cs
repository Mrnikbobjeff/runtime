#nullable disable warnings
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Unicode;

namespace SharpFuzzHarness;

/// <summary>
/// Memory safety of formatting into caller-provided spans (ISpanFormattable / IUtf8SpanFormattable
/// TryFormat, the interpolated-string TryWrite handlers), whose implementations write through
/// Unsafe / pointers after a length check. The destination is exactly as long as the text, or shorter,
/// and sits against a guard page (see <see cref="Guarded"/>), so a write past it faults.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     type; byte 1: bit 0 destination at the start of a slot; bits 1-3 how much shorter the
///              short destinations are
///   segment    the format string
///   rest       the value's bytes
/// Checks: with room, TryFormat succeeds and writes exactly ToString's text (UTF-16) or its UTF-8;
/// with less room it returns false; nothing is written outside the destination.
/// </remarks>
public static class UnsafeFormatTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte type = input.Byte();
        byte flags = input.Byte();
        string format = input.Segment();
        if (format.Length > 64)
        {
            return;
        }

        ReadOnlySpan<byte> v = input.Rest();
        Span<byte> raw = stackalloc byte[16];
        raw.Clear();
        v[..Math.Min(v.Length, 16)].CopyTo(raw);
        long l = BitConverter.ToInt64(raw);
        switch (type % 20)
        {
            case 0: Format((int)l, format, flags); break;
            case 1: Format(l, format, flags); break;
            case 2: Format((ulong)l, format, flags); break;
            case 3: Format((short)l, format, flags); break;
            case 4: Format((byte)l, format, flags); break;
            case 5: Format(BitConverter.ToInt128(raw), format, flags); break;
            case 6: Format(BitConverter.ToUInt128(raw), format, flags); break;
            case 7: Format(BitConverter.ToDouble(raw), format, flags); break;
            case 8: Format(BitConverter.ToSingle(raw), format, flags); break;
            case 9: Format(BitConverter.ToHalf(raw), format, flags); break;
            case 10: Format(Decimal(raw), format, flags); break;
            case 11: Format(new Guid(raw), format, flags); break;
            case 12: Format(new DateTime(Math.Abs(l % DateTime.MaxValue.Ticks), (DateTimeKind)(raw[8] % 3)), format, flags); break;
            case 13: Format(new DateTimeOffset(Math.Abs(l % (DateTime.MaxValue.Ticks - 2 * TimeSpan.TicksPerDay)) + TimeSpan.TicksPerDay, TimeSpan.FromMinutes((sbyte)raw[8] * 5 % 840)), format, flags); break;
            case 14: Format(new TimeSpan(l), format, flags); break;
            case 15: Format(DateOnly.FromDayNumber((int)((ulong)l % 3652059)), format, flags); break;
            case 16: Format(new TimeOnly((long)((ulong)l % (ulong)TimeSpan.TicksPerDay)), format, flags); break;
            case 17: Format(new BigInteger(v.Length > 64 ? v[..64] : v), format, flags); break;
            case 18: Format(new Version(raw[0] % 4 == 0 ? 0 : (int)(l & 0x7FFF), raw[1], raw[2] % 3 == 0 ? 0 : raw[3], raw[4]), format.Length == 0 ? "" : ((raw[5] % 5).ToString()), flags); break;
            default: Interpolated(l, BitConverter.ToDouble(raw[8..]), format, flags); break;
        }
    }

    private static decimal Decimal(ReadOnlySpan<byte> raw)
    {
        int flags = (raw[12] & 0x80) << 24 | (raw[13] % 29) << 16;
        return new decimal([BitConverter.ToInt32(raw), BitConverter.ToInt32(raw[4..]), BitConverter.ToInt32(raw[8..]), flags]);
    }

    private static void Format<T>(T value, string format, byte flags)
        where T : ISpanFormattable, IUtf8SpanFormattable
    {
        string text;
        try
        {
            text = value.ToString(format, CultureInfo.InvariantCulture);
        }
        catch (FormatException)
        {
            // An invalid format must fail the same way through TryFormat (and write nothing out of bounds).
            var e = Outcome<bool>.Of(() => { bool ok = value.TryFormat(Guarded.Copy<char>(new char[8], (flags & 1) != 0), out _, format, CultureInfo.InvariantCulture); return ok; }, x => x is FormatException);
            Check.That(!e.Ok || !e.Value, $"{typeof(T).Name} TryFormat with an invalid format {Check.Show(format)} succeeded");
            return;
        }

        if (text.Length > 4096)
        {
            return;
        }

        string what = $"{typeof(T).Name} {Check.Show(text)} format {Check.Show(format)}";
        bool atStart = (flags & 1) != 0;
        int shorter = 1 + (flags >> 1 & 7);

        // UTF-16: exactly sized, then too short.
        Span<char> exact = Guarded.Copy<char>(new char[text.Length], atStart);
        Check.That(value.TryFormat(exact, out int written, format, CultureInfo.InvariantCulture) && written == text.Length && exact.SequenceEqual(text),
            $"TryFormat into exactly {text.Length} chars wrote {written}: {what}");
        foreach (int size in (int[])[text.Length - 1, text.Length - shorter, 0])
        {
            if (size < 0 || size >= text.Length)
            {
                continue;
            }

            Span<char> small = Guarded.Copy<char>(new char[size], atStart);
            Check.That(!value.TryFormat(small, out _, format, CultureInfo.InvariantCulture), $"TryFormat into {size} < {text.Length} chars succeeded: {what}");
        }

        // UTF-8.
        byte[] utf8 = Encoding.UTF8.GetBytes(text);
        Span<byte> exact8 = Guarded.Copy<byte>(new byte[utf8.Length], !atStart);
        Check.That(value.TryFormat(exact8, out written, format, CultureInfo.InvariantCulture) && written == utf8.Length && exact8.SequenceEqual(utf8),
            $"UTF-8 TryFormat into exactly {utf8.Length} bytes wrote {written}: {what}");
        foreach (int size in (int[])[utf8.Length - 1, utf8.Length - shorter, 0])
        {
            if (size < 0 || size >= utf8.Length)
            {
                continue;
            }

            Span<byte> small = Guarded.Copy<byte>(new byte[size], !atStart);
            Check.That(!value.TryFormat(small, out _, format, CultureInfo.InvariantCulture), $"UTF-8 TryFormat into {size} < {utf8.Length} bytes succeeded: {what}");
        }
    }

    /// <summary>The TryWrite interpolated-string handlers (MemoryExtensions.TryWrite, Utf8.TryWrite) into guarded spans.</summary>
    private static void Interpolated(long l, double d, string format, byte flags)
    {
        string text = string.Create(CultureInfo.InvariantCulture, $"[{l,-12}|{d:E3}|{(int)l:X}|{format}|{d,20:F2}]");
        bool atStart = (flags & 1) != 0;
        for (int size = text.Length; size >= Math.Max(0, text.Length - 3); size--)
        {
            Span<char> dest = Guarded.Copy<char>(new char[size], atStart);
            bool ok = dest.TryWrite(CultureInfo.InvariantCulture, $"[{l,-12}|{d:E3}|{(int)l:X}|{format}|{d,20:F2}]", out int written);
            Check.That(ok == (size == text.Length) && (!ok || written == size && dest.SequenceEqual(text)), $"TryWrite into {size} chars of {Check.Show(text)}: ok {ok}, written {written}");
            byte[] utf8 = Encoding.UTF8.GetBytes(text);
            Span<byte> dest8 = Guarded.Copy<byte>(new byte[Math.Max(0, utf8.Length - (text.Length - size))], !atStart);
            bool ok8 = Utf8.TryWrite(dest8, CultureInfo.InvariantCulture, $"[{l,-12}|{d:E3}|{(int)l:X}|{format}|{d,20:F2}]", out int written8);
            Check.That(ok8 == (dest8.Length == utf8.Length) && (!ok8 || dest8.SequenceEqual(utf8)), $"Utf8.TryWrite into {dest8.Length} bytes of {Check.Show(text)}: ok {ok8}, written {written8}");
        }
    }
}
