#nullable disable warnings
using System.Buffers;
using System.Buffers.Binary;
using System.Globalization;
using System.IO.Hashing;
using System.Text;
using System.Text.Unicode;

namespace SharpFuzzHarness;

/// <summary>
/// Memory safety of the span APIs whose implementations read and write through Unsafe.ReadUnaligned /
/// WriteUnaligned and vector loads (Latin1Utility, Ascii.Utility, Utf8Utility.Transcoding,
/// Ordinal / Marvin hashing, HexConverter, BitConverter, SpanHelpers, Frozen string hashing, XxHash).
/// Every input and output span is exactly sized and sits against a guard page (see <see cref="Guarded"/>),
/// so touching a single element outside it faults; results are compared with the same call on
/// ordinary arrays or with a plain loop.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     operation; byte 1 placement bits (inputs / outputs at the start of a slot instead of the end)
///   rest       the data (bytes, or UTF-16LE text for char operations)
/// </remarks>
public static class UnsafeTextTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte op = input.Byte();
        byte place = input.Byte();
        byte[] bytes = input.Rest().ToArray();
        if (bytes.Length > 8192)
        {
            return;
        }

        char[] chars = Encoding.Unicode.GetString(bytes, 0, bytes.Length & ~1).ToCharArray();
        bool inStart = (place & 1) != 0, outStart = (place & 2) != 0;
        ReadOnlySpan<byte> b = Guarded.Copy<byte>(bytes, inStart);
        ReadOnlySpan<char> c = Guarded.Copy<char>(chars, inStart);
        string what = $"op {op % 16}, {bytes.Length} bytes 0x{Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 48)))}{(bytes.Length > 48 ? "..." : "")}, placement {place & 3}";

        switch (op % 16)
        {
            case 0: // Latin-1 (Latin1Utility)
            {
                Span<char> dest = Out<char>(bytes.Length, outStart);
                Check.Equal(bytes.Length, Encoding.Latin1.GetChars(b, dest), $"Latin1.GetChars count: {what}");
                Check.That(dest.SequenceEqual(bytes.Select(x => (char)x).ToArray()), $"Latin1.GetChars: {what}");
                Span<byte> back = Out<byte>(Encoding.Latin1.GetByteCount(chars), outStart);
                Check.Equal(back.Length, Encoding.Latin1.GetBytes(c, back), $"Latin1.GetBytes count: {what}");
                Check.That(back.SequenceEqual(Encoding.Latin1.GetBytes(chars)), $"Latin1.GetBytes: {what}");
                Check.Equal(Encoding.Latin1.GetByteCount(chars), Encoding.Latin1.GetByteCount(c), $"Latin1.GetByteCount: {what}");
                break;
            }

            case 1: // ASCII (Ascii.Utility)
            {
                Span<char> dest = Out<char>(bytes.Length, outStart);
                Check.Equal(bytes.Length, Encoding.ASCII.GetChars(b, dest), $"ASCII.GetChars count: {what}");
                Check.That(dest.SequenceEqual(Encoding.ASCII.GetChars(bytes)), $"ASCII.GetChars: {what}");
                Span<byte> back = Out<byte>(Encoding.ASCII.GetByteCount(chars), outStart);
                Check.Equal(back.Length, Encoding.ASCII.GetBytes(c, back), $"ASCII.GetBytes count: {what}");
                Check.That(back.SequenceEqual(Encoding.ASCII.GetBytes(chars)), $"ASCII.GetBytes: {what}");
                Check.Equal(bytes.All(x => x < 0x80), Ascii.IsValid(b), $"Ascii.IsValid(bytes): {what}");
                Check.Equal(chars.All(x => x < 0x80), Ascii.IsValid(c), $"Ascii.IsValid(chars): {what}");
                break;
            }

            case 2: // Ascii case conversion and comparison
            {
                Span<byte> upper = Out<byte>(bytes.Length, outStart);
                OperationStatus status = Ascii.ToUpper(b, upper, out int written);
                int valid = Array.FindIndex(bytes, x => x >= 0x80);
                int expectedWritten = valid < 0 ? bytes.Length : valid;
                Check.That(written == expectedWritten && status == (valid < 0 ? OperationStatus.Done : OperationStatus.InvalidData), $"Ascii.ToUpper {status} {written}: {what}");
                Check.That(upper[..written].SequenceEqual(bytes.AsSpan(0, written).ToArray().Select(x => x is >= (byte)'a' and <= (byte)'z' ? (byte)(x - 32) : x).ToArray()), $"Ascii.ToUpper: {what}");
                Span<char> lower = Out<char>(chars.Length, outStart);
                Ascii.ToLower(c, lower, out int lowered);
                Check.That(lower[..lowered].SequenceEqual(chars.AsSpan(0, lowered).ToArray().Select(x => x is >= 'A' and <= 'Z' ? (char)(x + 32) : x).ToArray()), $"Ascii.ToLower: {what}");
                Span<char> inPlace = Out<char>(chars.Length, outStart);
                c.CopyTo(inPlace);
                Ascii.ToUpperInPlace(inPlace, out _);
                int half = bytes.Length / 2;
                ReadOnlySpan<byte> left = Guarded.Copy<byte>(bytes.AsSpan(0, half), inStart), right = Guarded.Copy<byte>(bytes.AsSpan(half, half), !inStart);
                bool asciiBoth = bytes.AsSpan(0, 2 * half).IndexOfAnyInRange((byte)0x80, (byte)0xFF) < 0;
                bool expectedEquals = Encoding.Latin1.GetString(bytes, 0, half).Equals(Encoding.Latin1.GetString(bytes, half, half), StringComparison.OrdinalIgnoreCase);
                if (asciiBoth)
                {
                    Check.Equal(expectedEquals, Ascii.EqualsIgnoreCase(left, right), $"Ascii.EqualsIgnoreCase: {what}");
                }

                _ = Ascii.Equals(left, right);
                _ = Ascii.Trim(b);
                _ = Ascii.Trim(c);
                break;
            }

            case 3: // UTF-8 <-> UTF-16 (Utf8Utility.Transcoding)
            {
                string reference = Encoding.UTF8.GetString(bytes);
                Span<char> dest = Out<char>(reference.Length, outStart);
                OperationStatus s1 = Utf8.ToUtf16(b, dest, out int read, out int wrote);
                Check.That(s1 == OperationStatus.Done && read == bytes.Length && wrote == reference.Length && dest.SequenceEqual(reference), $"Utf8.ToUtf16 {s1} {read} {wrote}: {what}");
                Check.Equal(reference.Length, Encoding.UTF8.GetCharCount(b), $"UTF8.GetCharCount: {what}");
                byte[] encoded = Encoding.UTF8.GetBytes(chars);
                Span<byte> back = Out<byte>(encoded.Length, outStart);
                OperationStatus s2 = Utf8.FromUtf16(c, back, out read, out wrote);
                Check.That(s2 == OperationStatus.Done && wrote == encoded.Length && back.SequenceEqual(encoded), $"Utf8.FromUtf16 {s2} {wrote}: {what}");
                Check.Equal(encoded.Length, Encoding.UTF8.GetByteCount(c), $"UTF8.GetByteCount: {what}");
                Check.Equal(System.Text.Unicode.Utf8.IsValid(bytes), Utf8.IsValid(b), $"Utf8.IsValid: {what}");
                break;
            }

            case 4: // UTF-16 / UTF-32 encodings
            {
                foreach (Encoding enc in (Encoding[])[Encoding.Unicode, Encoding.BigEndianUnicode, Encoding.UTF32])
                {
                    string reference = enc.GetString(bytes);
                    Span<char> dest = Out<char>(reference.Length, outStart);
                    Check.Equal(reference.Length, enc.GetChars(b, dest), $"{enc.WebName}.GetChars count: {what}");
                    Check.That(dest.SequenceEqual(reference), $"{enc.WebName}.GetChars: {what}");
                    byte[] encoded = enc.GetBytes(chars);
                    Span<byte> back = Out<byte>(encoded.Length, outStart);
                    Check.Equal(encoded.Length, enc.GetBytes(c, back), $"{enc.WebName}.GetBytes count: {what}");
                    Check.That(back.SequenceEqual(encoded), $"{enc.WebName}.GetBytes: {what}");
                }

                break;
            }

            case 5: // Marvin hashing, ordinal ignore-case hashing and comparisons
            {
                string s = new(chars);
                Check.Equal(s.GetHashCode(), string.GetHashCode(c), $"string.GetHashCode(span): {what}");
                Check.Equal(s.GetHashCode(StringComparison.OrdinalIgnoreCase), string.GetHashCode(c, StringComparison.OrdinalIgnoreCase), $"GetHashCode(span, OrdinalIgnoreCase): {what}");
                int half = chars.Length / 2;
                string l = s[..half], r = s[half..(2 * half)];
                ReadOnlySpan<char> lc = Guarded.Copy<char>(l, inStart), rc = Guarded.Copy<char>(r, !inStart);
                Check.Equal(string.Equals(l, r, StringComparison.OrdinalIgnoreCase), lc.Equals(rc, StringComparison.OrdinalIgnoreCase), $"Equals OrdinalIgnoreCase: {what}");
                Check.Equal(Math.Sign(string.Compare(l, r, StringComparison.OrdinalIgnoreCase)), Math.Sign(lc.CompareTo(rc, StringComparison.OrdinalIgnoreCase)), $"CompareTo OrdinalIgnoreCase: {what}");
                Check.Equal(l.StartsWith(r[..Math.Min(r.Length, 5)], StringComparison.OrdinalIgnoreCase), lc.StartsWith(rc[..Math.Min(rc.Length, 5)], StringComparison.OrdinalIgnoreCase), $"StartsWith OrdinalIgnoreCase: {what}");
                Check.Equal(l.IndexOf(r[..Math.Min(r.Length, 3)], StringComparison.OrdinalIgnoreCase), lc.IndexOf(rc[..Math.Min(rc.Length, 3)], StringComparison.OrdinalIgnoreCase), $"IndexOf OrdinalIgnoreCase: {what}");
                Check.Equal(l.GetHashCode(), string.GetHashCode(lc), $"GetHashCode(half): {what}");
                break;
            }

            case 6: // hex (HexConverter)
            {
                string hex = Convert.ToHexString(bytes);
                Check.Equal(hex, Convert.ToHexString(b), $"ToHexString(span): {what}");
                Span<char> hexChars = Out<char>(bytes.Length * 2, outStart);
                Check.That(Convert.TryToHexStringLower(b, hexChars, out int n) && n == hexChars.Length && hexChars.SequenceEqual(hex.ToLowerInvariant()), $"TryToHexStringLower: {what}");
                string text = new(chars);
                var parsed = Outcome<byte[]>.Of(() => Convert.FromHexString(text), e => e is FormatException);
                Span<byte> dest = Out<byte>(chars.Length / 2, outStart);
                OperationStatus status = Convert.FromHexString(c, dest, out int consumed, out int produced);
                Check.That(!parsed.Ok || status == OperationStatus.Done && dest[..produced].SequenceEqual(parsed.Value), $"FromHexString(span) {status} vs {parsed}: {what}");
                Span<byte> utf8Dest = Out<byte>(bytes.Length / 2, outStart);
                _ = Convert.FromHexString(b, utf8Dest, out _, out _);
                break;
            }

            case 7: // BitConverter / BinaryPrimitives on exactly sized spans
            {
                for (int i = 0; i + 16 <= bytes.Length && i < 64; i += 3)
                {
                    ReadOnlySpan<byte> s2 = Guarded.Copy<byte>(bytes.AsSpan(i, 2), inStart), s4 = Guarded.Copy<byte>(bytes.AsSpan(i, 4), inStart),
                        s8 = Guarded.Copy<byte>(bytes.AsSpan(i, 8), inStart), s16 = Guarded.Copy<byte>(bytes.AsSpan(i, 16), !inStart);
                    Check.Equal(BitConverter.ToInt16(bytes, i), BitConverter.ToInt16(s2), $"ToInt16: {what}");
                    Check.Equal(BitConverter.ToInt32(bytes, i), BitConverter.ToInt32(s4), $"ToInt32: {what}");
                    Check.Equal(BitConverter.ToInt64(bytes, i), BitConverter.ToInt64(s8), $"ToInt64: {what}");
                    Check.Equal(BitConverter.ToUInt128(bytes.AsSpan(i, 16)), BitConverter.ToUInt128(s16), $"ToUInt128: {what}");
                    Check.Equal(BinaryPrimitives.ReadInt64BigEndian(bytes.AsSpan(i)), BinaryPrimitives.ReadInt64BigEndian(s8), $"ReadInt64BigEndian: {what}");
                    Check.Equal(BinaryPrimitives.ReadUInt128BigEndian(bytes.AsSpan(i)), BinaryPrimitives.ReadUInt128BigEndian(s16), $"ReadUInt128BigEndian: {what}");
                    Span<byte> w8 = Out<byte>(8, outStart);
                    Check.That(BitConverter.TryWriteBytes(w8, BitConverter.ToDouble(s8)) && w8.SequenceEqual(s8), $"TryWriteBytes(double): {what}");
                }

                break;
            }

            case 8: // SpanHelpers searches (bytes)
            {
                byte needle = bytes.Length > 0 ? bytes[^1] : (byte)0;
                ReadOnlySpan<byte> needles = Guarded.Copy<byte>(bytes.AsSpan(0, Math.Min(3, bytes.Length)), !inStart);
                Check.Equal(Array.IndexOf(bytes, needle), b.IndexOf(needle), $"IndexOf(byte): {what}");
                Check.Equal(Array.LastIndexOf(bytes, needle), b.LastIndexOf(needle), $"LastIndexOf(byte): {what}");
                Check.Equal(bytes.Count(x => x == needle), b.Count(needle), $"Count(byte): {what}");
                Check.Equal(bytes.AsSpan().IndexOf(needles.ToArray()), b.IndexOf(needles), $"IndexOf(sequence): {what}");
                Check.Equal(bytes.AsSpan().LastIndexOf(needles.ToArray()), b.LastIndexOf(needles), $"LastIndexOf(sequence): {what}");
                Check.Equal(bytes.AsSpan().IndexOfAny(needles.ToArray()), b.IndexOfAny(needles), $"IndexOfAny: {what}");
                Check.Equal(bytes.AsSpan().IndexOfAnyExcept(needles.ToArray()), b.IndexOfAnyExcept(needles), $"IndexOfAnyExcept: {what}");
                int half = bytes.Length / 2;
                ReadOnlySpan<byte> l = Guarded.Copy<byte>(bytes.AsSpan(0, half), inStart), r = Guarded.Copy<byte>(bytes.AsSpan(half, half), !inStart);
                Check.Equal(bytes.AsSpan(0, half).SequenceEqual(bytes.AsSpan(half, half)), l.SequenceEqual(r), $"SequenceEqual: {what}");
                Check.Equal(Math.Sign(bytes.AsSpan(0, half).ToArray().AsSpan().SequenceCompareTo(bytes.AsSpan(half, half).ToArray())), Math.Sign(l.SequenceCompareTo(r)), $"SequenceCompareTo: {what}");
                Check.Equal(bytes.AsSpan(0, half).ToArray().AsSpan().CommonPrefixLength(bytes.AsSpan(half, half).ToArray()), l.CommonPrefixLength(r), $"CommonPrefixLength: {what}");
                break;
            }

            case 9: // SpanHelpers searches (chars)
            {
                char needle = chars.Length > 0 ? chars[^1] : 'a';
                ReadOnlySpan<char> needles = Guarded.Copy<char>(chars.AsSpan(0, Math.Min(4, chars.Length)), !inStart);
                Check.Equal(Array.IndexOf(chars, needle), c.IndexOf(needle), $"IndexOf(char): {what}");
                Check.Equal(Array.LastIndexOf(chars, needle), c.LastIndexOf(needle), $"LastIndexOf(char): {what}");
                Check.Equal(chars.AsSpan().IndexOf(needles.ToArray()), c.IndexOf(needles), $"IndexOf(chars): {what}");
                Check.Equal(chars.AsSpan().IndexOfAny(needles.ToArray()), c.IndexOfAny(needles), $"IndexOfAny(chars): {what}");
                Check.Equal(chars.AsSpan().IndexOfAnyInRange('0', '9'), c.IndexOfAnyInRange('0', '9'), $"IndexOfAnyInRange: {what}");
                Check.Equal(chars.AsSpan().LastIndexOfAnyExcept(needles.ToArray()), c.LastIndexOfAnyExcept(needles), $"LastIndexOfAnyExcept: {what}");
                Check.Equal(new string(chars).Contains(new string(needles), StringComparison.Ordinal), c.IndexOf(needles) >= 0, $"Contains(chars): {what}");
                break;
            }

            case 10: // copies, fills, reversal (SpanHelpers.ByteMemOps / Memmove)
            {
                Span<byte> dest = Out<byte>(bytes.Length, outStart);
                b.CopyTo(dest);
                Check.That(dest.SequenceEqual(bytes), $"CopyTo: {what}");
                dest.Reverse();
                Check.That(dest.SequenceEqual(bytes.Reverse().ToArray()), $"Reverse: {what}");
                dest.Fill(0xA5);
                Check.That(dest.IndexOfAnyExcept((byte)0xA5) < 0, $"Fill: {what}");
                dest.Clear();
                Check.That(dest.IndexOfAnyExcept((byte)0) < 0, $"Clear: {what}");
                Span<char> cdest = Out<char>(chars.Length, outStart);
                c.CopyTo(cdest);
                cdest.Reverse();
                Check.That(cdest.SequenceEqual(chars.Reverse().ToArray()), $"Reverse(chars): {what}");
                cdest.Replace('a', 'b');
                break;
            }

            case 11: // parsers over exactly sized spans (a peek past the end faults)
            {
                string text = new(chars);
                CultureInfo inv = CultureInfo.InvariantCulture;
                Check.Equal(long.TryParse(text, NumberStyles.Any, inv, out long l1), long.TryParse(c, NumberStyles.Any, inv, out long l2) && l1 == l2, $"long.TryParse(span): {what}");
                Check.Equal(double.TryParse(text, NumberStyles.Any, inv, out double d1), double.TryParse(c, NumberStyles.Any, inv, out double d2), $"double.TryParse(span): {what}");
                Check.Equal(decimal.TryParse(text, NumberStyles.Any, inv, out decimal m1), decimal.TryParse(c, NumberStyles.Any, inv, out decimal m2), $"decimal.TryParse(span): {what}");
                Check.Equal(Guid.TryParse(text, out Guid g1), Guid.TryParse(c, out Guid g2) && g1 == g2, $"Guid.TryParse(span): {what}");
                Check.Equal(DateTime.TryParse(text, inv, DateTimeStyles.None, out DateTime t1), DateTime.TryParse(c, inv, DateTimeStyles.None, out DateTime t2), $"DateTime.TryParse(span): {what}");
                Check.Equal(TimeSpan.TryParse(text, inv, out TimeSpan s1), TimeSpan.TryParse(c, inv, out TimeSpan s2), $"TimeSpan.TryParse(span): {what}");
                Check.Equal(Version.TryParse(text, out Version v1), Version.TryParse(c, out Version v2), $"Version.TryParse(span): {what}");
                // UTF-8 overloads over the raw bytes.
                Check.Equal(long.TryParse(Encoding.UTF8.GetString(bytes), NumberStyles.Any, inv, out long u1), long.TryParse(b, NumberStyles.Any, inv, out long u2) && u1 == u2, $"long.TryParse(utf8): {what}");
                _ = double.TryParse(b, NumberStyles.Any, inv, out _);
                _ = Guid.TryParse(b, out _);
                _ = System.Buffers.Text.Utf8Parser.TryParse(b, out decimal _, out _);
                _ = System.Buffers.Text.Utf8Parser.TryParse(b, out DateTimeOffset _, out _, 'R');
                break;
            }

            default: // XxHash / Crc (XxHashShared reads through Unsafe.ReadUnaligned)
            {
                Check.Equal(XxHash3.HashToUInt64(bytes), XxHash3.HashToUInt64(b), $"XxHash3: {what}");
                Check.Equal(XxHash128.HashToUInt128(bytes), XxHash128.HashToUInt128(b), $"XxHash128: {what}");
                Check.Equal(XxHash64.HashToUInt64(bytes), XxHash64.HashToUInt64(b), $"XxHash64: {what}");
                Check.Equal(XxHash32.HashToUInt32(bytes), XxHash32.HashToUInt32(b), $"XxHash32: {what}");
                Check.Equal(Crc32.HashToUInt32(bytes), Crc32.HashToUInt32(b), $"Crc32: {what}");
                Check.Equal(Crc64.HashToUInt64(bytes), Crc64.HashToUInt64(b), $"Crc64: {what}");
                var h = new XxHash3();
                for (int i = 0; i < bytes.Length; i += 1 + i % 97)
                {
                    int n = Math.Min(bytes.Length - i, 1 + i % 97);
                    h.Append(Guarded.Copy<byte>(bytes.AsSpan(i, n), inStart));
                }

                Check.Equal(XxHash3.HashToUInt64(bytes), h.GetCurrentHashAsUInt64(), $"XxHash3 in guarded chunks: {what}");
                break;
            }
        }
    }

    private static Span<T> Out<T>(int length, bool atStart) => Guarded.Copy<T>(new T[length], atStart);
}
