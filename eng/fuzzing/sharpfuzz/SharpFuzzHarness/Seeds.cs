using System.Resources;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// Seed corpora for the CoreLib targets, in each target's input layout. Written to seeds/&lt;target&gt;
/// with <c>SharpFuzzHarness &lt;target&gt; --write-seeds &lt;dir&gt;</c> (setup.sh does this when the
/// directory is missing).
/// </summary>
internal static class Seeds
{
    public static IEnumerable<byte[]>? For(string target) => target switch
    {
        "number" => Number(),
        "datetime" => DateTime(),
        "guid" => Guid(),
        "version" => Version(),
        "enum" => Enum(),
        "base64" => Base64(),
        "encoding" => Encoding_(),
        "searchvalues" => SearchValues(),
        "compositeformat" => CompositeFormat(),
        "resources" => Resources(),
        _ => null,
    };

    private static byte[] Build(params object[] parts)
    {
        var ms = new MemoryStream();
        foreach (object part in parts)
        {
            switch (part)
            {
                case byte b: ms.WriteByte(b); break;
                case ushort u: ms.Write(BitConverter.GetBytes(u)); break;
                case byte[] bytes: ms.Write(bytes); break;
                case string s: ms.Write(Encoding.UTF8.GetBytes(s)); ms.WriteByte(0); break;
                default: throw new ArgumentException(part.GetType().Name);
            }
        }

        return ms.ToArray();
    }

    private static IEnumerable<byte[]> Number()
    {
        (byte Type, ushort Styles, string Text, string Format)[] cases =
        [
            (4, 0x07, "123", "N2"), (4, 0x07, "  -2147483648 ", "D12"), (4, 0x6F, "1,234,567", "#,##0.00;(#,##0.00);zero"),
            (0, 0x07, "-128", "X"), (1, 0x203, "ff", "x2"), (2, 0x403, "1111000011110000", "B16"), (3, 0x1FF, "$65,535.00", "C"),
            (5, 0xA7, "4.294967295E9", "E3"), (6, 0x07, "-9223372036854775808", "D"), (7, 0x203, "FFFFFFFFFFFFFFFF", "X16"),
            (8, 0x07, "-170141183460469231731687303715884105728", "N0"), (9, 0x6F, "340,282,366,920,938,463,463,374,607,431,768,211,455", "E40"),
            (10, 0x17F, "(42)", "0000"), (11, 0x07, "+0", "P"),
            (12, 0xA7, "65504", "R"), (12, 0xA7, "6.1E-05", "G5"), (13, 0xA7, "3.4028235E+38", "R"), (13, 0x1FF, "-Infinity", "E"),
            (14, 0xA7, "1.7976931348623157E+308", "G17"), (14, 0xA7, "4.9406564584124654E-324", "R"), (14, 0x1FF, "NaN", "F2"),
            (14, 0xA7, "2.2250738585072011e-308", "E16"), (14, 0x2A7, "0.1", "0.###E+0"), (14, 0xE7, "123456789012345678901234567890e-10", "N"),
            (13, 0xA7, "1.00000017881393432617187499", "R"), (12, 0xA7, "0.000030517578125", "R"),
            (15, 0x6F, "79,228,162,514,264,337,593,543,950,335", "C"), (15, 0xA7, "-0.0000000000000000000000000001", "E28"), (15, 0x6F, "1.00", "G"),
            (14, 0x8FFF, "1", ""), (4, 0x07, "1_000", "‰"), (14, 0xA7, "٣", "#'#'"),
        ];
        foreach (var (type, styles, text, format) in cases)
        {
            yield return Build(type, styles, text, format);
        }

        // Fuzzed NumberFormatInfo: every field set.
        yield return Build((byte)0x14, (ushort)0x1FF, (byte)0xFF, (byte)0x2A, (byte)0x93, (byte)3, (byte)2,
            "−", "⁺", "٫", "٬", "€", ",", ".", "¿NaN?", "∞", "-∞", "%", "‰", "/", "1٬234٫5", "N3");
        yield return Build((byte)0x1E, (ushort)0x1FF, (byte)0x0F, (byte)0x00, (byte)0x80, (byte)0, (byte)1, "--", "+", "..", ".", "--1.5", "#,0.00");
    }

    private static IEnumerable<byte[]> DateTime()
    {
        (byte Type, byte Styles, string Text, string Format)[] cases =
        [
            (0, 0x80, "2024-02-29T13:45:07.1234567Z", "O"), (0, 0x07, " 02/29/2024 13:45 ", "MM/dd/yyyy HH:mm"),
            (0, 0x10, "Thu, 29 Feb 2024 13:45:07 GMT", "R"), (0, 0x00, "29 February 2024 1:45 PM", "dd MMMM yyyy h:mm tt"),
            (0, 0x04, "2024 - 02 - 29", "yyyy - MM - dd"), (0, 0x40, "12/31/9999 23:59:59", "G"), (0, 0x08, "13:45:07", "T"),
            (0, 0x00, "20240229134507", "yyyyMMddHHmmss"), (0, 0x00, "A.D. 2024", "gg yyyy"), (0, 0x00, "2024-02-29T13:45:07.1+05:30", "yyyy-MM-ddTHH:mm:ss.FFFFFFFK"),
            (1, 0x00, "2024-02-29T13:45:07+05:30", "yyyy-MM-ddTHH:mm:sszzz"), (1, 0x40, "Feb 29 2024", "MMM dd yyyy"), (1, 0x00, "0001-01-01T00:00:00-14:00", "O"),
            (2, 0x00, "2024-02-29", "yyyy-MM-dd"), (2, 0x07, " Thursday, 29 February 2024 ", "D"),
            (3, 0x00, "23:59:59.9999999", "HH:mm:ss.fffffff"), (3, 0x00, "1:02 PM", "h:mm tt"),
            (4, 0x00, "1.02:03:04.5", "c"), (4, 0x01, "-00:00:01", "g"), (4, 0x00, "10675199.02:48:05.4775807", "G"),
            (4, 0x00, "12:34", "hh\\:mm"), (4, 0x00, "3.04:05", "d\\.hh\\:mm"),
            (0x10, 0x00, "2024-02-29", "O\nyyyy-MM-dd\nd"),
        ];
        foreach (var (type, styles, text, format) in cases)
        {
            yield return Build(type, styles, text, format);
        }

        yield return Build((byte)0x08, (byte)0x00, (byte)0xFF, (byte)0x2B, "vorm.", "nachm.", ".", ":", "dd.MM.yyyy", "dddd, d. MMMM yyyy", "HH:mm", "HH:mm:ss",
            "dddd, d. MMMM yyyy HH:mm:ss", "d. MMMM", "MMMM yyyy", "Januar|Februar|März|April|Mai|Juni|Juli|August|September|Oktober|November|Dezember|", "Jan.|Feb.|März",
            "Sonntag|Montag|Dienstag|Mittwoch|Donnerstag|Freitag|Samstag", "So|Mo|Di|Mi|Do|Fr|Sa", "29.02.2024 13:45", "dd.MM.yyyy HH:mm");
    }

    private static IEnumerable<byte[]> Guid()
    {
        string[] texts =
        [
            "00000000-0000-0000-0000-000000000000", "0123456789abcdef0123456789ABCDEF", "{01234567-89ab-cdef-0123-456789abcdef}",
            "(01234567-89AB-CDEF-0123-456789ABCDEF)", "{0x01234567,0x89ab,0xcdef,{0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef}}",
            "  01234567-89ab-cdef-0123-456789abcdef  ", "{0x1,0x2,0x3,{0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb}}", "ffffffff-ffff-ffff-ffff-ffffffffffff",
        ];
        string[] formats = ["D", "N", "B", "P", "X", "", "d"];
        for (int i = 0; i < texts.Length; i++)
        {
            yield return Build((byte)0, texts[i], formats[i % formats.Length]);
            yield return Build((byte)1, Enumerable.Range(i * 7, 16).Select(x => (byte)(x * 37)).ToArray(), texts[i], formats[(i + 3) % formats.Length]);
        }
    }

    private static IEnumerable<byte[]> Version()
    {
        string[] texts = ["1.0", "1.2.3.4", "2147483647.0.0.0", "1.2.3", " 1 . 2 ", "+1.0", "1.2.3.4.5", "01.002", "1.-1", "4.0.30319.42000"];
        for (int i = 0; i < texts.Length; i++)
        {
            yield return Build(texts[i], texts[(i + 1) % texts.Length]);
        }
    }

    private static IEnumerable<byte[]> Enum()
    {
        (byte Type, string Text, string Format)[] cases =
        [
            (0, "A", "G"), (0, "d", "D"), (0, "10", "X"), (0, " -1 ", "F"), (1, "X, Y", "G"), (1, "XY, High", "F"), (1, "136", "x"),
            (2, "Min", "D"), (3, "A, B, Negative", "F"), (4, "Second", "G"), (4, "zero", "g"), (5, "Bit31, Bit0", "X"), (5, "4294967295", "F"),
            (6, "-9223372036854775808", "D"), (7, "One, High", "F"), (8, "0", "G"), (9, "Zip", "F"), (9, "A, C", "G"), (10, "N1000", "D"),
            (11, "M39", "G"), (12, "F0, F30, Neg", "F"), (13, "Straße", "G"), (14, "Friday", "G"), (15, "Class, Method", "F"),
            (16, "Public, Static", "F"), (17, "RemoveEmptyEntries", "D"), (18, "V1", "G"), (19, "V0, V1", "F"), (20, "V2", "D"),
            (21, "V0, V1", "F"), (18, "b", "G"), (20, "-1", "D"),
        ];
        foreach (var (type, text, format) in cases)
        {
            yield return Build(type, (byte)(type % 3 == 0 ? 1 : 0), BitConverter.GetBytes(0x80000001UL * type), text, format);
        }
    }

    private static IEnumerable<byte[]> Base64()
    {
        (byte Mode, string Payload)[] cases =
        [
            (0, "SGVsbG8gV29ybGQ="), (0, "QQ=="), (0, "QUI="), (0, "QUJD"), (0, " Q U J D "), (0, "QR=="), (0, ""), (0, "===="),
            (0, "AAAA\r\nBBBB\tCCCC DD=="), (0, "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBsb25nZXIgaW5wdXQgdG8gaGl0IHRoZSB2ZWN0b3JpemVkIHBhdGhzIG9mIHRoZSBkZWNvZGVyLg=="),
            (1, "SGVsbG8"), (1, "-_-_"), (1, "AA"), (1, "AAA="), (1, "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBsb25nZXIgaW5wdXQgdG8gaGl0IHRoZSB2ZWN0b3JpemVkIHBhdGhz"),
            (2, "0123456789abcdefABCDEF"), (2, "0"), (2, "zz"), (2, "00112233445566778899AABBCCDDEEFF00112233445566778899aabbccddeeff"),
        ];
        foreach (var (mode, payload) in cases)
        {
            yield return [mode, 3, .. Encoding.ASCII.GetBytes(payload)];
        }

        yield return [4, 5, .. Encoding.Unicode.GetBytes("QUJDÀ==")];
        yield return [3, 1, .. Enumerable.Range(0, 64).Select(i => (byte)(i * 73))];
        yield return [3, 9, 0xFB, 0xFF, 0xBF];
    }

    private static IEnumerable<byte[]> Encoding_()
    {
        byte[][] payloads =
        [
            Encoding.UTF8.GetBytes("Hello, World"),
            Encoding.UTF8.GetBytes("héllo € 𝄞 日本語"),
            [0xC0, 0x80, 0xED, 0xA0, 0x80, 0xF4, 0x90, 0x80, 0x80, 0xE0, 0x80, 0x41, 0xF0, 0x9F, 0x98, 0xE2, 0x82],
            [0xEF, 0xBB, 0xBF, 0xFF, 0xFE, 0x00, 0x00, 0xFE, 0xFF],
            Encoding.Unicode.GetBytes("a\uD800b\uDC00􏿿c"),
            Encoding.ASCII.GetBytes("+AGEAYgBj- +ZeVnLIqe- a+-b +2D3cAA-"),
            Encoding.UTF32.GetBytes("x𝄞") .Concat(new byte[] { 0x00, 0xD8, 0x00, 0x00, 0xFF, 0xFF, 0x11, 0x00, 0x41 }).ToArray(),
        ];
        for (int encoding = 0; encoding < 12; encoding++)
        {
            for (int p = 0; p < payloads.Length; p++)
            {
                int mode = (encoding + p) % 4;
                byte[] header = mode switch
                {
                    2 => Build((byte)encoding, (byte)mode, (byte)(p * 29), (byte)1, "<?>", "¤"),
                    3 => [(byte)encoding, (byte)mode, (byte)(p * 29), 2, .. Encoding.Unicode.GetBytes("[\uD800]"), 0, .. Encoding.Unicode.GetBytes("xyz"), 0],
                    _ => [(byte)encoding, (byte)mode, (byte)(p * 29)],
                };
                yield return [.. header, .. payloads[p]];
            }
        }
    }

    private static IEnumerable<byte[]> SearchValues()
    {
        byte[] text = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs! 0123456789 <tag attr=\"v\">&amp;</tag>\r\n");
        yield return [0, 0, 5, .. "aeiou"u8, .. text];
        yield return [0, 3, 3, .. "<>&"u8, .. text];
        yield return [0, 1, 1, .. "\n"u8, .. text];
        yield return [0, 0, 20, .. Enumerable.Range(0, 20).Select(i => (byte)(i * 13 + 100)), .. text, .. Enumerable.Range(0, 200).Select(i => (byte)i)];
        yield return [3, 2, 4, .. "\t\r\n "u8, .. text];
        yield return [1, 1, 3, .. Encoding.Unicode.GetBytes("é€日"), .. Encoding.Unicode.GetBytes("résumé costs 5€, 日本 " + new string('x', 70) + "€")];
        yield return [1, 0, 6, .. Encoding.Unicode.GetBytes("abcXYZ"), .. Encoding.Unicode.GetBytes(new string('.', 100) + "Z")];
        yield return Build((byte)0x08, (byte)0, (byte)3, "fox", "dog", "lazy", "The quick brown fox jumps over the lazy dog");
        yield return Build((byte)0x0C, (byte)1, (byte)4, "HELLO", "wörld", "ſ", "K", "say hello to the WÖRLD, straße, kelvin");
        yield return Build((byte)0x0A, (byte)0, (byte)2, "", "x", "anything");
        yield return Build((byte)0x0E, (byte)0, (byte)12, "if", "else", "while", "for", "return", "switch", "case", "break", "continue", "goto", "do", "try",
            "public static int Main() { while (true) { if (x) break; } return 0; }");
    }

    private static IEnumerable<byte[]> CompositeFormat()
    {
        (byte Header, byte[] Kinds, string Format, string[] Args)[] cases =
        [
            (1, [0], "{0}", ["hello"]),
            (3, [2, 3, 0], "{0,-10:N2}|{1:E3}|{{literal}}|{2,5}", ["42", "3.14159", "abc"]),
            (2, [5, 11], "{0:yyyy-MM-dd HH:mm} took {1:c}", ["", "x"]),
            (4, [6, 7, 1, 12], "{0:custom}{1,3:fmt}[{2}]{3:D}", ["echo", "span", "", ""]),
            (0, [], "no holes {{ }}", []),
            (2, [2, 2], "{1} {0} {1,-3} { 0 } {0 ,2}", ["1", "2"]),
            (1, [4], "{0:C}", ["1234.5"]),
            (9, [2, 0], "{0:X8} {1}", ["255", "custom"]),
            (0x11, [3], "{0:N3}", ["1234567.891"]),
            (5, [8, 9, 10, 13, 14], "{0}{1}{2:X}{3:B}{4}", ["", "c", "", "", "arr"]),
            (1, [15], "{0,1000001}", ["1"]),
            (2, [2, 0], "{0:}{1:{{}}}", ["5", "s"]),
        ];
        foreach (var (header, kinds, format, args) in cases)
        {
            var parts = new List<object> { header, kinds };
            if ((header & 0x10) != 0)
            {
                parts.AddRange([(byte)0x0C, (byte)0, (byte)0, "'", " "]);
            }

            parts.Add(format);
            parts.AddRange(args);
            yield return Build([.. parts]);
        }
    }

    private static IEnumerable<byte[]> Resources()
    {
        yield return Write(_ => { });
        yield return Write(w => w.AddResource("Greeting", "Hello, World"));
        yield return Write(w =>
        {
            w.AddResource("String", "text with ünïcödé");
            w.AddResource("Empty", "");
            w.AddResource("Null", (string?)null);
            w.AddResource("Int", 42);
            w.AddResource("Long", long.MinValue);
            w.AddResource("Bool", true);
            w.AddResource("Char", 'x');
            w.AddResource("Byte", (byte)200);
            w.AddResource("SByte", (sbyte)-5);
            w.AddResource("Short", (short)-300);
            w.AddResource("UShort", (ushort)60000);
            w.AddResource("UInt", uint.MaxValue);
            w.AddResource("ULong", ulong.MaxValue);
            w.AddResource("Single", 1.5f);
            w.AddResource("Double", Math.PI);
            w.AddResource("Decimal", 79228162514264337593543950335m);
            w.AddResource("DateTime", new System.DateTime(2024, 2, 29, 13, 45, 7, DateTimeKind.Utc));
            w.AddResource("TimeSpan", TimeSpan.FromHours(-1.5));
            w.AddResource("Bytes", new byte[] { 0, 1, 2, 3, 255 });
            w.AddResource("Stream", new MemoryStream([9, 8, 7]), closeAfterWrite: true);
        });
        yield return Write(w =>
        {
            for (int i = 0; i < 40; i++)
            {
                w.AddResource($"Key{i:D3}", new string((char)('a' + i % 26), i));
            }
        });
        yield return Write(w =>
        {
            w.AddResource("key", "lower");
            w.AddResource("Kéy", "accent");
            w.AddResource("KÉY2", "upper accent");
        });
    }

    private static byte[] Write(Action<ResourceWriter> fill)
    {
        var ms = new MemoryStream();
        using (var writer = new ResourceWriter(ms))
        {
            fill(writer);
            writer.Generate();
            return ms.ToArray();
        }
    }
}
