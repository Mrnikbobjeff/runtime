#nullable disable warnings
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// PEM and ASN.1 readers that copy into caller spans, over guarded memory (see <see cref="Guarded"/>):
/// PemEncoding.TryFind (chars and UTF-8) and TryWrite into exactly sized destinations, with a round trip;
/// AsnDecoder.TryReadOctetString / TryReadBitString / TryReadCharacterString into exactly sized and short
/// destinations, compared with the array-returning ReadOctetString / ReadBitString / ReadCharacterString.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     operation (bit 0: PEM or ASN.1) and rule set; byte 1 tag / placement
///   rest       the text or the encoded value
/// </remarks>
public static class UnsafeDerTarget
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

        bool atStart = (place & 1) != 0;
        string what = $"op {op:X2} place {place:X2}, {bytes.Length} bytes 0x{Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 48)))}";
        if ((op & 1) == 0)
        {
            Pem(bytes, atStart, what);
        }
        else
        {
            Asn((AsnEncodingRules)((op >> 1 & 3) % 3), place, bytes, atStart, what);
        }
    }

    private static Span<T> Out<T>(int length, bool atStart) => Guarded.Copy<T>(new T[length], atStart);

    private static void Pem(byte[] bytes, bool atStart, string what)
    {
        string text = Encoding.UTF8.GetString(bytes);
        ReadOnlySpan<char> chars = Guarded.Copy<char>(text.AsSpan(), atStart);
        bool found = PemEncoding.TryFind(text, out PemFields fields);
        bool spanFound = PemEncoding.TryFind(chars, out PemFields spanFields);
        Check.That(found == spanFound && (!found || fields.Location.Equals(spanFields.Location) && fields.Label.Equals(spanFields.Label) && fields.Base64Data.Equals(spanFields.Base64Data) && fields.DecodedDataLength == spanFields.DecodedDataLength),
            $"PemEncoding.TryFind(guarded) {spanFound} vs (string) {found}: {what}");
        if (Encoding.UTF8.GetByteCount(text) == bytes.Length && !text.Contains('�'))
        {
            ReadOnlySpan<byte> utf8 = Guarded.Copy<byte>(bytes, !atStart);
            bool utf8Found = PemEncoding.TryFindUtf8(utf8, out PemFields utf8Fields);
            if (text.All(char.IsAscii))
            {
                Check.That(utf8Found == found && (!found || utf8Fields.Location.Equals(fields.Location) && utf8Fields.Label.Equals(fields.Label) && utf8Fields.DecodedDataLength == fields.DecodedDataLength),
                    $"PemEncoding.TryFindUtf8 {utf8Found} vs TryFind {found}: {what}");
            }
        }

        if (!found)
        {
            return;
        }

        string label = text[fields.Label];
        byte[] decoded = new byte[fields.DecodedDataLength];
        Check.That(Convert.TryFromBase64Chars(text.AsSpan(fields.Base64Data), decoded, out int n) && n == decoded.Length, $"PEM data doesn't decode to DecodedDataLength {decoded.Length}: {what}");

        // Write it back into exactly GetEncodedSize chars, and one less.
        int size = PemEncoding.GetEncodedSize(label.Length, decoded.Length);
        Span<char> dest = Out<char>(size, !atStart);
        Check.That(PemEncoding.TryWrite(label, decoded, dest, out int written) && written == size, $"PemEncoding.TryWrite into GetEncodedSize {size} wrote {written}: {what}");
        Check.That(!PemEncoding.TryWrite(label, decoded, Out<char>(size - 1, atStart), out _), $"PemEncoding.TryWrite into {size - 1} succeeded: {what}");
        string pem = new(dest);
        Check.That(PemEncoding.TryFind(pem, out PemFields again) && pem[again.Label] == label && Convert.FromBase64String(pem[again.Base64Data]).AsSpan().SequenceEqual(decoded),
            $"PemEncoding.TryWrite output {Check.Show(pem)} doesn't read back: {what}");
    }

    private static void Asn(AsnEncodingRules rules, byte place, byte[] bytes, bool atStart, string what)
    {
        what = $"{rules} {what}";
        ReadOnlySpan<byte> source = Guarded.Copy<byte>(bytes, atStart);
        static bool Allowed(Exception e) => e is AsnContentException or ArgumentException;

        // Octet strings.
        var array = Outcome<string>.Of(() => Convert.ToHexString(AsnDecoder.ReadOctetString(bytes, rules, out int c)) + "/" + c, Allowed);
        if (array.Ok)
        {
            int length = array.Value.IndexOf('/') / 2;
            byte[] expected = Convert.FromHexString(array.Value[..(length * 2)]);
            Span<byte> exact = Out<byte>(length, !atStart);
            Check.That(AsnDecoder.TryReadOctetString(source, exact, rules, out int consumed, out int written) && written == length && exact.SequenceEqual(expected) && array.Value.EndsWith("/" + consumed, StringComparison.Ordinal),
                $"TryReadOctetString into exactly {length} bytes: {what}");
            if (length > 0)
            {
                Check.That(!AsnDecoder.TryReadOctetString(source, Out<byte>(length - 1, atStart), rules, out _, out _), $"TryReadOctetString into {length - 1} succeeded: {what}");
            }
        }

        // Bit strings.
        var bits = Outcome<string>.Of(() => Convert.ToHexString(AsnDecoder.ReadBitString(bytes, rules, out int unused, out int c)) + "/" + unused + "/" + c, Allowed);
        if (bits.Ok)
        {
            int length = bits.Value.IndexOf('/') / 2;
            byte[] expected = Convert.FromHexString(bits.Value[..(length * 2)]);
            Span<byte> exact = Out<byte>(length, !atStart);
            Check.That(AsnDecoder.TryReadBitString(source, exact, rules, out int unused, out int consumed, out int written) && written == length && exact.SequenceEqual(expected) && bits.Value.EndsWith("/" + unused + "/" + consumed, StringComparison.Ordinal),
                $"TryReadBitString into exactly {length} bytes: {what}");
            if (length > 0)
            {
                Check.That(!AsnDecoder.TryReadBitString(source, Out<byte>(length - 1, atStart), rules, out _, out _, out _), $"TryReadBitString into {length - 1} succeeded: {what}");
            }
        }

        // Character strings of each type.
        UniversalTagNumber[] types = [UniversalTagNumber.UTF8String, UniversalTagNumber.PrintableString, UniversalTagNumber.IA5String, UniversalTagNumber.BMPString, UniversalTagNumber.T61String, UniversalTagNumber.VisibleString, UniversalTagNumber.NumericString];
        UniversalTagNumber type = types[place % types.Length];
        var text = Outcome<string>.Of(() => AsnDecoder.ReadCharacterString(bytes, rules, type, out int c) + "\0" + c, Allowed);
        if (text.Ok)
        {
            string s = text.Value[..text.Value.LastIndexOf('\0')];
            Span<char> exact = Out<char>(s.Length, !atStart);
            Check.That(AsnDecoder.TryReadCharacterString(source, exact, rules, type, out int consumed, out int written) && written == s.Length && exact.SequenceEqual(s) && text.Value.EndsWith("\0" + consumed, StringComparison.Ordinal),
                $"TryReadCharacterString({type}) into exactly {s.Length} chars: {what}");
            if (s.Length > 0)
            {
                Check.That(!AsnDecoder.TryReadCharacterString(source, Out<char>(s.Length - 1, atStart), rules, type, out _, out _), $"TryReadCharacterString({type}) into {s.Length - 1} succeeded: {what}");
            }

            // TryReadCharacterStringBytes: the raw content bytes.
            var raw = Outcome<int>.Of(() => { byte[] b = new byte[bytes.Length]; return AsnDecoder.TryReadCharacterStringBytes(bytes, b, rules, new Asn1Tag(type), out _, out int w) ? w : -1; }, Allowed);
            if (raw.Ok && raw.Value >= 0)
            {
                Span<byte> exactRaw = Out<byte>(raw.Value, atStart);
                Check.That(AsnDecoder.TryReadCharacterStringBytes(source, exactRaw, rules, new Asn1Tag(type), out _, out int w2) && w2 == raw.Value, $"TryReadCharacterStringBytes into exactly {raw.Value}: {what}");
            }
        }

        // Scalars from guarded memory must match arrays.
        var reader = Outcome<string>.Of(() => Walk(new AsnReader(bytes, rules)), Allowed);
        Memory<byte> guardedMemory = Guarded.CopyMemory<byte>(bytes, atStart);
        var guardedReader = Outcome<string>.Of(() => Walk(new AsnReader(guardedMemory, rules)), Allowed);
        Check.That(reader.SameAs(guardedReader), $"AsnReader over guarded memory [{guardedReader}] vs array [{reader}]: {what}");
    }

    private static string Walk(AsnReader reader)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 200 && reader.HasData; i++)
        {
            Asn1Tag tag = reader.PeekTag();
            sb.Append(tag).Append(':');
            if (tag.IsConstructed)
            {
                sb.Append('[').Append(Walk(reader.ReadSequence(tag))).Append(']');
                continue;
            }

            sb.Append(tag.TagClass == TagClass.Universal ? (UniversalTagNumber)tag.TagValue switch
            {
                UniversalTagNumber.Integer => reader.ReadInteger(tag).ToString(),
                UniversalTagNumber.Boolean => reader.ReadBoolean(tag).ToString(),
                UniversalTagNumber.ObjectIdentifier => reader.ReadObjectIdentifier(tag),
                UniversalTagNumber.UtcTime => reader.ReadUtcTime(tag).ToString("O"),
                UniversalTagNumber.GeneralizedTime => reader.ReadGeneralizedTime(tag).ToString("O"),
                UniversalTagNumber.Enumerated => Convert.ToHexString(reader.ReadEnumeratedBytes(tag).Span),
                _ => Convert.ToHexString(reader.ReadEncodedValue().Span),
            } : Convert.ToHexString(reader.ReadEncodedValue().Span));
            sb.Append(';');
        }

        return sb.ToString();
    }
}
