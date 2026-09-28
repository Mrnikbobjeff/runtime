#nullable disable warnings
using System.Formats.Asn1;
using System.Numerics;

namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Formats.Asn1: AsnReader, AsnDecoder and AsnWriter.</summary>
/// <remarks>
/// Input layout: byte 0 selects the rule set (BER, CER, DER); the rest is the encoded document.
/// The document is walked with AsnReader, reading every element with the typed method its tag
/// calls for. Checks: the static AsnDecoder methods agree with AsnReader on every value and on the
/// number of bytes consumed; for DER, which is canonical, writing the decoded values back with
/// AsnWriter reproduces the input bytes exactly. Invalid content may only throw AsnContentException.
/// </remarks>
public static class Asn1Target
{
    private const int MaxDepth = 24;

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 1 || data.Length > 1 << 14)
        {
            return;
        }

        var ruleSet = (AsnEncodingRules)(data[0] % 3);
        byte[] document = data.Slice(1).ToArray();
        var writer = new AsnWriter(AsnEncodingRules.DER);
        int consumed;
        try
        {
            var reader = new AsnReader(document, ruleSet);
            ReadOnlyMemory<byte> first = reader.PeekEncodedValue();
            consumed = first.Length;
            var single = new AsnReader(first, ruleSet);
            Walk(single, writer, ruleSet, 0);
        }
        catch (AsnContentException)
        {
            return;
        }

        if (ruleSet == AsnEncodingRules.DER)
        {
            byte[] rewritten = writer.Encode();
            Check.That(rewritten.AsSpan().SequenceEqual(document.AsSpan(0, consumed)),
                $"DER value re-encoded by AsnWriter differs: input {Check.Show(document[..consumed])}, rewritten {Check.Show(rewritten)}");
        }
    }

    private static void Walk(AsnReader reader, AsnWriter writer, AsnEncodingRules ruleSet, int depth)
    {
        while (reader.HasData)
        {
            Asn1Tag tag = reader.PeekTag();
            byte[] encoded = reader.PeekEncodedValue().ToArray();
            string what = $"{tag} value {Check.Show(encoded)} ({ruleSet})";

            if (tag.IsConstructed && depth < MaxDepth && (tag.TagClass != TagClass.Universal || tag.TagValue is (int)UniversalTagNumber.Sequence or (int)UniversalTagNumber.Set))
            {
                bool isSet = tag.TagClass == TagClass.Universal && tag.TagValue == (int)UniversalTagNumber.Set;
                AsnReader inner = isSet ? reader.ReadSetOf(tag) : reader.ReadSequence(tag);
                using (isSet ? writer.PushSetOf(tag) : writer.PushSequence(tag))
                {
                    Walk(inner, writer, ruleSet, depth + 1);
                }

                continue;
            }

            if (tag.TagClass != TagClass.Universal || tag.IsConstructed && tag.TagValue is not ((int)UniversalTagNumber.OctetString or (int)UniversalTagNumber.BitString))
            {
                writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
                continue;
            }

            switch ((UniversalTagNumber)tag.TagValue)
            {
                case UniversalTagNumber.Boolean:
                {
                    bool value = reader.ReadBoolean(tag);
                    Check.Equal(value, AsnDecoder.ReadBoolean(encoded, ruleSet, out int n, tag), $"AsnDecoder.ReadBoolean for {what}");
                    Check.Equal(encoded.Length, n, $"AsnDecoder.ReadBoolean consumed for {what}");
                    writer.WriteBoolean(value, tag);
                    break;
                }

                case UniversalTagNumber.Integer:
                case UniversalTagNumber.Enumerated:
                {
                    bool enumerated = tag.TagValue == (int)UniversalTagNumber.Enumerated;
                    ReadOnlyMemory<byte> bytes = enumerated ? reader.ReadEnumeratedBytes(tag) : reader.ReadIntegerBytes(tag);
                    var value = new BigInteger(bytes.Span, isUnsigned: false, isBigEndian: true);
                    if (!enumerated)
                    {
                        Check.Equal(value, AsnDecoder.ReadInteger(encoded, ruleSet, out int n, tag), $"AsnDecoder.ReadInteger for {what}");
                        Check.Equal(encoded.Length, n, $"AsnDecoder.ReadInteger consumed for {what}");
                        bool fits = AsnDecoder.TryReadInt64(encoded, ruleSet, out long small, out _, tag);
                        Check.That(fits == (value >= long.MinValue && value <= long.MaxValue) && (!fits || small == value), $"AsnDecoder.TryReadInt64 {fits}/{small} vs {value} for {what}");
                        writer.WriteInteger(value, tag);
                    }
                    else
                    {
                        ReadOnlySpan<byte> viaDecoder = AsnDecoder.ReadEnumeratedBytes(encoded, ruleSet, out int n, tag);
                        Check.That(viaDecoder.SequenceEqual(bytes.Span) && n == encoded.Length, $"AsnDecoder.ReadEnumeratedBytes differs for {what}");
                        writer.WriteEncodedValue(encoded); // AsnWriter only writes enumerated values of enum types
                    }

                    break;
                }

                case UniversalTagNumber.BitString:
                {
                    byte[] value = reader.ReadBitString(out int unused, tag);
                    byte[] viaDecoder = AsnDecoder.ReadBitString(encoded, ruleSet, out int unused2, out int n, tag);
                    Check.That(value.AsSpan().SequenceEqual(viaDecoder) && unused == unused2 && n == encoded.Length, $"AsnDecoder.ReadBitString differs for {what}");
                    writer.WriteBitString(value, unused, tag.IsConstructed ? new Asn1Tag(UniversalTagNumber.BitString) : tag);
                    break;
                }

                case UniversalTagNumber.OctetString:
                {
                    byte[] value = reader.ReadOctetString(tag.IsConstructed ? new Asn1Tag(UniversalTagNumber.OctetString) : tag);
                    byte[] viaDecoder = AsnDecoder.ReadOctetString(encoded, ruleSet, out int n, tag.IsConstructed ? new Asn1Tag(UniversalTagNumber.OctetString) : tag);
                    Check.That(value.AsSpan().SequenceEqual(viaDecoder) && n == encoded.Length, $"AsnDecoder.ReadOctetString differs for {what}");
                    writer.WriteOctetString(value, tag.IsConstructed ? new Asn1Tag(UniversalTagNumber.OctetString) : tag);
                    break;
                }

                case UniversalTagNumber.Null:
                    reader.ReadNull(tag);
                    AsnDecoder.ReadNull(encoded, ruleSet, out int nullLength, tag);
                    Check.Equal(encoded.Length, nullLength, $"AsnDecoder.ReadNull consumed for {what}");
                    writer.WriteNull(tag);
                    break;

                case UniversalTagNumber.ObjectIdentifier:
                {
                    string oid = reader.ReadObjectIdentifier(tag);
                    Check.Equal(oid, AsnDecoder.ReadObjectIdentifier(encoded, ruleSet, out int n, tag), $"AsnDecoder.ReadObjectIdentifier for {what}");
                    Check.Equal(encoded.Length, n, $"AsnDecoder.ReadObjectIdentifier consumed for {what}");
                    writer.WriteObjectIdentifier(oid, tag);
                    break;
                }

                case UniversalTagNumber.UtcTime:
                {
                    DateTimeOffset value = reader.ReadUtcTime(tag);
                    Check.Equal(value, AsnDecoder.ReadUtcTime(encoded, ruleSet, out int n, expectedTag: tag), $"AsnDecoder.ReadUtcTime for {what}");
                    Check.Equal(encoded.Length, n, $"AsnDecoder.ReadUtcTime consumed for {what}");
                    writer.WriteUtcTime(value, tag);
                    break;
                }

                case UniversalTagNumber.GeneralizedTime:
                {
                    DateTimeOffset value = reader.ReadGeneralizedTime(tag);
                    Check.Equal(value, AsnDecoder.ReadGeneralizedTime(encoded, ruleSet, out int n, tag), $"AsnDecoder.ReadGeneralizedTime for {what}");
                    Check.Equal(encoded.Length, n, $"AsnDecoder.ReadGeneralizedTime consumed for {what}");
                    writer.WriteGeneralizedTime(value, omitFractionalSeconds: false, tag);
                    break;
                }

                case UniversalTagNumber.UTF8String:
                case UniversalTagNumber.PrintableString:
                case UniversalTagNumber.IA5String:
                case UniversalTagNumber.VisibleString:
                case UniversalTagNumber.NumericString:
                case UniversalTagNumber.BMPString:
                case UniversalTagNumber.T61String:
                {
                    var type = (UniversalTagNumber)tag.TagValue;
                    string value = reader.ReadCharacterString(type, tag);
                    Check.Equal(value, AsnDecoder.ReadCharacterString(encoded, ruleSet, type, out int n, tag), $"AsnDecoder.ReadCharacterString for {what}");
                    Check.Equal(encoded.Length, n, $"AsnDecoder.ReadCharacterString consumed for {what}");
                    if (type == UniversalTagNumber.T61String)
                    {
                        writer.WriteEncodedValue(encoded); // T61 decoding is lossy by design (read as UTF-8 or Latin-1)
                    }
                    else
                    {
                        writer.WriteCharacterString(type, value, tag);
                    }

                    break;
                }

                default:
                    writer.WriteEncodedValue(reader.ReadEncodedValue().Span);
                    break;
            }
        }
    }
}
