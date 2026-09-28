#nullable disable warnings
using System.Formats.Cbor;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Formats.Cbor (NuGet package): CborReader in each conformance mode, re-encoded with CborWriter.</summary>
/// <remarks>
/// Input layout:
///   byte 0     low 2 bits: conformance mode (Lax, Strict, Canonical, Ctap2Canonical); 0x04 multiple root values
///   rest       the CBOR data
/// Checks: the reader only throws CborContentException; the modes nest (what Canonical or
/// Ctap2Canonical accepts, Strict accepts; what Strict accepts, Lax accepts) with the same values;
/// replaying the values into a CborWriter of the same mode reproduces the input exactly in the
/// canonical modes (encodings are unique there), and otherwise gives data that reads back as the
/// same values; SkipValue and ReadEncodedValue agree with reading the value.
/// </remarks>
public static class CborTarget
{
    private static readonly CborConformanceMode[] s_modes = [CborConformanceMode.Lax, CborConformanceMode.Strict, CborConformanceMode.Canonical, CborConformanceMode.Ctap2Canonical];

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte flags = input.Byte();
        byte[] bytes = input.Rest().ToArray();
        CborConformanceMode mode = s_modes[flags & 3];
        bool multiple = (flags & 4) != 0;
        string what = $"{mode}{(multiple ? " (multiple roots)" : "")} 0x{Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 64)))}{(bytes.Length > 64 ? "..." : "")}";

        List<string> tokens = Read(bytes, mode, multiple, out string error);
        // Known (CBOR-TRUNC-1): with multiple root values a trailing tag without a data item after it is
        // accepted (PeekState says Finished).
        if (tokens is null || tokens.Count == 0 || !s_reportKnownIssues && multiple && tokens[^1].StartsWith('G'))
        {
            return;
        }

        // Known (CBOR-NAN-1): CborWriter writes every NaN as the canonical quiet NaN, dropping sign and payload.
        bool nan = tokens.Any(IsNaN);

        // Nesting of the conformance modes.
        foreach (CborConformanceMode weaker in mode switch
        {
            CborConformanceMode.Canonical or CborConformanceMode.Ctap2Canonical => (CborConformanceMode[])[CborConformanceMode.Strict, CborConformanceMode.Lax],
            CborConformanceMode.Strict => [CborConformanceMode.Lax],
            _ => [],
        })
        {
            List<string> other = Read(bytes, weaker, multiple, out string otherError);
            Check.That(other is not null, $"accepted in {mode} but not in {weaker} ({otherError}): {what}");
            Check.That(other.SequenceEqual(tokens), $"{weaker} reads [{string.Join(" ", other)}], {mode} reads [{string.Join(" ", tokens)}]: {what}");
        }

        // Re-encode the values in the same mode.
        var writer = new CborWriter(mode, convertIndefiniteLengthEncodings: false, allowMultipleRootLevelValues: multiple);
        var replay = new CborReader(bytes, mode, multiple);
        try
        {
            Replay(replay, writer);
        }
        catch (InvalidOperationException e) when (!s_reportKnownIssues && e.Message.Contains("duplicate keys", StringComparison.Ordinal))
        {
            // Known (CBOR-DUP-1/2): the Strict reader misses a duplicate map key when the value before it is an
            // indefinite-length string ({3: 7F FF, 3: "n"}), or when the two keys encode the same value
            // differently ({1: 0, 1 as 18 01: 0}); the writer, which encodes values one way, then rejects it.
            return;
        }
        byte[] encoded = writer.Encode();
        // Without multiple root values the reader stops after the first one and leaves the rest.
        ReadOnlySpan<byte> consumed = bytes.AsSpan(0, bytes.Length - replay.BytesRemaining);
        // Known (CBOR-FLOAT-1, informational): the canonical readers accept floats that have a shorter exact
        // encoding (FA 7F800000 for +Infinity), which the writer then shortens (F9 7C00).
        bool floats = tokens.Any(t => t[0] is 'H' or 'F' or 'D' && t.Length > 1 && char.IsAsciiHexDigit(t[1]));
        if (mode is CborConformanceMode.Canonical or CborConformanceMode.Ctap2Canonical && (s_reportKnownIssues || !nan && !floats))
        {
            Check.That(encoded.AsSpan().SequenceEqual(consumed), $"re-encoded as 0x{Convert.ToHexString(encoded)}: {what}");
        }

        List<string> again = Read(encoded, mode, multiple, out string againError);
        // CborWriter writes floats in the shortest width that keeps the value, and simple values 20-22 as
        // false / true / null, so compare floats by value and those simple values by meaning.
        static List<string> Nans(List<string> list) => list?.Select(t => IsNaN(t) && !s_reportKnownIssues ? "NaN" : Normalize(t)).ToList();
        Check.That(again is not null && Nans(again).SequenceEqual(Nans(tokens)), $"re-encoded 0x{Convert.ToHexString(encoded)} reads as [{(again is null ? againError : string.Join(" ", again))}]: {what}");

        // SkipValue / ReadEncodedValue over the top-level values.
        var skipper = new CborReader(bytes, mode, multiple);
        var encodedReader = new CborReader(bytes, mode, multiple);
        while (skipper.PeekState() != CborReaderState.Finished)
        {
            if (!s_reportKnownIssues && tokens.Any(t => t.StartsWith('S')))
            {
                break; // Known (CBOR-SIMPLE-1), see Read
            }

            int before = skipper.BytesRemaining;
            skipper.SkipValue();
            ReadOnlyMemory<byte> value = encodedReader.ReadEncodedValue();
            Check.Equal(before - skipper.BytesRemaining, value.Length, $"SkipValue vs ReadEncodedValue length: {what}");
            Check.Equal(skipper.BytesRemaining, encodedReader.BytesRemaining, $"BytesRemaining after SkipValue / ReadEncodedValue: {what}");
        }
    }

    /// <summary>All values as tokens, or null (with the error) if the reader rejects the data.</summary>
    private static List<string> Read(byte[] bytes, CborConformanceMode mode, bool multiple, out string error)
    {
        var reader = new CborReader(bytes, mode, multiple);
        var tokens = new List<string>();
        error = null;
        try
        {
            while (true)
            {
                CborReaderState state = reader.PeekState();
                if (state == CborReaderState.Finished)
                {
                    return tokens;
                }

                tokens.Add(Token(reader, state));
                if (tokens.Count > 10000)
                {
                    return tokens;
                }
            }
        }
        catch (CborContentException e)
        {
            error = e.Message;
            return null;
        }
        catch (InvalidOperationException e) when (!s_reportKnownIssues && e.StackTrace?.Contains("ReadSimpleValue", StringComparison.Ordinal) == true)
        {
            // Known (CBOR-SIMPLE-1): PeekState reports SimpleValue for the reserved simple values
            // 0xFC-0xFE, and ReadSimpleValue / SkipValue then throw InvalidOperationException.
            error = e.Message;
            return null;
        }
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    private static string Normalize(string token) => token switch
    {
        "S20" => "false",
        "S21" => "true",
        "S22" => "null",
        ['H', ..] => "V" + BitConverter.DoubleToUInt64Bits((double)BitConverter.UInt16BitsToHalf(Convert.ToUInt16(token[1..], 16))).ToString("X16"),
        ['F', ..] => "V" + BitConverter.DoubleToUInt64Bits(BitConverter.UInt32BitsToSingle(Convert.ToUInt32(token[1..], 16))).ToString("X16"),
        ['D', ..] => "V" + token[1..],
        _ => token,
    };

    private static bool IsNaN(string token) => token.Length > 1 && token[0] switch
    {
        'H' => Half.IsNaN(BitConverter.UInt16BitsToHalf(Convert.ToUInt16(token[1..], 16))),
        'F' => float.IsNaN(BitConverter.UInt32BitsToSingle(Convert.ToUInt32(token[1..], 16))),
        'D' => double.IsNaN(BitConverter.UInt64BitsToDouble(Convert.ToUInt64(token[1..], 16))),
        _ => false,
    };

    private static string Token(CborReader r, CborReaderState state) => state switch
    {
        CborReaderState.UnsignedInteger => "U" + r.ReadUInt64(),
        CborReaderState.NegativeInteger => "N" + r.ReadCborNegativeIntegerRepresentation(),
        CborReaderState.ByteString => "B" + Convert.ToHexString(r.ReadByteString()),
        CborReaderState.TextString => "T" + Check.Show(r.ReadTextString()),
        CborReaderState.StartIndefiniteLengthByteString => ((Func<string>)(() => { r.ReadStartIndefiniteLengthByteString(); return "SIB"; }))(),
        CborReaderState.EndIndefiniteLengthByteString => ((Func<string>)(() => { r.ReadEndIndefiniteLengthByteString(); return "EIB"; }))(),
        CborReaderState.StartIndefiniteLengthTextString => ((Func<string>)(() => { r.ReadStartIndefiniteLengthTextString(); return "SIT"; }))(),
        CborReaderState.EndIndefiniteLengthTextString => ((Func<string>)(() => { r.ReadEndIndefiniteLengthTextString(); return "EIT"; }))(),
        CborReaderState.StartArray => "A" + (r.ReadStartArray()?.ToString() ?? "*"),
        CborReaderState.EndArray => ((Func<string>)(() => { r.ReadEndArray(); return "EA"; }))(),
        CborReaderState.StartMap => "M" + (r.ReadStartMap()?.ToString() ?? "*"),
        CborReaderState.EndMap => ((Func<string>)(() => { r.ReadEndMap(); return "EM"; }))(),
        CborReaderState.Tag => "G" + (ulong)r.ReadTag(),
        CborReaderState.SimpleValue => "S" + (byte)r.ReadSimpleValue(),
        CborReaderState.HalfPrecisionFloat => "H" + BitConverter.HalfToUInt16Bits(r.ReadHalf()).ToString("X4"),
        CborReaderState.SinglePrecisionFloat => "F" + BitConverter.SingleToUInt32Bits(r.ReadSingle()).ToString("X8"),
        CborReaderState.DoublePrecisionFloat => "D" + BitConverter.DoubleToUInt64Bits(r.ReadDouble()).ToString("X16"),
        CborReaderState.Null => ((Func<string>)(() => { r.ReadNull(); return "null"; }))(),
        CborReaderState.Boolean => r.ReadBoolean() ? "true" : "false",
        _ => throw new InvalidOperationException($"unexpected state {state}"),
    };

    private static void Replay(CborReader r, CborWriter w)
    {
        while (true)
        {
            switch (r.PeekState())
            {
                case CborReaderState.Finished: return;
                case CborReaderState.UnsignedInteger: w.WriteUInt64(r.ReadUInt64()); break;
                case CborReaderState.NegativeInteger: w.WriteCborNegativeIntegerRepresentation(r.ReadCborNegativeIntegerRepresentation()); break;
                case CborReaderState.ByteString: w.WriteByteString(r.ReadByteString()); break;
                case CborReaderState.TextString: w.WriteTextString(r.ReadTextString()); break;
                case CborReaderState.StartIndefiniteLengthByteString: r.ReadStartIndefiniteLengthByteString(); w.WriteStartIndefiniteLengthByteString(); break;
                case CborReaderState.EndIndefiniteLengthByteString: r.ReadEndIndefiniteLengthByteString(); w.WriteEndIndefiniteLengthByteString(); break;
                case CborReaderState.StartIndefiniteLengthTextString: r.ReadStartIndefiniteLengthTextString(); w.WriteStartIndefiniteLengthTextString(); break;
                case CborReaderState.EndIndefiniteLengthTextString: r.ReadEndIndefiniteLengthTextString(); w.WriteEndIndefiniteLengthTextString(); break;
                case CborReaderState.StartArray: w.WriteStartArray(r.ReadStartArray()); break;
                case CborReaderState.EndArray: r.ReadEndArray(); w.WriteEndArray(); break;
                case CborReaderState.StartMap: w.WriteStartMap(r.ReadStartMap()); break;
                case CborReaderState.EndMap: r.ReadEndMap(); w.WriteEndMap(); break;
                case CborReaderState.Tag: w.WriteTag(r.ReadTag()); break;
                case CborReaderState.SimpleValue: w.WriteSimpleValue(r.ReadSimpleValue()); break;
                case CborReaderState.HalfPrecisionFloat: w.WriteHalf(r.ReadHalf()); break;
                case CborReaderState.SinglePrecisionFloat: w.WriteSingle(r.ReadSingle()); break;
                case CborReaderState.DoublePrecisionFloat: w.WriteDouble(r.ReadDouble()); break;
                case CborReaderState.Null: r.ReadNull(); w.WriteNull(); break;
                case CborReaderState.Boolean: w.WriteBoolean(r.ReadBoolean()); break;
                default: throw new InvalidOperationException("unexpected state");
            }
        }
    }
}
