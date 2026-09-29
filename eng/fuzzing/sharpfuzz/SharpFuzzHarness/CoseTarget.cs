#nullable disable warnings
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;

namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Security.Cryptography.Cose (NuGet package): decoding COSE_Sign1 and COSE_Sign messages.</summary>
/// <remarks>
/// Input layout:
///   byte 0     0x01: COSE_Sign (multi-signer), otherwise COSE_Sign1
///   rest       the CBOR message
/// Checks: decoding only throws CryptographicException; the header maps and their values can be read
/// (GetValueAs* only throws InvalidOperationException for a value of another type); a decoded message
/// re-encodes (Encode) to a message that decodes to the same headers, content and signatures.
/// </remarks>
public static class CoseTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        byte[] bytes = input.Rest().ToArray();
        string what = $"COSE 0x{Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 64)))}{(bytes.Length > 64 ? "..." : "")}";
        CoseMessage message;
        try
        {
            message = (mode & 1) != 0 ? CoseMessage.DecodeMultiSign(bytes) : CoseMessage.DecodeSign1(bytes);
        }
        catch (CryptographicException)
        {
            return;
        }

        string summary = Describe(message);
        byte[] encoded = message.Encode();
        CoseMessage again;
        try
        {
            again = (mode & 1) != 0 ? CoseMessage.DecodeMultiSign(encoded) : CoseMessage.DecodeSign1(encoded);
        }
        catch (CryptographicException e)
        {
            Check.That(false, $"Encode() output 0x{Convert.ToHexString(encoded)} doesn't decode ({e.Message}): {what}");
            return;
        }

        string summary2 = Describe(again);
        Check.That(summary == summary2, $"re-encoded message reads as {summary2}, original {summary}: {what}");
    }

    private static string Describe(CoseMessage message)
    {
        var parts = new List<string>
        {
            "P" + Headers(message.ProtectedHeaders),
            "U" + Headers(message.UnprotectedHeaders),
            "C" + (message.Content is { } c ? Convert.ToHexString(c.Span) : "detached"),
        };
        switch (message)
        {
            case CoseSign1Message sign1:
                parts.Add("S" + Convert.ToHexString(sign1.Signature.Span));
                break;
            case CoseMultiSignMessage multi:
                foreach (CoseSignature signature in multi.Signatures)
                {
                    parts.Add($"[P{Headers(signature.ProtectedHeaders)} U{Headers(signature.UnprotectedHeaders)} S{Convert.ToHexString(signature.Signature.Span)}]");
                }

                break;
        }

        return string.Join(" ", parts);
    }

    private static string Headers(CoseHeaderMap map)
    {
        var entries = new List<string>();
        foreach (KeyValuePair<CoseHeaderLabel, CoseHeaderValue> entry in map)
        {
            CoseHeaderValue value = entry.Value;
            string typed = Outcome<string>.Of(() => value.GetValueAsInt32().ToString(), e => e is InvalidOperationException).ToString() + "/" +
                Outcome<string>.Of(() => value.GetValueAsString(), e => e is InvalidOperationException) + "/" +
                Outcome<string>.Of(() => Convert.ToHexString(value.GetValueAsBytes()), e => e is InvalidOperationException);
            entries.Add($"{entry.Key.GetHashCode():X8}={Convert.ToHexString(value.EncodedValue.Span)}({typed.Length})");
        }

        entries.Sort(StringComparer.Ordinal);
        return "{" + string.Join(",", entries) + "}";
    }
}
