#nullable disable warnings
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// Certificate and signing-request parsing from memory that sits against a guard page (see
/// <see cref="Guarded"/>): X509CertificateLoader.LoadCertificate(ReadOnlySpan) hands the span to the
/// native parser, so a read past the input faults. The parsed fields (names, validity, extensions,
/// public key parameters, raw data) are read and compared with loading the same bytes from an array;
/// CertificateRequest.LoadSigningRequest and X500DistinguishedName get the same treatment.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     operation; byte 1 placement bits
///   rest       DER (or PEM text) data
/// </remarks>
public static class UnsafeX509Target
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte op = input.Byte();
        byte place = input.Byte();
        byte[] bytes = input.Rest().ToArray();
        if (bytes.Length > 16384)
        {
            return;
        }

        bool atStart = (place & 1) != 0;
        string what = $"op {op % 3} place {place:X2}, {bytes.Length} bytes 0x{Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 48)))}";
        Memory<byte> guarded = Guarded.CopyMemory<byte>(bytes, atStart);
        switch (op % 3)
        {
            case 0:
            {
                var fromArray = Outcome<string>.Of(() => { using var c = X509CertificateLoader.LoadCertificate(bytes); return Describe(c); }, e => e is CryptographicException);
                var fromSpan = Outcome<string>.Of(() => { using var c = X509CertificateLoader.LoadCertificate(guarded.Span); return Describe(c); }, e => e is CryptographicException);
                Check.That(fromArray.SameAs(fromSpan), $"LoadCertificate(guarded span) [{fromSpan}] vs (array) [{fromArray}]: {what}");
                break;
            }

            case 1:
            {
                var fromArray = Outcome<string>.Of(() => Describe(CertificateRequest.LoadSigningRequest(bytes, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.SkipSignatureValidation)), e => e is CryptographicException);
                var fromSpan = Outcome<string>.Of(() => Describe(CertificateRequest.LoadSigningRequest(guarded.Span, HashAlgorithmName.SHA256, out int consumed, CertificateRequestLoadOptions.SkipSignatureValidation)), e => e is CryptographicException);
                Check.That(fromArray.SameAs(fromSpan) || fromArray.Ok != fromSpan.Ok && !fromArray.Ok, $"LoadSigningRequest(guarded span) [{fromSpan}] vs (array) [{fromArray}]: {what}");
                break;
            }

            default:
            {
                var fromArray = Outcome<string>.Of(() => Describe(new X500DistinguishedName(bytes)), e => e is CryptographicException);
                var fromSpan = Outcome<string>.Of(() => Describe(new X500DistinguishedName(guarded.Span)), e => e is CryptographicException);
                Check.That(fromArray.SameAs(fromSpan), $"X500DistinguishedName(guarded span) [{fromSpan}] vs (array) [{fromArray}]: {what}");
                break;
            }
        }
    }

    private static string Describe(X500DistinguishedName name)
    {
        var sb = new StringBuilder(name.Name).Append('|').Append(name.Format(multiLine: false)).Append('|');
        foreach (X500RelativeDistinguishedName rdn in name.EnumerateRelativeDistinguishedNames())
        {
            sb.Append(rdn.HasMultipleElements ? "multi" : rdn.GetSingleElementType().Value + "=" + rdn.GetSingleElementValue()).Append(';');
        }

        return sb.ToString();
    }

    private static string Describe(X509Certificate2 c)
    {
        var sb = new StringBuilder();
        sb.Append(c.Subject).Append('|').Append(c.Issuer).Append('|').Append(c.SerialNumber).Append('|').Append(c.Version).Append('|');
        sb.Append(c.NotBefore.ToUniversalTime().ToString("O")).Append('|').Append(c.NotAfter.ToUniversalTime().ToString("O")).Append('|');
        sb.Append(c.SignatureAlgorithm.Value).Append('|').Append(c.GetKeyAlgorithm()).Append('|').Append(Convert.ToHexString(c.GetPublicKey())).Append('|');
        sb.Append(c.Thumbprint).Append('|').Append(Convert.ToHexString(c.RawData)).Append('|');
        sb.Append(c.GetNameInfo(X509NameType.SimpleName, false)).Append('|').Append(c.GetNameInfo(X509NameType.DnsName, false)).Append('|');
        sb.Append(c.GetNameInfo(X509NameType.EmailName, false)).Append('|').Append(c.GetNameInfo(X509NameType.UpnName, true)).Append('|');
        foreach (X509Extension e in c.Extensions)
        {
            sb.Append(e.Oid?.Value).Append(e.Critical ? "!" : "").Append('=').Append(Convert.ToHexString(e.RawData)).Append(':');
            sb.Append(e switch
            {
                X509BasicConstraintsExtension b => $"{b.CertificateAuthority}/{b.HasPathLengthConstraint}/{b.PathLengthConstraint}",
                X509KeyUsageExtension k => k.KeyUsages.ToString(),
                X509EnhancedKeyUsageExtension eku => string.Join(",", eku.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value)),
                X509SubjectKeyIdentifierExtension s => s.SubjectKeyIdentifier,
                X509SubjectAlternativeNameExtension san => string.Join(",", san.EnumerateDnsNames()) + "/" + string.Join(",", san.EnumerateIPAddresses()),
                X509AuthorityKeyIdentifierExtension a => (a.KeyIdentifier is ReadOnlyMemory<byte> k ? Convert.ToHexString(k.Span) : "") + "/" + a.NamedIssuer?.Name,
                _ => "",
            }).Append(';');
        }

        sb.Append(Describe(c.SubjectName)).Append(Describe(c.IssuerName));
        return sb.ToString();
    }

    private static string Describe(CertificateRequest r)
    {
        var sb = new StringBuilder(Describe(r.SubjectName)).Append('|').Append(r.PublicKey.Oid.Value).Append('|');
        sb.Append(Convert.ToHexString(r.PublicKey.EncodedKeyValue.RawData)).Append('|');
        foreach (X509Extension e in r.CertificateExtensions)
        {
            sb.Append(e.Oid?.Value).Append('=').Append(Convert.ToHexString(e.RawData)).Append(';');
        }

        foreach (AsnEncodedData a in r.OtherRequestAttributes)
        {
            sb.Append(a.Oid?.Value).Append('=').Append(Convert.ToHexString(a.RawData)).Append(';');
        }

        return sb.ToString();
    }
}
