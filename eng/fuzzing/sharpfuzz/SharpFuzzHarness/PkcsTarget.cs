#nullable disable warnings
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace SharpFuzzHarness;

/// <summary>
/// Fuzzes the PKCS / CMS decoders: X509CertificateLoader's managed PKCS#12 loader, Pkcs12Info,
/// SignedCms, EnvelopedCms, RFC 3161 timestamp tokens and PKCS#8 private key info.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     decoder
///   rest       the DER / BER data
/// Checks: only CryptographicException (including Pkcs12LoadLimitExceededException) is thrown while
/// decoding and walking the result; what decodes re-encodes (SignedCms.Encode, Pkcs8PrivateKeyInfo.Encode,
/// Rfc3161TimestampToken.AsSignedCms) and decodes again to the same content.
/// </remarks>
public static class PkcsTarget
{
    private static readonly Pkcs12LoaderLimits s_limits = new()
    {
        // Keep key derivations cheap: iteration counts come from the input.
        IndividualKdfIterationLimit = 2048,
        TotalKdfIterationLimit = 8192,
        MacIterationLimit = 2048,
        MaxCertificates = 16,
        MaxKeys = 16,
    };

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        byte[] bytes = input.Rest().ToArray();
        if (bytes.Length > 16384)
        {
            return;
        }

        try
        {
            switch (mode % 6)
            {
                case 0:
                    using (X509Certificate2 cert = X509CertificateLoader.LoadPkcs12(bytes, (mode & 0x80) != 0 ? "password" : null, X509KeyStorageFlags.EphemeralKeySet, s_limits))
                    {
                        _ = (cert.Subject, cert.Thumbprint, cert.HasPrivateKey, cert.Extensions.Count);
                    }

                    foreach (X509Certificate2 c in X509CertificateLoader.LoadPkcs12Collection(bytes, null, X509KeyStorageFlags.EphemeralKeySet, s_limits))
                    {
                        _ = c.SerialNumber;
                        c.Dispose();
                    }

                    break;
                case 1:
                    Pkcs12(bytes);
                    break;
                case 2:
                    Signed(bytes);
                    break;
                case 3:
                {
                    var cms = new EnvelopedCms();
                    cms.Decode(bytes);
                    _ = (cms.ContentEncryptionAlgorithm.Oid.Value, cms.ContentInfo.Content.Length, cms.Certificates.Count, cms.UnprotectedAttributes.Count);
                    foreach (RecipientInfo r in cms.RecipientInfos)
                    {
                        _ = (r.Type, r.Version, r.RecipientIdentifier.Type, r.RecipientIdentifier.Value, r.KeyEncryptionAlgorithm.Oid.Value, r.EncryptedKey.Length);
                    }

                    break;
                }

                case 4:
                    if (Rfc3161TimestampToken.TryDecode(bytes, out Rfc3161TimestampToken token, out int consumed))
                    {
                        Check.That(consumed > 0 && consumed <= bytes.Length, $"Rfc3161TimestampToken.TryDecode consumed {consumed} of {bytes.Length}");
                        Rfc3161TimestampTokenInfo info = token.TokenInfo;
                        _ = (info.Version, info.PolicyId.Value, info.HashAlgorithmId.Value, info.GetMessageHash().Length, info.GetSerialNumber().Length, info.Timestamp, info.AccuracyInMicroseconds, info.IsOrdering, info.GetNonce()?.Length, info.HasExtensions);
                        _ = info.GetExtensions().Count;
                        Signed(token.AsSignedCms().Encode());
                    }

                    if (Rfc3161TimestampTokenInfo.TryDecode(bytes, out Rfc3161TimestampTokenInfo tokenInfo, out _))
                    {
                        byte[] encoded = tokenInfo.Encode();
                        Check.That(Rfc3161TimestampTokenInfo.TryDecode(encoded, out Rfc3161TimestampTokenInfo again, out _) && again.Timestamp == tokenInfo.Timestamp &&
                            again.GetSerialNumber().Span.SequenceEqual(tokenInfo.GetSerialNumber().Span), "Rfc3161TimestampTokenInfo.Encode doesn't decode back");
                    }

                    break;
                default:
                {
                    Pkcs8PrivateKeyInfo key = Pkcs8PrivateKeyInfo.Decode(bytes, out int read, skipCopy: (mode & 0x40) != 0);
                    Check.That(read > 0 && read <= bytes.Length, $"Pkcs8PrivateKeyInfo.Decode read {read} of {bytes.Length}");
                    _ = (key.AlgorithmId.Value, key.AlgorithmParameters?.Length, key.PrivateKeyBytes.Length, key.Attributes.Count);
                    Pkcs8PrivateKeyInfo again = Pkcs8PrivateKeyInfo.Decode(key.Encode(), out _, skipCopy: false);
                    Check.That(again.AlgorithmId.Value == key.AlgorithmId.Value && again.PrivateKeyBytes.Span.SequenceEqual(key.PrivateKeyBytes.Span), "Pkcs8PrivateKeyInfo.Encode doesn't decode back");
                    break;
                }
            }
        }
        catch (CryptographicException)
        {
        }
    }

    private static void Pkcs12(byte[] bytes)
    {
        Pkcs12Info info = Pkcs12Info.Decode(bytes, out int consumed, skipCopy: true);
        Check.That(consumed > 0 && consumed <= bytes.Length, $"Pkcs12Info.Decode consumed {consumed} of {bytes.Length}");
        _ = info.IntegrityMode; // not VerifyMac: it runs a KDF with an input-chosen iteration count
        foreach (Pkcs12SafeContents contents in info.AuthenticatedSafe)
        {
            _ = contents.ConfidentialityMode;
            if (contents.ConfidentialityMode != Pkcs12ConfidentialityMode.None)
            {
                continue; // decrypting runs a KDF with an input-chosen iteration count
            }

            foreach (Pkcs12SafeBag bag in contents.GetBags())
            {
                _ = (bag.GetBagId().Value, bag.Attributes.Count, bag.EncodedBagValue.Length);
                if (bag is Pkcs12CertBag cert)
                {
                    _ = (cert.IsX509Certificate, cert.GetCertificateType().Value, cert.EncodedCertificate.Length);
                }
                else if (bag is Pkcs12SecretBag secret)
                {
                    _ = (secret.GetSecretType().Value, secret.SecretValue.Length);
                }
                else if (bag is Pkcs12KeyBag key)
                {
                    _ = key.Pkcs8PrivateKey.Length;
                }
            }
        }
    }

    private static void Signed(byte[] bytes)
    {
        var cms = new SignedCms();
        cms.Decode(bytes);
        _ = (cms.Version, cms.Detached, cms.ContentInfo.ContentType.Value, cms.ContentInfo.Content.Length, cms.Certificates.Count);
        foreach (SignerInfo signer in cms.SignerInfos)
        {
            _ = (signer.Version, signer.SignerIdentifier.Type, signer.SignerIdentifier.Value, signer.DigestAlgorithm.Value, signer.SignatureAlgorithm.Value, signer.GetSignature().Length);
            foreach (CryptographicAttributeObject attribute in signer.SignedAttributes)
            {
                _ = (attribute.Oid.Value, attribute.Values.Count);
            }

            _ = (signer.UnsignedAttributes.Count, signer.CounterSignerInfos.Count, signer.Certificate?.Subject);
        }

        // What was decoded re-encodes and decodes to the same content.
        byte[] encoded = cms.Encode();
        var again = new SignedCms();
        again.Decode(encoded);
        Check.That(again.ContentInfo.Content.AsSpan().SequenceEqual(cms.ContentInfo.Content) && again.SignerInfos.Count == cms.SignerInfos.Count &&
            again.Certificates.Count == cms.Certificates.Count, "SignedCms.Encode doesn't decode back to the same content");
    }
}
