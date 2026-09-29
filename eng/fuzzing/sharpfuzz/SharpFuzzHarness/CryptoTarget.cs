#nullable disable warnings
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// The OpenSSL shim (libSystem.Security.Cryptography.Native.OpenSsl) through the public one-shot
/// and incremental APIs, with every destination exactly sized against a guard page: hashes and
/// HMACs (one-shot, span, stream, incremental in fuzzed chunks, cloned, and the legacy
/// HashAlgorithm / TransformBlock paths, all against each other), AEAD ciphers (round trips,
/// tampering, in-place, every nonce / tag size), AES / TripleDES in CBC / ECB / CFB (one-shot vs
/// CryptoStream / ICryptoTransform in fuzzed chunks, padding modes, short destinations), PBKDF2 /
/// HKDF / SP800-108, the random number generator, and RSA / ECDSA / ECDH / DSA with parameters and
/// key blobs from the input (invalid ones must be rejected with CryptographicException, valid ones
/// must sign, verify, encrypt and decrypt) plus signature and encryption round trips into exactly
/// sized buffers.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     operation; byte 1 flags; byte 2 chunking seed
///   rest       data
/// </remarks>
public static unsafe class CryptoTarget
{
    private static readonly Lazy<RSA> s_rsa = new(() => RSA.Create(2048));
    private static readonly Lazy<ECDsa> s_ecdsa = new(() => ECDsa.Create(ECCurve.NamedCurves.nistP256));
    private static readonly Lazy<ECDiffieHellman> s_ecdh = new(() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256));
    private static readonly Lazy<DSA> s_dsa = new(() => DSA.Create(1024));

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte op = input.Byte();
        byte flags = input.Byte();
        byte chunking = input.Byte();
        switch (op % 7)
        {
            case 0: Hashes(ref input, flags, chunking); break;
            case 1: Aead(ref input, flags); break;
            case 2: Symmetric(ref input, flags, chunking); break;
            case 3: Kdf(ref input, flags); break;
            case 4: Parameters(ref input, flags); break;
            case 5: Signatures(ref input, flags); break;
            default: Keys(ref input, flags); break;
        }
    }

    private static Span<byte> Exact(int size, bool atStart)
    {
        Span<byte> span = new(Guarded.Allocate(size, atStart), size);
        span.Fill(0xCC);
        return span;
    }

    /// <summary>Splits <paramref name="data"/> into chunks whose sizes come from the seed (some empty).</summary>
    private static List<byte[]> Chunks(byte[] data, int seed)
    {
        var chunks = new List<byte[]>();
        int i = 0, n = 0;
        while (i < data.Length)
        {
            int size = ((seed * 7 + n * 13) % 37) switch { 0 => 0, 1 => 1, var s3 => Math.Min(s3 * 3, data.Length - i) };
            chunks.Add(data.AsSpan(i, size).ToArray());
            i += size;
            n++;
            if (n > 400)
            {
                chunks.Add(data.AsSpan(i).ToArray());
                break;
            }
        }

        if ((seed & 1) != 0)
        {
            chunks.Add([]);
        }

        return chunks;
    }

    private static bool Allowed(Exception e) => e is CryptographicException or ArgumentException or PlatformNotSupportedException or NotSupportedException;

    // ------------------------------------------------------------ hashes and HMACs

    private static readonly (HashAlgorithmName Name, Func<bool> Supported)[] s_hashes =
    [
        (HashAlgorithmName.MD5, () => true), (HashAlgorithmName.SHA1, () => true), (HashAlgorithmName.SHA256, () => true), (HashAlgorithmName.SHA384, () => true), (HashAlgorithmName.SHA512, () => true),
        (HashAlgorithmName.SHA3_256, () => SHA3_256.IsSupported && HMACSHA3_256.IsSupported), (HashAlgorithmName.SHA3_384, () => SHA3_384.IsSupported && HMACSHA3_384.IsSupported), (HashAlgorithmName.SHA3_512, () => SHA3_512.IsSupported && HMACSHA3_512.IsSupported),
    ];

    private static void Hashes(ref FuzzInput input, byte flags, byte chunking)
    {
        bool atStart = (flags & 1) != 0;
        var (name, supported) = s_hashes[(flags >> 1) % s_hashes.Length];
        if (!supported())
        {
            return;
        }

        byte[] key = input.Bytes(input.Byte() % 200).ToArray();
        byte[] data = input.Rest().ToArray();
        string what = $"{name.Name} over {data.Length} bytes, key {key.Length} bytes";
        byte[] reference = HashOneShot(name, data);
        int length = reference.Length;

        // Span one-shots into exact, oversized and short destinations.
        Span<byte> exact = Exact(length, atStart);
        Check.That(TryHashOneShot(name, data, exact, out int written) && written == length && exact.SequenceEqual(reference), $"{what}: TryHashData exact");
        Span<byte> bigger = Exact(length + 5, !atStart);
        Check.That(TryHashOneShot(name, data, bigger, out written) && written == length && bigger.Slice(0, length).SequenceEqual(reference) && bigger.Slice(length).ToArray().All(b => b == 0xCC), $"{what}: TryHashData into a bigger buffer");
        Span<byte> shorter = Exact(length - 1, atStart);
        Check.That(!TryHashOneShot(name, data, shorter, out written) && written == 0 && shorter.ToArray().All(b => b == 0xCC), $"{what}: TryHashData into a short buffer");
        Check.Equal(length, HashOneShot(name, data, exact), $"{what}: HashData(span, span) length");
        Check.That(exact.SequenceEqual(reference), $"{what}: HashData(span, span)");
        Check.That(HashOneShot(name, new MemoryStream(data)).SequenceEqual(reference), $"{what}: HashData(Stream)");
        // Incremental in chunks, with a clone and a peek in the middle.
        using IncrementalHash incremental = IncrementalHash.CreateHash(name);
        Check.Equal(length, incremental.HashLengthInBytes, $"{what}: HashLengthInBytes");
        List<byte[]> chunks = Chunks(data, chunking);
        IncrementalHash clone = null;
        for (int i = 0; i < chunks.Count; i++)
        {
            incremental.AppendData(chunks[i]);
            if (i == chunks.Count / 2)
            {
                clone = incremental.Clone();
                byte[] peek = incremental.GetCurrentHash();
                Check.That(peek.SequenceEqual(HashOneShot(name, data.AsSpan(0, chunks.Take(i + 1).Sum(c => c.Length)).ToArray())), $"{what}: GetCurrentHash after {i + 1} chunks");
            }
        }

        Span<byte> incrementalOut = Exact(length, atStart);
        Check.Equal(length, incremental.GetHashAndReset(incrementalOut), $"{what}: GetHashAndReset length");
        Check.That(incrementalOut.SequenceEqual(reference), $"{what}: incremental hash in {chunks.Count} chunks");
        if (clone is not null)
        {
            foreach (byte[] chunk in chunks.Skip(chunks.Count / 2 + 1))
            {
                clone.AppendData(chunk);
            }

            Check.That(clone.GetHashAndReset().SequenceEqual(reference), $"{what}: cloned incremental hash");
            clone.Dispose();
        }

        // After the reset the object hashes the empty input.
        Check.That(incremental.GetHashAndReset().SequenceEqual(HashOneShot(name, [])), $"{what}: hash after reset");
        // The legacy HashAlgorithm path in the same chunks.
        using HashAlgorithm legacy = CreateLegacy(name);
        foreach (byte[] chunk in chunks)
        {
            legacy.TransformBlock(chunk, 0, chunk.Length, null, 0);
        }

        legacy.TransformFinalBlock([], 0, 0);
        Check.That(legacy.Hash.SequenceEqual(reference), $"{what}: TransformBlock in {chunks.Count} chunks");
        Check.That(legacy.ComputeHash(data).SequenceEqual(reference), $"{what}: ComputeHash after TransformFinalBlock");
        Check.That(legacy.ComputeHash(new MemoryStream(data)).SequenceEqual(reference), $"{what}: ComputeHash(Stream)");

        // HMAC: one-shot span, incremental, legacy.
        byte[] mac = HmacOneShot(name, key, data);
        Check.Equal(length, mac.Length, $"{what}: HMAC length");
        Span<byte> macExact = Exact(length, !atStart);
        Check.That(TryHmacOneShot(name, key, data, macExact, out written) && written == length && macExact.SequenceEqual(mac), $"{what}: HMAC TryHashData exact");
        Span<byte> macShort = Exact(length - 1, atStart);
        Check.That(!TryHmacOneShot(name, key, data, macShort, out written) && written == 0, $"{what}: HMAC TryHashData short");
        using IncrementalHash incrementalMac = IncrementalHash.CreateHMAC(name, key);
        foreach (byte[] chunk in chunks)
        {
            incrementalMac.AppendData(chunk);
        }

        Check.That(incrementalMac.GetHashAndReset().SequenceEqual(mac), $"{what}: incremental HMAC in {chunks.Count} chunks");
        using HMAC legacyMac = CreateLegacyHmac(name, key);
        Check.That(legacyMac.ComputeHash(data).SequenceEqual(mac), $"{what}: legacy HMAC");
        int blockSize = name.Name switch { "SHA384" or "SHA512" => 128, "SHA3-256" => 136, "SHA3-384" => 104, "SHA3-512" => 72, _ => 64 };
        Check.That(key.Length > blockSize ? legacyMac.Key.Length == legacy.HashSize / 8 : legacyMac.Key.SequenceEqual(key), $"{what}: HMAC key round trip");
        Check.That(HmacOneShot(name, key, new MemoryStream(data)).SequenceEqual(mac), $"{what}: HMAC HashData(Stream)");

        // SHAKE (variable output) when available.
        if (Shake128.IsSupported)
        {
            int outLength = flags % 100;
            byte[] shake = Shake128.HashData(data, outLength);
            Check.Equal(outLength, shake.Length, $"{what}: Shake128 output length");
            Span<byte> shakeExact = Exact(outLength, atStart);
            Shake128.HashData(data, shakeExact);
            Check.That(shakeExact.SequenceEqual(shake), $"{what}: Shake128 span");
            Check.That(Shake128.HashData(data, outLength + 7).AsSpan(0, outLength).SequenceEqual(shake), $"{what}: Shake128 prefix property");
            using var shakeIncremental = new Shake128();
            foreach (byte[] chunk in chunks)
            {
                shakeIncremental.AppendData(chunk);
            }

            Check.That(shakeIncremental.GetHashAndReset(outLength).SequenceEqual(shake), $"{what}: incremental Shake128");
        }
    }

    private static byte[] HashOneShot(HashAlgorithmName name, byte[] data) => name.Name switch
    {
        "MD5" => MD5.HashData(data), "SHA1" => SHA1.HashData(data), "SHA256" => SHA256.HashData(data), "SHA384" => SHA384.HashData(data), "SHA512" => SHA512.HashData(data),
        "SHA3-256" => SHA3_256.HashData(data), "SHA3-384" => SHA3_384.HashData(data), _ => SHA3_512.HashData(data),
    };

    private static byte[] HashOneShot(HashAlgorithmName name, Stream data) => name.Name switch
    {
        "MD5" => MD5.HashData(data), "SHA1" => SHA1.HashData(data), "SHA256" => SHA256.HashData(data), "SHA384" => SHA384.HashData(data), "SHA512" => SHA512.HashData(data),
        "SHA3-256" => SHA3_256.HashData(data), "SHA3-384" => SHA3_384.HashData(data), _ => SHA3_512.HashData(data),
    };

    private static int HashOneShot(HashAlgorithmName name, ReadOnlySpan<byte> data, Span<byte> dest) => name.Name switch
    {
        "MD5" => MD5.HashData(data, dest), "SHA1" => SHA1.HashData(data, dest), "SHA256" => SHA256.HashData(data, dest), "SHA384" => SHA384.HashData(data, dest), "SHA512" => SHA512.HashData(data, dest),
        "SHA3-256" => SHA3_256.HashData(data, dest), "SHA3-384" => SHA3_384.HashData(data, dest), _ => SHA3_512.HashData(data, dest),
    };

    private static bool TryHashOneShot(HashAlgorithmName name, ReadOnlySpan<byte> data, Span<byte> dest, out int written) => name.Name switch
    {
        "MD5" => MD5.TryHashData(data, dest, out written), "SHA1" => SHA1.TryHashData(data, dest, out written), "SHA256" => SHA256.TryHashData(data, dest, out written),
        "SHA384" => SHA384.TryHashData(data, dest, out written), "SHA512" => SHA512.TryHashData(data, dest, out written),
        "SHA3-256" => SHA3_256.TryHashData(data, dest, out written), "SHA3-384" => SHA3_384.TryHashData(data, dest, out written), _ => SHA3_512.TryHashData(data, dest, out written),
    };

    private static byte[] HmacOneShot(HashAlgorithmName name, byte[] key, byte[] data) => name.Name switch
    {
        "MD5" => HMACMD5.HashData(key, data), "SHA1" => HMACSHA1.HashData(key, data), "SHA256" => HMACSHA256.HashData(key, data), "SHA384" => HMACSHA384.HashData(key, data), "SHA512" => HMACSHA512.HashData(key, data),
        "SHA3-256" => HMACSHA3_256.HashData(key, data), "SHA3-384" => HMACSHA3_384.HashData(key, data), _ => HMACSHA3_512.HashData(key, data),
    };

    private static byte[] HmacOneShot(HashAlgorithmName name, byte[] key, Stream data) => name.Name switch
    {
        "MD5" => HMACMD5.HashData(key, data), "SHA1" => HMACSHA1.HashData(key, data), "SHA256" => HMACSHA256.HashData(key, data), "SHA384" => HMACSHA384.HashData(key, data), "SHA512" => HMACSHA512.HashData(key, data),
        "SHA3-256" => HMACSHA3_256.HashData(key, data), "SHA3-384" => HMACSHA3_384.HashData(key, data), _ => HMACSHA3_512.HashData(key, data),
    };

    private static bool TryHmacOneShot(HashAlgorithmName name, ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Span<byte> dest, out int written) => name.Name switch
    {
        "MD5" => HMACMD5.TryHashData(key, data, dest, out written), "SHA1" => HMACSHA1.TryHashData(key, data, dest, out written), "SHA256" => HMACSHA256.TryHashData(key, data, dest, out written),
        "SHA384" => HMACSHA384.TryHashData(key, data, dest, out written), "SHA512" => HMACSHA512.TryHashData(key, data, dest, out written),
        "SHA3-256" => HMACSHA3_256.TryHashData(key, data, dest, out written), "SHA3-384" => HMACSHA3_384.TryHashData(key, data, dest, out written), _ => HMACSHA3_512.TryHashData(key, data, dest, out written),
    };

    private static HashAlgorithm CreateLegacy(HashAlgorithmName name) => name.Name switch
    {
        "MD5" => MD5.Create(), "SHA1" => SHA1.Create(), "SHA256" => SHA256.Create(), "SHA384" => SHA384.Create(), "SHA512" => SHA512.Create(),
        "SHA3-256" => SHA3_256.Create(), "SHA3-384" => SHA3_384.Create(), _ => SHA3_512.Create(),
    };

    private static HMAC CreateLegacyHmac(HashAlgorithmName name, byte[] key) => name.Name switch
    {
        "MD5" => new HMACMD5(key), "SHA1" => new HMACSHA1(key), "SHA256" => new HMACSHA256(key), "SHA384" => new HMACSHA384(key), "SHA512" => new HMACSHA512(key),
        "SHA3-256" => new HMACSHA3_256(key), "SHA3-384" => new HMACSHA3_384(key), _ => new HMACSHA3_512(key),
    };

    // ------------------------------------------------------------ AEAD

    private static void Aead(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        int which = (flags >> 1) % 3;
        int keySize = ((flags >> 3) % 3) switch { 0 => 16, 1 => 24, _ => 32 };
        int nonceSize = input.Byte() % 20;
        int tagSize = input.Byte() % 20;
        byte[] key = new byte[keySize];
        input.Bytes(keySize).CopyTo(key);
        byte[] nonce = input.Bytes(nonceSize).ToArray();
        byte[] aad = input.Bytes(input.Byte() % 64).ToArray();
        byte[] plaintext = input.Rest().ToArray();
        string what = $"{(which == 0 ? "AesGcm" : which == 1 ? "AesCcm" : "ChaCha20Poly1305")} key {keySize} nonce {nonceSize} tag {tagSize} aad {aad.Length} plaintext {plaintext.Length}";
        if (which == 0 && !AesGcm.IsSupported || which == 1 && !AesCcm.IsSupported || which == 2 && !ChaCha20Poly1305.IsSupported)
        {
            return;
        }

        IDisposable cipher;
        try
        {
            cipher = which switch
            {
                0 => new AesGcm(key, tagSize),
                1 => new AesCcm(key),
                _ => new ChaCha20Poly1305(key),
            };
        }
        catch (Exception e) when (Allowed(e))
        {
            Check.That(which == 2 && keySize != 32 || which == 0 && !Valid(AesGcm.TagByteSizes, tagSize), $"{what}: constructor rejected valid sizes: {e.Message}");
            return;
        }

        using (cipher)
        {
            Span<byte> ciphertext = Exact(plaintext.Length, atStart);
            Span<byte> tag = Exact(tagSize, !atStart);
            try
            {
                Encrypt(cipher, nonce, plaintext, ciphertext, tag, aad);
            }
            catch (Exception e) when (Allowed(e))
            {
                bool valid = which switch
                {
                    0 => nonceSize == 12 && Valid(AesGcm.TagByteSizes, tagSize),
                    1 => Valid(AesCcm.NonceByteSizes, nonceSize) && Valid(AesCcm.TagByteSizes, tagSize),
                    _ => nonceSize == 12 && tagSize == 16,
                };
                Check.That(!valid, $"{what}: Encrypt rejected valid sizes: {e.Message}");
                return;
            }

            Check.That(which != 0 || Valid(AesGcm.TagByteSizes, tagSize), $"{what}: Encrypt accepted an invalid tag size");
            // Round trip into an exact buffer, in place, and with a tampered tag / ciphertext / AAD.
            Span<byte> decrypted = Exact(plaintext.Length, atStart);
            Decrypt(cipher, nonce, ciphertext, tag, decrypted, aad);
            Check.That(decrypted.SequenceEqual(plaintext), $"{what}: round trip");
            byte[] inPlace = ciphertext.ToArray();
            Decrypt(cipher, nonce, inPlace, tag, inPlace, aad);
            Check.That(inPlace.AsSpan().SequenceEqual(plaintext), $"{what}: in-place decrypt");
            byte[] encryptInPlace = plaintext.ToArray();
            Span<byte> tag2 = Exact(tagSize, atStart);
            Encrypt(cipher, nonce, encryptInPlace, encryptInPlace, tag2, aad);
            Check.That(encryptInPlace.AsSpan().SequenceEqual(ciphertext) && tag2.SequenceEqual(tag), $"{what}: in-place encrypt");
            if (tagSize > 0)
            {
                byte[] badTag = tag.ToArray();
                badTag[flags % tagSize] ^= 0x01;
                Tampered(cipher, nonce, ciphertext.ToArray(), badTag, plaintext.Length, aad, $"{what}: tampered tag");
            }

            if (plaintext.Length > 0)
            {
                byte[] badCiphertext = ciphertext.ToArray();
                badCiphertext[flags % plaintext.Length] ^= 0x80;
                Tampered(cipher, nonce, badCiphertext, tag.ToArray(), plaintext.Length, aad, $"{what}: tampered ciphertext");
            }

            Tampered(cipher, nonce, ciphertext.ToArray(), tag.ToArray(), plaintext.Length, [.. aad, 0x01], $"{what}: tampered AAD");
            // A wrong-sized plaintext buffer for the ciphertext is rejected up front.
            try
            {
                Span<byte> wrong = Exact(plaintext.Length + 1, atStart);
                Decrypt(cipher, nonce, ciphertext, tag, wrong, aad);
                Check.That(false, $"{what}: Decrypt accepted a plaintext buffer of the wrong size");
            }
            catch (ArgumentException)
            {
            }
        }
    }

    private static bool Valid(KeySizes sizes, int size) => size >= sizes.MinSize && size <= sizes.MaxSize && (sizes.SkipSize == 0 ? size == sizes.MinSize : (size - sizes.MinSize) % sizes.SkipSize == 0);

    private static void Encrypt(IDisposable cipher, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, ReadOnlySpan<byte> aad)
    {
        switch (cipher)
        {
            case AesGcm g: g.Encrypt(nonce, plaintext, ciphertext, tag, aad); break;
            case AesCcm c: c.Encrypt(nonce, plaintext, ciphertext, tag, aad); break;
            case ChaCha20Poly1305 p: p.Encrypt(nonce, plaintext, ciphertext, tag, aad); break;
        }
    }

    private static void Decrypt(IDisposable cipher, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        switch (cipher)
        {
            case AesGcm g: g.Decrypt(nonce, ciphertext, tag, plaintext, aad); break;
            case AesCcm c: c.Decrypt(nonce, ciphertext, tag, plaintext, aad); break;
            case ChaCha20Poly1305 p: p.Decrypt(nonce, ciphertext, tag, plaintext, aad); break;
        }
    }

    private static void Tampered(IDisposable cipher, byte[] nonce, byte[] ciphertext, byte[] tag, int length, byte[] aad, string what)
    {
        Span<byte> plaintext = Exact(length, true);
        try
        {
            Decrypt(cipher, nonce, ciphertext, tag, plaintext, aad);
            Check.That(false, $"{what}: accepted");
        }
        catch (AuthenticationTagMismatchException)
        {
            Check.That(plaintext.ToArray().All(b => b == 0xCC) || plaintext.ToArray().All(b => b == 0), $"{what}: plaintext left partially decrypted");
        }
    }

    // ------------------------------------------------------------ AES / TripleDES modes

    private static void Symmetric(ref FuzzInput input, byte flags, byte chunking)
    {
        bool atStart = (flags & 1) != 0;
        bool triple = (flags & 2) != 0;
        var padding = (PaddingMode)((flags >> 2) % 5 + 1);
        int mode = (flags >> 5) % 3; // CBC, ECB, CFB
        using SymmetricAlgorithm algorithm = triple ? TripleDES.Create() : Aes.Create();
        int keySize = triple ? 24 : ((flags >> 4) % 3) switch { 0 => 16, 1 => 24, _ => 32 }; // TripleDES: 3-key only (OpenSSL 3.0)
        byte[] key = new byte[keySize];
        input.Bytes(keySize).CopyTo(key);
        byte[] iv = new byte[algorithm.BlockSize / 8];
        input.Bytes(iv.Length).CopyTo(iv);
        byte[] plaintext = input.Rest().ToArray();
        int block = algorithm.BlockSize / 8;
        string what = $"{(triple ? "TripleDES" : "AES")} {(mode == 0 ? "CBC" : mode == 1 ? "ECB" : "CFB")} {padding} key {keySize} plaintext {plaintext.Length}";
        if (triple && TripleDES.IsWeakKey(key))
        {
            return; // weak / degenerate keys are rejected by design; not what this target checks
        }

        try
        {
            algorithm.Key = key;
        }
        catch (CryptographicException)
        {
            return;
        }

        int cfbFeedback = 8; // CFB8: one feedback byte, so the length model stays exact
        bool aligned = plaintext.Length % block == 0;
        byte[] ciphertext;
        try
        {
            ciphertext = mode switch
            {
                0 => algorithm.EncryptCbc(plaintext, iv, padding),
                1 => algorithm.EncryptEcb(plaintext, padding),
                _ => algorithm.EncryptCfb(plaintext, iv, padding, cfbFeedback),
            };
        }
        catch (Exception e) when (Allowed(e))
        {
            // PaddingMode.None with an unaligned length is the only expected rejection; other provider policy
            // (key rules, feedback support) is out of scope for this round-trip target.
            Check.That(padding == PaddingMode.None && !aligned || e is not ArgumentException, $"{what}: encryption rejected: {e.Message}");
            return;
        }

        int expectedLength = mode switch { 0 => algorithm.GetCiphertextLengthCbc(plaintext.Length, padding), 1 => algorithm.GetCiphertextLengthEcb(plaintext.Length, padding), _ => algorithm.GetCiphertextLengthCfb(plaintext.Length, padding, cfbFeedback) };
        Check.Equal(expectedLength, ciphertext.Length, $"{what}: ciphertext length");
        // Span one-shots into exact and short buffers.
        Span<byte> exact = Exact(ciphertext.Length, atStart);
        int written;
        bool ok = mode switch
        {
            0 => algorithm.TryEncryptCbc(plaintext, iv, exact, out written, padding),
            1 => algorithm.TryEncryptEcb(plaintext, exact, padding, out written),
            _ => algorithm.TryEncryptCfb(plaintext, iv, exact, out written, padding, cfbFeedback),
        };
        Check.That(ok && written == ciphertext.Length && (padding == PaddingMode.ISO10126 || exact.SequenceEqual(ciphertext)), $"{what}: TryEncrypt exact");
        if (ciphertext.Length > 0)
        {
            Span<byte> shorter = Exact(ciphertext.Length - 1, !atStart);
            ok = mode switch
            {
                0 => algorithm.TryEncryptCbc(plaintext, iv, shorter, out written, padding),
                1 => algorithm.TryEncryptEcb(plaintext, shorter, padding, out written),
                _ => algorithm.TryEncryptCfb(plaintext, iv, shorter, out written, padding, cfbFeedback),
            };
            Check.That(!ok && written == 0 && shorter.ToArray().All(b => b == 0xCC), $"{what}: TryEncrypt short");
        }

        // Decrypt round trip (ISO10126 pads with random bytes, so only the plaintext is compared).
        byte[] decrypted = mode switch
        {
            0 => algorithm.DecryptCbc(ciphertext, iv, padding),
            1 => algorithm.DecryptEcb(ciphertext, padding),
            _ => algorithm.DecryptCfb(ciphertext, iv, padding, cfbFeedback),
        };
        if (padding == PaddingMode.Zeros)
        {
            Check.That(decrypted.AsSpan(0, plaintext.Length).SequenceEqual(plaintext) && decrypted.AsSpan(plaintext.Length).ToArray().All(b => b == 0), $"{what}: round trip (zeros)");
        }
        else
        {
            Check.That(decrypted.AsSpan().SequenceEqual(plaintext), $"{what}: round trip");
        }

        // The transform / CryptoStream path in fuzzed chunks gives the same ciphertext (PKCS7, ANSIX923, None, Zeros).
        if (padding != PaddingMode.ISO10126 && mode != 2)
        {
            algorithm.Mode = mode == 0 ? CipherMode.CBC : CipherMode.ECB;
            algorithm.Padding = padding;
            algorithm.IV = iv;
            var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, algorithm.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true))
            {
                foreach (byte[] chunk in Chunks(plaintext, chunking))
                {
                    cs.Write(chunk);
                }
            }

            Check.That(ms.ToArray().AsSpan().SequenceEqual(ciphertext), $"{what}: CryptoStream in chunks");
            using ICryptoTransform transform = algorithm.CreateEncryptor();
            var pieces = new List<byte>();
            var carry = new List<byte>();
            foreach (byte[] chunk in Chunks(plaintext, chunking + 1))
            {
                carry.AddRange(chunk);
                int whole = carry.Count / block * block; // TransformBlock only accepts block-multiple counts
                if (whole > 0)
                {
                    byte[] outBuffer = new byte[whole];
                    int n = transform.TransformBlock(carry.ToArray(), 0, whole, outBuffer, 0);
                    pieces.AddRange(outBuffer.AsSpan(0, n).ToArray());
                    carry.RemoveRange(0, whole);
                }
            }

            pieces.AddRange(transform.TransformFinalBlock(carry.ToArray(), 0, carry.Count));
            Check.That(pieces.ToArray().AsSpan().SequenceEqual(ciphertext), $"{what}: TransformBlock in chunks");
            // Decrypt through a reading CryptoStream in chunks.
            using ICryptoTransform decryptor = algorithm.CreateDecryptor();
            using var reader = new CryptoStream(new MemoryStream(ciphertext), decryptor, CryptoStreamMode.Read);
            var all = new List<byte>();
            int size = chunking % 7 + 1;
            byte[] buffer = new byte[size];
            int read;
            while ((read = reader.Read(buffer, 0, size)) > 0)
            {
                all.AddRange(buffer.AsSpan(0, read).ToArray());
            }

            Check.That(all.ToArray().AsSpan().SequenceEqual(decrypted), $"{what}: CryptoStream decrypt in {size}-byte reads");
        }

        // Corrupted padding is rejected (PKCS7 / ANSIX923) or ignored (None / Zeros).
        if (ciphertext.Length >= block && mode == 0 && padding is PaddingMode.PKCS7 or PaddingMode.ANSIX923)
        {
            byte[] bad = ciphertext.ToArray();
            bad[^1] ^= 0xFF;
            try
            {
                algorithm.DecryptCbc(bad, iv, padding);
            }
            catch (CryptographicException)
            {
            }
        }
    }

    // ------------------------------------------------------------ KDFs and the RNG

    private static void Kdf(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        var (name, _) = s_hashes[(flags >> 1) % 3 + 2]; // SHA256 / SHA384 / SHA512: the ones PBKDF2 / HKDF accept
        byte[] password = input.Bytes(input.Byte() % 40).ToArray();
        byte[] salt = input.Bytes(input.Byte() % 40).ToArray();
        int iterations = input.Byte() % 20 + 1;
        int length = input.UInt16() % 300;
        byte[] info = input.Rest().ToArray();
        string what = $"{name.Name} PBKDF2 pw {password.Length} salt {salt.Length} iterations {iterations} length {length}";

        byte[] reference = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, name, length);
        Check.Equal(length, reference.Length, $"{what}: length");
        Span<byte> exact = Exact(length, atStart);
        Rfc2898DeriveBytes.Pbkdf2(password, salt, exact, iterations, name);
        Check.That(exact.SequenceEqual(reference), $"{what}: span overload");
        if (salt.Length >= 8)
        {
            using var legacy = new Rfc2898DeriveBytes(password, salt, iterations, name);
            int first = Math.Clamp(length / 3, 1, Math.Max(1, length - 1));
            if (length >= 2)
            {
                byte[] a = legacy.GetBytes(first);      // GetBytes rejects a zero count
                byte[] b = legacy.GetBytes(length - first);
                Check.That(a.Concat(b).SequenceEqual(reference), $"{what}: Rfc2898DeriveBytes.GetBytes in two calls");
                legacy.Reset();
            }

            if (length >= 1)
            {
                Check.That(legacy.GetBytes(length).SequenceEqual(reference), $"{what}: Rfc2898DeriveBytes after Reset");
            }
        }

        // HKDF: extract, expand and derive against each other, into exact buffers.
        int hashLength = HashOneShot(name, []).Length;
        Span<byte> prk = Exact(hashLength, !atStart);
        Check.Equal(hashLength, HKDF.Extract(name, password, salt, prk), $"{what}: HKDF.Extract length");
        Check.That(prk.SequenceEqual(HKDF.Extract(name, password, salt)), $"{what}: HKDF.Extract");
        int okmLength = length % (255 * hashLength) + 1; // HKDF output is 1..255*hashLength
        Span<byte> okm = Exact(okmLength, atStart);
        HKDF.Expand(name, prk, okm, info);
        Check.That(okm.SequenceEqual(HKDF.Expand(name, prk.ToArray(), okmLength, info)), $"{what}: HKDF.Expand");
        Span<byte> derived = Exact(okmLength, !atStart);
        HKDF.DeriveKey(name, password, derived, salt, info);
        Check.That(derived.SequenceEqual(okm), $"{what}: HKDF.DeriveKey = Expand(Extract)");
        try
        {
            HKDF.Expand(name, prk, new byte[255 * hashLength + 1], info);
            Check.That(false, $"{what}: HKDF.Expand accepted too long an output");
        }
        catch (ArgumentException)
        {
        }

        _ = okm.Length;

        // SP800-108 counter mode (output length >= 1).
        int kdfLen = Math.Max(1, length);
        Span<byte> kdf = Exact(kdfLen, atStart);
        SP800108HmacCounterKdf.DeriveBytes(password, name, salt, info, kdf);
        Check.That(kdf.SequenceEqual(SP800108HmacCounterKdf.DeriveBytes(password, name, salt, info, kdfLen)), $"{what}: SP800108HmacCounterKdf");
        using var counterKdf = new SP800108HmacCounterKdf(password, name);
        Check.That(kdf.SequenceEqual(counterKdf.DeriveKey(salt, info, kdfLen)), $"{what}: SP800108HmacCounterKdf instance");

        // The RNG: exact fills, ranges, and the helpers.
        Span<byte> random = Exact(length, !atStart);
        RandomNumberGenerator.Fill(random);
        Check.That(length < 16 || !random.ToArray().All(b => b == 0xCC), $"{what}: Fill left the buffer untouched");
        byte[] array = new byte[length + 8];
        array.AsSpan().Fill(0xCC);
        RandomNumberGenerator.Fill(array.AsSpan(4, length));
        Check.That(array.AsSpan(0, 4).ToArray().All(b => b == 0xCC) && array.AsSpan(length + 4).ToArray().All(b => b == 0xCC), $"{what}: Fill wrote outside the slice");
        int from = iterations - 10, to = from + length + 1;
        int value = RandomNumberGenerator.GetInt32(from, to);
        Check.That(value >= from && value < to, $"{what}: GetInt32({from}, {to}) = {value}");
        Check.Equal(length, RandomNumberGenerator.GetHexString(length).Length, $"{what}: GetHexString length");
        Check.Equal(length, RandomNumberGenerator.GetString("abc", length).Length, $"{what}: GetString length");
        Check.That(RandomNumberGenerator.GetString("abc", length).All(c => c is 'a' or 'b' or 'c'), $"{what}: GetString choices");
    }

    // ------------------------------------------------------------ fuzzed key parameters

    private static void Parameters(ref FuzzInput input, byte flags)
    {
        int kind = flags % 4;
        switch (kind)
        {
            case 0:
            {
                // RSA parameters: sizes and values from the input, some derived from the real key.
                RSAParameters real = s_rsa.Value.ExportParameters(true);
                var p = new RSAParameters
                {
                    Modulus = Pick(ref input, real.Modulus), Exponent = Pick(ref input, real.Exponent), D = Pick(ref input, real.D), P = Pick(ref input, real.P), Q = Pick(ref input, real.Q),
                    DP = Pick(ref input, real.DP), DQ = Pick(ref input, real.DQ), InverseQ = Pick(ref input, real.InverseQ),
                };
                string what = $"RSAParameters n {p.Modulus?.Length} e {p.Exponent?.Length} d {p.D?.Length} p {p.P?.Length} q {p.Q?.Length}";
                using RSA rsa = RSA.Create();
                try
                {
                    rsa.ImportParameters(p);
                }
                catch (Exception e) when (Allowed(e))
                {
                    return;
                }

                // Whatever was accepted must work as a key pair, or at least as a public key.
                byte[] data = input.Rest().ToArray();
                if (p.D is not null)
                {
                    try
                    {
                        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                        Check.That(rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), $"{what}: accepted key pair doesn't verify its own signature");
                        byte[] encrypted = rsa.Encrypt(data.AsSpan(0, Math.Min(data.Length, 32)).ToArray(), RSAEncryptionPadding.OaepSHA256);
                        Check.That(rsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256).AsSpan().SequenceEqual(data.AsSpan(0, Math.Min(data.Length, 32))), $"{what}: accepted key pair doesn't decrypt its own ciphertext");
                    }
                    catch (CryptographicException)
                    {
                        // Accepted at import, rejected at use: inconsistent parameters are caught late but caught.
                    }
                }

                RSAParameters back = rsa.ExportParameters(false);
                Check.That(back.Modulus.AsSpan().TrimStart((byte)0).SequenceEqual(p.Modulus.AsSpan().TrimStart((byte)0)), $"{what}: modulus round trip");
                break;
            }
            case 1:
            {
                ECCurve curve = ((flags >> 2) % 4) switch { 0 => ECCurve.NamedCurves.nistP256, 1 => ECCurve.NamedCurves.nistP384, 2 => ECCurve.NamedCurves.nistP521, _ => ECCurve.NamedCurves.brainpoolP256r1 };
                ECParameters real;
                try
                {
                    using ECDsa key = ECDsa.Create(curve);
                    real = key.ExportParameters(true);
                }
                catch (Exception e) when (Allowed(e))
                {
                    return; // curve not available
                }

                var p = new ECParameters { Curve = curve, Q = new ECPoint { X = Pick(ref input, real.Q.X), Y = Pick(ref input, real.Q.Y) }, D = (flags & 0x80) != 0 ? null : Pick(ref input, real.D) };
                string what = $"ECParameters {curve.Oid.FriendlyName} X {p.Q.X?.Length} Y {p.Q.Y?.Length} D {p.D?.Length}";
                using ECDsa ecdsa = ECDsa.Create();
                try
                {
                    ecdsa.ImportParameters(p);
                }
                catch (Exception e) when (Allowed(e))
                {
                    return;
                }

                byte[] data = input.Rest().ToArray();
                if (p.D is not null)
                {
                    try
                    {
                        byte[] signature = ecdsa.SignData(data, HashAlgorithmName.SHA256);
                        Check.That(ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256), $"{what}: accepted key pair doesn't verify its own signature");
                    }
                    catch (CryptographicException)
                    {
                    }
                }

                // ECDH with a public key built from the same fuzzed point.
                using ECDiffieHellman ecdh = ECDiffieHellman.Create();
                try
                {
                    ecdh.ImportParameters(new ECParameters { Curve = curve, Q = p.Q, D = p.D });
                    using ECDiffieHellman other = ECDiffieHellman.Create(curve);
                    if (p.D is not null)
                    {
                        byte[] secret1 = ecdh.DeriveRawSecretAgreement(other.PublicKey);
                        byte[] secret2 = other.DeriveRawSecretAgreement(ecdh.PublicKey);
                        Check.That(secret1.SequenceEqual(secret2), $"{what}: ECDH secrets differ");
                        Check.That(ecdh.DeriveKeyMaterial(other.PublicKey).SequenceEqual(other.DeriveKeyMaterial(ecdh.PublicKey)), $"{what}: ECDH key material differs");
                    }
                }
                catch (Exception e) when (Allowed(e))
                {
                }

                break;
            }
            case 2:
            {
                DSAParameters real = s_dsa.Value.ExportParameters(true);
                var p = new DSAParameters { P = Pick(ref input, real.P), Q = Pick(ref input, real.Q), G = Pick(ref input, real.G), Y = Pick(ref input, real.Y), X = (flags & 0x80) != 0 ? null : Pick(ref input, real.X), Counter = real.Counter, Seed = real.Seed };
                string what = $"DSAParameters p {p.P?.Length} q {p.Q?.Length} g {p.G?.Length} y {p.Y?.Length} x {p.X?.Length}";
                using DSA dsa = DSA.Create();
                try
                {
                    dsa.ImportParameters(p);
                }
                catch (Exception e) when (Allowed(e))
                {
                    return;
                }

                byte[] data = input.Rest().ToArray();
                if (p.X is not null)
                {
                    try
                    {
                        byte[] signature = dsa.SignData(data, HashAlgorithmName.SHA1);
                        Check.That(dsa.VerifyData(data, signature, HashAlgorithmName.SHA1), $"{what}: accepted key pair doesn't verify its own signature");
                    }
                    catch (CryptographicException)
                    {
                    }
                }

                break;
            }
            default:
            {
                // Key blobs: DER / PEM / PKCS#8 / encrypted PKCS#8 importers over arbitrary bytes.
                byte[] blob = input.Rest().ToArray();
                string what = $"key blob of {blob.Length} bytes";
                using RSA rsa = RSA.Create();
                using ECDsa ecdsa = ECDsa.Create();
                foreach ((string name, Action import) in (ValueTuple<string, Action>[])
                [
                    ("RSA ImportRSAPublicKey", () => rsa.ImportRSAPublicKey(blob, out _)), ("RSA ImportRSAPrivateKey", () => rsa.ImportRSAPrivateKey(blob, out _)),
                    ("RSA ImportSubjectPublicKeyInfo", () => rsa.ImportSubjectPublicKeyInfo(blob, out _)), ("RSA ImportPkcs8PrivateKey", () => rsa.ImportPkcs8PrivateKey(blob, out _)),
                    ("RSA ImportEncryptedPkcs8PrivateKey", () => rsa.ImportEncryptedPkcs8PrivateKey("pw"u8, blob, out _)), ("RSA ImportFromPem", () => rsa.ImportFromPem(Encoding.UTF8.GetString(blob))),
                    ("ECDsa ImportSubjectPublicKeyInfo", () => ecdsa.ImportSubjectPublicKeyInfo(blob, out _)), ("ECDsa ImportPkcs8PrivateKey", () => ecdsa.ImportPkcs8PrivateKey(blob, out _)),
                    ("ECDsa ImportECPrivateKey", () => ecdsa.ImportECPrivateKey(blob, out _)), ("ECDsa ImportFromPem", () => ecdsa.ImportFromPem(Encoding.UTF8.GetString(blob))),
                ])
                {
                    try
                    {
                        import();
                    }
                    catch (Exception e) when (Allowed(e))
                    {
                    }
                }

                break;
            }
        }
    }

    /// <summary>A parameter from the input: the real value, a truncated / extended / mutated copy, or random bytes.</summary>
    private static byte[] Pick(ref FuzzInput input, byte[] real)
    {
        int mode = input.Byte() % 8;
        switch (mode)
        {
            case 0: case 1: case 2: return real;
            case 3: return real.AsSpan(0, Math.Min(real.Length, input.Byte())).ToArray();
            case 4: return [.. real, .. input.Bytes(input.Byte() % 8)];
            case 5:
            {
                byte[] copy = real.ToArray();
                if (copy.Length > 0)
                {
                    copy[input.Byte() % copy.Length] ^= (byte)(input.Byte() | 1);
                }

                return copy;
            }
            case 6: return null;
            default: return input.Bytes(input.Byte()).ToArray();
        }
    }

    // ------------------------------------------------------------ signatures and encryption round trips

    private static void Signatures(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        byte[] data = input.Rest().ToArray();
        HashAlgorithmName hash = ((flags >> 1) % 3) switch { 0 => HashAlgorithmName.SHA256, 1 => HashAlgorithmName.SHA384, _ => HashAlgorithmName.SHA512 };
        RSASignaturePadding padding = (flags & 8) != 0 ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        RSA rsa = s_rsa.Value;
        string what = $"RSA {hash.Name} {padding.Mode} over {data.Length} bytes";
        int max = rsa.KeySize / 8;
        Span<byte> signature = Exact(max, atStart);
        Check.That(rsa.TrySignData(data, signature, hash, padding, out int written) && written == max, $"{what}: TrySignData exact");
        Check.That(rsa.VerifyData(data, signature, hash, padding), $"{what}: VerifyData");
        Span<byte> shorter = Exact(max - 1, !atStart);
        Check.That(!rsa.TrySignData(data, shorter, hash, padding, out written) && written == 0, $"{what}: TrySignData short");
        byte[] tampered = signature.ToArray();
        tampered[flags % max] ^= 0x01;
        Check.That(!rsa.VerifyData(data, tampered, hash, padding), $"{what}: tampered signature verified");
        if (data.Length > 0)
        {
            byte[] otherData = data.ToArray();
            otherData[flags % data.Length] ^= 0x01;
            Check.That(!rsa.VerifyData(otherData, signature, hash, padding), $"{what}: signature verified other data");
        }

        byte[] digest = HashOneShot(hash, data);
        Span<byte> hashSignature = Exact(max, atStart);
        Check.That(rsa.TrySignHash(digest, hashSignature, hash, padding, out written) && written == max && rsa.VerifyHash(digest, hashSignature, hash, padding), $"{what}: TrySignHash / VerifyHash");
        if (padding == RSASignaturePadding.Pkcs1)
        {
            Check.That(hashSignature.SequenceEqual(signature), $"{what}: PKCS#1 signatures are deterministic");
        }

        // Encryption round trips into exact buffers, OAEP and PKCS#1.
        RSAEncryptionPadding encryption = ((flags >> 4) % 3) switch { 0 => RSAEncryptionPadding.Pkcs1, 1 => RSAEncryptionPadding.OaepSHA1, _ => RSAEncryptionPadding.OaepSHA256 };
        int room = encryption.Mode == RSAEncryptionPaddingMode.Pkcs1 ? max - 11 : max - 2 * HashOneShot(encryption.OaepHashAlgorithm, []).Length - 2;
        byte[] message = data.AsSpan(0, Math.Min(data.Length, room + (flags >> 7))).ToArray();
        Span<byte> ciphertext = Exact(max, !atStart);
        try
        {
            Check.That(rsa.TryEncrypt(message, ciphertext, encryption, out written) && written == max, $"{what}: TryEncrypt {encryption.Mode} {message.Length} bytes");
        }
        catch (CryptographicException)
        {
            Check.That(message.Length > room, $"{what}: TryEncrypt rejected {message.Length} bytes with room for {room}");
            return;
        }

        Check.That(message.Length <= room, $"{what}: TryEncrypt accepted {message.Length} bytes with room for {room}");
        Span<byte> decrypted = Exact(message.Length, atStart);
        Check.That(rsa.TryDecrypt(ciphertext, decrypted, encryption, out written) && written == message.Length && decrypted.SequenceEqual(message), $"{what}: TryDecrypt exact");
        Check.That(rsa.Decrypt(ciphertext.ToArray(), encryption).AsSpan().SequenceEqual(message), $"{what}: Decrypt");
        if (message.Length > 0)
        {
            Span<byte> tooSmall = Exact(message.Length - 1, !atStart);
            Check.That(!rsa.TryDecrypt(ciphertext, tooSmall, encryption, out written) && written == 0, $"{what}: TryDecrypt short");
        }

        byte[] badCiphertext = ciphertext.ToArray();
        badCiphertext[flags % max] ^= 0x01;
        try
        {
            byte[] junk = rsa.Decrypt(badCiphertext, encryption);
            Check.That(encryption.Mode == RSAEncryptionPaddingMode.Pkcs1, $"{what}: tampered OAEP ciphertext decrypted to {junk.Length} bytes");
        }
        catch (CryptographicException)
        {
        }

        // ECDSA in both signature formats.
        ECDsa ecdsa = s_ecdsa.Value;
        foreach (DSASignatureFormat format in (DSASignatureFormat[])[DSASignatureFormat.IeeeP1363FixedFieldConcatenation, DSASignatureFormat.Rfc3279DerSequence])
        {
            int maxEc = ecdsa.GetMaxSignatureSize(format);
            Span<byte> ecSignature = Exact(maxEc, atStart);
            Check.That(ecdsa.TrySignData(data, ecSignature, hash, format, out written) && written <= maxEc && written > 0, $"{what}: ECDSA TrySignData {format}");
            Check.That(ecdsa.VerifyData(data, ecSignature.Slice(0, written), hash, format), $"{what}: ECDSA VerifyData {format}");
            Check.That(format == DSASignatureFormat.Rfc3279DerSequence || written == maxEc, $"{what}: fixed-field signature of {written} bytes, expected {maxEc}");
            byte[] ecTampered = ecSignature.Slice(0, written).ToArray();
            ecTampered[flags % written] ^= 0x01;
            Check.That(!ecdsa.VerifyData(data, ecTampered, hash, format), $"{what}: ECDSA tampered signature verified {format}");
        }
    }

    // ------------------------------------------------------------ key export / import round trips

    private static void Keys(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        string password = new string((input.Bytes(input.Byte() % 30).ToArray()).Select(b => (char)('a' + b % 26)).ToArray());
        int iterations = input.Byte() % 5 + 1;
        bool aesPbe = (flags & 2) != 0;
        var pbe = new PbeParameters(aesPbe ? PbeEncryptionAlgorithm.Aes256Cbc : PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, aesPbe ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA1, iterations); // PKCS#12 requires a SHA-1 PRF
        AsymmetricAlgorithm key = ((flags >> 2) % 3) switch { 0 => (AsymmetricAlgorithm)s_rsa.Value, 1 => s_ecdsa.Value, _ => s_dsa.Value };
        string what = $"{key.GetType().Name} key export";
        // Exports into exactly sized buffers must match the allocating exports and import back.
        byte[] spki = key.ExportSubjectPublicKeyInfo();
        Span<byte> spkiExact = Exact(spki.Length, atStart);
        Check.That(key.TryExportSubjectPublicKeyInfo(spkiExact, out int written) && written == spki.Length && spkiExact.SequenceEqual(spki), $"{what}: TryExportSubjectPublicKeyInfo exact");
        Span<byte> spkiShort = Exact(spki.Length - 1, !atStart);
        Check.That(!key.TryExportSubjectPublicKeyInfo(spkiShort, out written) && written == 0, $"{what}: TryExportSubjectPublicKeyInfo short");
        byte[] pkcs8 = key.ExportPkcs8PrivateKey();
        Span<byte> pkcs8Exact = Exact(pkcs8.Length, atStart);
        Check.That(key.TryExportPkcs8PrivateKey(pkcs8Exact, out written) && written == pkcs8.Length && pkcs8Exact.SequenceEqual(pkcs8), $"{what}: TryExportPkcs8PrivateKey exact");
        byte[] encrypted = key.ExportEncryptedPkcs8PrivateKey(password, pbe);
        Span<byte> encryptedExact = Exact(encrypted.Length, !atStart);
        Check.That(key.TryExportEncryptedPkcs8PrivateKey(password, pbe, encryptedExact, out written) && written == encrypted.Length, $"{what}: TryExportEncryptedPkcs8PrivateKey exact");
        using AsymmetricAlgorithm fresh = key switch { RSA => RSA.Create(), ECDsa => ECDsa.Create(), _ => DSA.Create() };
        fresh.ImportSubjectPublicKeyInfo(spki, out int consumed);
        Check.Equal(spki.Length, consumed, $"{what}: ImportSubjectPublicKeyInfo consumed");
        Check.That(fresh.ExportSubjectPublicKeyInfo().SequenceEqual(spki), $"{what}: SubjectPublicKeyInfo round trip");
        fresh.ImportPkcs8PrivateKey(pkcs8, out consumed);
        Check.Equal(pkcs8.Length, consumed, $"{what}: ImportPkcs8PrivateKey consumed");
        Check.That(fresh.ExportPkcs8PrivateKey().SequenceEqual(pkcs8), $"{what}: PKCS#8 round trip");
        fresh.ImportEncryptedPkcs8PrivateKey(password, encryptedExact, out consumed);
        Check.Equal(encrypted.Length, consumed, $"{what}: ImportEncryptedPkcs8PrivateKey consumed");
        Check.That(fresh.ExportPkcs8PrivateKey().SequenceEqual(pkcs8), $"{what}: encrypted PKCS#8 round trip");
        try
        {
            fresh.ImportEncryptedPkcs8PrivateKey(password + "x", encryptedExact, out _);
            Check.That(false, $"{what}: encrypted PKCS#8 imported with the wrong password");
        }
        catch (CryptographicException)
        {
        }

        // PEM.
        string pem = key.ExportPkcs8PrivateKeyPem();
        fresh.ImportFromPem(pem);
        Check.That(fresh.ExportPkcs8PrivateKey().SequenceEqual(pkcs8), $"{what}: PEM round trip");
        char[] pemChars = new char[pem.Length];
        Check.That(key.TryExportPkcs8PrivateKeyPem(pemChars, out int chars) && chars == pem.Length && new string(pemChars).Equals(pem), $"{what}: TryExportPkcs8PrivateKeyPem exact");
        fresh.ImportFromEncryptedPem(key.ExportEncryptedPkcs8PrivateKeyPem(password, pbe), password);
        Check.That(fresh.ExportPkcs8PrivateKey().SequenceEqual(pkcs8), $"{what}: encrypted PEM round trip");
    }
}
