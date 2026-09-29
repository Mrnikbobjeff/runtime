#nullable disable warnings
using System.Buffers.Binary;
using System.IO.Hashing;
using System.Numerics;

namespace SharpFuzzHarness;

/// <summary>Fuzzes System.IO.Hashing (NuGet package): CRC-32/64 with arbitrary parameters, Adler-32, XxHash32/64/3/128.</summary>
/// <remarks>
/// Input layout:
///   byte 0     algorithm; byte 1 chunk pattern
///   CRC        polynomial, initial value, final XOR (4 or 8 bytes each), reflect flag byte
///   XxHash     seed (4 or 8 bytes)
///   rest       the data
/// Checks: the one-shot Hash / TryHash / HashToUIntNN, the incremental Append in chunks,
/// GetCurrentHash (which doesn't reset), Clone() mid-stream and GetHashAndReset all agree; CRCs match
/// a bit-at-a-time implementation of the Rocksoft model for the same parameters, Adler-32 and
/// XxHash32/64 match straightforward reference implementations.
/// </remarks>
public static class HashingTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte algorithm = input.Byte();
        byte pattern = input.Byte();
        switch (algorithm % 8)
        {
            case 0:
            {
                uint poly = (uint)input.Int32(), init = (uint)input.Int32(), xorOut = (uint)input.Int32();
                bool reflect = (input.Byte() & 1) != 0;
                byte[] bytes = input.Rest().ToArray();
                var set = (algorithm / 8 % 3) switch
                {
                    0 => Crc32ParameterSet.Create(poly, init, xorOut, reflect),
                    1 => Crc32ParameterSet.Crc32,
                    _ => Crc32ParameterSet.Crc32C,
                };
                (poly, init, xorOut, reflect) = (algorithm / 8 % 3) switch
                {
                    0 => (poly, init, xorOut, reflect),
                    1 => (0x04C11DB7u, 0xFFFFFFFFu, 0xFFFFFFFFu, true),
                    _ => (0x1EDC6F41u, 0xFFFFFFFFu, 0xFFFFFFFFu, true),
                };
                string what = $"CRC-32 poly 0x{poly:X8} init 0x{init:X8} xor 0x{xorOut:X8} reflect {reflect}, {Show(bytes)}";

                uint expected = (uint)Crc(bytes, poly, init, xorOut, reflect, 32);
                Check.Equal(expected, Crc32.HashToUInt32(set, bytes), $"HashToUInt32 vs reference for {what}");
                Incremental(() => new Crc32(set), h => ((Crc32)h).Clone(), Crc32.Hash(set, bytes), bytes, pattern, what);
                if (algorithm / 8 % 3 == 1)
                {
                    Check.Equal(expected, Crc32.HashToUInt32(bytes), $"default Crc32 for {what}");
                }

                break;
            }

            case 1:
            {
                ulong poly = (ulong)(uint)input.Int32() << 32 | (uint)input.Int32(), init = (ulong)(uint)input.Int32() << 32 | (uint)input.Int32();
                ulong xorOut = (ulong)(uint)input.Int32() << 32 | (uint)input.Int32();
                bool reflect = (input.Byte() & 1) != 0;
                byte[] bytes = input.Rest().ToArray();
                var set = (algorithm / 8 % 3) switch
                {
                    0 => Crc64ParameterSet.Create(poly, init, xorOut, reflect),
                    1 => Crc64ParameterSet.Crc64,
                    _ => Crc64ParameterSet.Nvme,
                };
                (poly, init, xorOut, reflect) = (algorithm / 8 % 3) switch
                {
                    0 => (poly, init, xorOut, reflect),
                    1 => (0x42F0E1EBA9EA3693ul, 0ul, 0ul, false),
                    _ => (0xAD93D23594C93659ul, ulong.MaxValue, ulong.MaxValue, true),
                };
                string what = $"CRC-64 poly 0x{poly:X16} init 0x{init:X16} xor 0x{xorOut:X16} reflect {reflect}, {Show(bytes)}";
                if (!s_reportKnownIssues && reflect && (poly & 1) == 0)
                {
                    // Known (HASH-CRC-EVEN-1): reflected CRC-64 parameter sets with an even polynomial (no
                    // x^0 term) give wrong results on the vectorized path (inputs of 16 bytes or more).
                    break;
                }

                ulong expected = Crc(bytes, poly, init, xorOut, reflect, 64);
                Check.Equal(expected, Crc64.HashToUInt64(set, bytes), $"HashToUInt64 vs reference for {what}");
                Incremental(() => new Crc64(set), h => ((Crc64)h).Clone(), Crc64.Hash(set, bytes), bytes, pattern, what);
                if (algorithm / 8 % 3 == 1)
                {
                    Check.Equal(expected, Crc64.HashToUInt64(bytes), $"default Crc64 for {what}");
                }

                break;
            }

            case 2:
            {
                byte[] bytes = input.Rest().ToArray();
                string what = $"Adler-32 of {Show(bytes)}";
                uint a = 1, b = 0;
                foreach (byte x in bytes)
                {
                    a = (a + x) % 65521;
                    b = (b + a) % 65521;
                }

                Check.Equal(b << 16 | a, Adler32.HashToUInt32(bytes), $"HashToUInt32 vs reference for {what}");
                Incremental(() => new Adler32(), h => ((Adler32)h).Clone(), Adler32.Hash(bytes), bytes, pattern, what);
                break;
            }

            case 3:
            {
                int seed = input.Int32();
                byte[] bytes = input.Rest().ToArray();
                string what = $"XxHash32 seed {seed} of {Show(bytes)}";
                Check.Equal(XxHash32Reference(bytes, (uint)seed), XxHash32.HashToUInt32(bytes, seed), $"HashToUInt32 vs reference for {what}");
                Incremental(() => new XxHash32(seed), h => ((XxHash32)h).Clone(), XxHash32.Hash(bytes, seed), bytes, pattern, what);
                break;
            }

            case 4:
            {
                long seed = (long)((ulong)(uint)input.Int32() << 32 | (uint)input.Int32());
                byte[] bytes = input.Rest().ToArray();
                string what = $"XxHash64 seed {seed} of {Show(bytes)}";
                Check.Equal(XxHash64Reference(bytes, (ulong)seed), XxHash64.HashToUInt64(bytes, seed), $"HashToUInt64 vs reference for {what}");
                Incremental(() => new XxHash64(seed), h => ((XxHash64)h).Clone(), XxHash64.Hash(bytes, seed), bytes, pattern, what);
                break;
            }

            case 5 or 6:
            {
                long seed = (algorithm & 0x80) != 0 ? 0 : (long)((ulong)(uint)input.Int32() << 32 | (uint)input.Int32());
                byte[] bytes = input.Rest().ToArray();
                string what = $"XxHash3 seed {seed} of {Show(bytes)}";
                byte[] oneShot = XxHash3.Hash(bytes, seed);
                Check.Equal(BinaryPrimitives.ReadUInt64BigEndian(oneShot), XxHash3.HashToUInt64(bytes, seed), $"HashToUInt64 vs Hash for {what}");
                Incremental(() => new XxHash3(seed), h => ((XxHash3)h).Clone(), oneShot, bytes, pattern, what);
                break;
            }

            default:
            {
                long seed = (algorithm & 0x80) != 0 ? 0 : (long)((ulong)(uint)input.Int32() << 32 | (uint)input.Int32());
                byte[] bytes = input.Rest().ToArray();
                string what = $"XxHash128 seed {seed} of {Show(bytes)}";
                byte[] oneShot = XxHash128.Hash(bytes, seed);
                Check.Equal(BinaryPrimitives.ReadUInt128BigEndian(oneShot), XxHash128.HashToUInt128(bytes, seed), $"HashToUInt128 vs Hash for {what}");
                Incremental(() => new XxHash128(seed), h => ((XxHash128)h).Clone(), oneShot, bytes, pattern, what);
                break;
            }
        }
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    private static string Show(byte[] b) => $"{b.Length} bytes 0x{Convert.ToHexString(b.AsSpan(0, Math.Min(b.Length, 48)))}{(b.Length > 48 ? "..." : "")}";

    /// <summary>Append in chunks (sizes from the pattern, including big ones), with GetCurrentHash and a Clone taken midway.</summary>
    private static void Incremental(Func<NonCryptographicHashAlgorithm> create, Func<NonCryptographicHashAlgorithm, NonCryptographicHashAlgorithm> clone, byte[] expected, byte[] bytes, byte pattern, string what)
    {
        byte[] tried = new byte[expected.Length];
        Check.That(!create().TryGetCurrentHash(tried.AsSpan(0, expected.Length - 1), out _), $"TryGetCurrentHash into a short buffer for {what}");

        NonCryptographicHashAlgorithm hash = create();
        NonCryptographicHashAlgorithm copy = null;
        int copiedAt = 0, position = 0, k = 0;
        while (position < bytes.Length)
        {
            int size = Math.Min(bytes.Length - position, (pattern >> (k++ % 4 * 2) & 3) switch { 0 => 1, 1 => 3 + k % 13, 2 => 16 + pattern % 50, _ => 256 + pattern * 3 });
            hash.Append(bytes.AsSpan(position, size));
            position += size;
            if (copy is null && (pattern & 0x40) != 0 && position >= bytes.Length / 2)
            {
                copy = clone(hash);
                copiedAt = position;
            }

            if (k % 3 == 0)
            {
                _ = hash.GetCurrentHash(); // must not change the state
            }
        }

        Check.That(expected.AsSpan().SequenceEqual(hash.GetCurrentHash()), $"chunked Append vs one-shot for {what}");
        if (copy is not null)
        {
            copy.Append(bytes.AsSpan(copiedAt));
            Check.That(expected.AsSpan().SequenceEqual(copy.GetCurrentHash()), $"Clone() at {copiedAt} then the rest vs one-shot for {what}");
        }

        Check.That(expected.AsSpan().SequenceEqual(hash.GetHashAndReset()), $"GetHashAndReset for {what}");
        hash.Append(bytes);
        Check.That(expected.AsSpan().SequenceEqual(hash.GetCurrentHash()), $"after reset, Append all vs one-shot for {what}");
        var stream = new MemoryStream(bytes);
        NonCryptographicHashAlgorithm fromStream = create();
        fromStream.Append(stream);
        Check.That(expected.AsSpan().SequenceEqual(fromStream.GetCurrentHash()), $"Append(Stream) vs one-shot for {what}");
    }

    /// <summary>Bit-at-a-time CRC per the Rocksoft model (refin = refout = reflect).</summary>
    private static ulong Crc(byte[] bytes, ulong poly, ulong init, ulong xorOut, bool reflect, int width)
    {
        ulong top = 1ul << (width - 1), mask = width == 64 ? ulong.MaxValue : (1ul << width) - 1;
        // Known (HASH-CRC-INIT-1): for reflected parameter sets System.IO.Hashing loads the initial value
        // into the reflected register as is, where the Rocksoft model (and the CRC catalogue) reflect it;
        // the two differ only for initial values that aren't bit palindromes.
        if (reflect && !s_reportKnownIssues)
        {
            init = BitReverse(init) >> (64 - width);
        }

        ulong reg = init & mask;
        foreach (byte b in bytes)
        {
            byte x = reflect ? (byte)(BitReverse(b) >> 56) : b;
            reg ^= (ulong)x << (width - 8);
            for (int i = 0; i < 8; i++)
            {
                reg = ((reg & top) != 0 ? (reg << 1) ^ poly : reg << 1) & mask;
            }
        }

        if (reflect)
        {
            reg = BitReverse(reg) >> (64 - width);
        }

        return (reg ^ xorOut) & mask;
    }

    private static ulong BitReverse(ulong v)
    {
        ulong r = 0;
        for (int i = 0; i < 64; i++)
        {
            r = r << 1 | (v >> i & 1);
        }

        return r;
    }

    private static uint XxHash32Reference(byte[] b, uint seed)
    {
        const uint P1 = 2654435761u, P2 = 2246822519u, P3 = 3266489917u, P4 = 668265263u, P5 = 374761393u;
        static uint Round(uint acc, uint lane) => BitOperations.RotateLeft(acc + lane * P2, 13) * P1;
        int i = 0;
        uint h;
        if (b.Length >= 16)
        {
            uint v1 = seed + P1 + P2, v2 = seed + P2, v3 = seed, v4 = seed - P1;
            for (; i + 16 <= b.Length; i += 16)
            {
                v1 = Round(v1, BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(i)));
                v2 = Round(v2, BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(i + 4)));
                v3 = Round(v3, BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(i + 8)));
                v4 = Round(v4, BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(i + 12)));
            }

            h = BitOperations.RotateLeft(v1, 1) + BitOperations.RotateLeft(v2, 7) + BitOperations.RotateLeft(v3, 12) + BitOperations.RotateLeft(v4, 18);
        }
        else
        {
            h = seed + P5;
        }

        h += (uint)b.Length;
        for (; i + 4 <= b.Length; i += 4)
        {
            h = BitOperations.RotateLeft(h + BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(i)) * P3, 17) * P4;
        }

        for (; i < b.Length; i++)
        {
            h = BitOperations.RotateLeft(h + b[i] * P5, 11) * P1;
        }

        h ^= h >> 15;
        h *= P2;
        h ^= h >> 13;
        h *= P3;
        return h ^ h >> 16;
    }

    private static ulong XxHash64Reference(byte[] b, ulong seed)
    {
        const ulong P1 = 11400714785074694791ul, P2 = 14029467366897019727ul, P3 = 1609587929392839161ul, P4 = 9650029242287828579ul, P5 = 2870177450012600261ul;
        static ulong Round(ulong acc, ulong lane) => BitOperations.RotateLeft(acc + lane * P2, 31) * P1;
        static ulong Merge(ulong acc, ulong v) => (acc ^ Round(0, v)) * P1 + P4;
        int i = 0;
        ulong h;
        if (b.Length >= 32)
        {
            ulong v1 = seed + P1 + P2, v2 = seed + P2, v3 = seed, v4 = seed - P1;
            for (; i + 32 <= b.Length; i += 32)
            {
                v1 = Round(v1, BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(i)));
                v2 = Round(v2, BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(i + 8)));
                v3 = Round(v3, BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(i + 16)));
                v4 = Round(v4, BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(i + 24)));
            }

            h = BitOperations.RotateLeft(v1, 1) + BitOperations.RotateLeft(v2, 7) + BitOperations.RotateLeft(v3, 12) + BitOperations.RotateLeft(v4, 18);
            h = Merge(Merge(Merge(Merge(h, v1), v2), v3), v4);
        }
        else
        {
            h = seed + P5;
        }

        h += (ulong)b.Length;
        for (; i + 8 <= b.Length; i += 8)
        {
            h = BitOperations.RotateLeft(h ^ Round(0, BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(i))), 27) * P1 + P4;
        }

        if (i + 4 <= b.Length)
        {
            h = BitOperations.RotateLeft(h ^ BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(i)) * P1, 23) * P2 + P3;
            i += 4;
        }

        for (; i < b.Length; i++)
        {
            h = BitOperations.RotateLeft(h ^ b[i] * P5, 11) * P1;
        }

        h ^= h >> 33;
        h *= P2;
        h ^= h >> 29;
        h *= P3;
        return h ^ h >> 32;
    }
}
