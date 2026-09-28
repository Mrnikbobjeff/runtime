#nullable disable warnings
using System.Buffers;
using System.IO.Compression;

namespace SharpFuzzHarness;

/// <summary>
/// The span-based compression encoders / decoders (new in .NET 11: DeflateEncoder / Decoder,
/// ZLibEncoder / Decoder, GZipEncoder / Decoder; and BrotliEncoder / Decoder), whose native code
/// (zlib-ng, brotli) reads and writes the caller's spans through pointers. Sources and destinations
/// are exactly sized and sit against a guard page (see <see cref="Guarded"/>), so native code touching
/// a byte outside them faults.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     codec (Deflate, ZLib, GZip, Brotli) and mode (bit 2: decode the data itself)
///   byte 1     quality / window selection; byte 2 chunk sizes for streaming; byte 3 placement bits
///   rest       the data (up to 16 KB)
/// Checks: one-shot compression succeeds into GetMaxCompressedLength bytes and into exactly the
/// compressed size, fails into one byte less, and matches the same call over arrays; the output and the
/// output of streaming through tiny buffers decompress to the input (one-shot, streaming and the
/// DeflateStream family); decoding arbitrary data gives the same status and bytes from guarded memory
/// as from arrays, into exactly sized and short destinations.
/// </remarks>
public static class UnsafeCompressionTarget
{
    private const int MaxOutput = 1 << 17;

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        byte level = input.Byte();
        byte chunks = input.Byte();
        byte place = input.Byte();
        byte[] bytes = input.Rest().ToArray();
        if (bytes.Length > 16384)
        {
            return;
        }

        int codec = mode & 3;
        bool atStart = (place & 1) != 0;
        string what = $"{Name(codec)} level {level:X2} chunks {chunks:X2} place {place:X2}, {bytes.Length} bytes 0x{Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 32)))}{(bytes.Length > 32 ? "..." : "")}";
        if ((mode & 4) != 0)
        {
            DecodeArbitrary(codec, bytes, chunks, place, what);
        }
        else
        {
            RoundTrip(codec, level, bytes, chunks, atStart, what);
        }
    }

    private static string Name(int codec) => codec switch { 0 => "Deflate", 1 => "ZLib", 2 => "GZip", _ => "Brotli" };

    private static Span<byte> Out(int length, bool atStart) => Guarded.Copy<byte>(new byte[length], atStart);



    private static (int Quality, int Window) Parameters(int codec, byte level) => codec == 3
        ? (level % 12, 10 + (level >> 4) % 15)   // Brotli: quality 0-11, window 10-24
        : (level % 10, ZLibCompressionOptions.MinWindowLog2 + (level >> 4) % (ZLibCompressionOptions.MaxWindowLog2 - ZLibCompressionOptions.MinWindowLog2 + 1)); // zlib: level 0-9

    private static long MaxCompressed(int codec, int length) => codec switch
    {
        0 => DeflateEncoder.GetMaxCompressedLength(length),
        1 => ZLibEncoder.GetMaxCompressedLength(length),
        2 => GZipEncoder.GetMaxCompressedLength(length),
        _ => BrotliEncoder.GetMaxCompressedLength(length),
    };

    private static bool TryCompress(int codec, ReadOnlySpan<byte> source, Span<byte> destination, out int written, int quality, int window) => codec switch
    {
        0 => DeflateEncoder.TryCompress(source, destination, out written, quality, window),
        1 => ZLibEncoder.TryCompress(source, destination, out written, quality, window),
        2 => GZipEncoder.TryCompress(source, destination, out written, quality, window),
        _ => BrotliEncoder.TryCompress(source, destination, out written, quality, window),
    };

    private static bool TryDecompress(int codec, ReadOnlySpan<byte> source, Span<byte> destination, out int written) => codec switch
    {
        0 => DeflateDecoder.TryDecompress(source, destination, out written),
        1 => ZLibDecoder.TryDecompress(source, destination, out written),
        2 => GZipDecoder.TryDecompress(source, destination, out written),
        _ => BrotliDecoder.TryDecompress(source, destination, out written),
    };

    /// <summary>A streaming encoder or decoder behind one interface (BrotliEncoder / Decoder are structs).</summary>
    private sealed class Codec : IDisposable
    {
        private readonly int _codec;
        private readonly DeflateEncoder _deflateEncoder;
        private readonly ZLibEncoder _zlibEncoder;
        private readonly GZipEncoder _gzipEncoder;
        private readonly DeflateDecoder _deflateDecoder;
        private readonly ZLibDecoder _zlibDecoder;
        private readonly GZipDecoder _gzipDecoder;
        private BrotliEncoder _brotliEncoder;
        private BrotliDecoder _brotliDecoder;

        public Codec(int codec, bool encode, int quality, int window)
        {
            _codec = codec;
            switch (codec, encode)
            {
                case (0, true): _deflateEncoder = new DeflateEncoder(quality, window); break;
                case (1, true): _zlibEncoder = new ZLibEncoder(quality, window); break;
                case (2, true): _gzipEncoder = new GZipEncoder(quality, window); break;
                case (_, true): _brotliEncoder = new BrotliEncoder(quality, window); break;
                case (0, false): _deflateDecoder = new DeflateDecoder(); break;
                case (1, false): _zlibDecoder = new ZLibDecoder(); break;
                case (2, false): _gzipDecoder = new GZipDecoder(); break;
                default: _brotliDecoder = default; break;
            }
        }

        public OperationStatus Compress(ReadOnlySpan<byte> source, Span<byte> destination, out int consumed, out int written, bool final) => _codec switch
        {
            0 => _deflateEncoder.Compress(source, destination, out consumed, out written, final),
            1 => _zlibEncoder.Compress(source, destination, out consumed, out written, final),
            2 => _gzipEncoder.Compress(source, destination, out consumed, out written, final),
            _ => _brotliEncoder.Compress(source, destination, out consumed, out written, final),
        };

        public OperationStatus Flush(Span<byte> destination, out int written) => _codec switch
        {
            0 => _deflateEncoder.Flush(destination, out written),
            1 => _zlibEncoder.Flush(destination, out written),
            2 => _gzipEncoder.Flush(destination, out written),
            _ => _brotliEncoder.Flush(destination, out written),
        };

        public OperationStatus Decompress(ReadOnlySpan<byte> source, Span<byte> destination, out int consumed, out int written) => _codec switch
        {
            0 => _deflateDecoder.Decompress(source, destination, out consumed, out written),
            1 => _zlibDecoder.Decompress(source, destination, out consumed, out written),
            2 => _gzipDecoder.Decompress(source, destination, out consumed, out written),
            _ => _brotliDecoder.Decompress(source, destination, out consumed, out written),
        };

        public void Dispose()
        {
            _deflateEncoder?.Dispose();
            _zlibEncoder?.Dispose();
            _gzipEncoder?.Dispose();
            _deflateDecoder?.Dispose();
            _zlibDecoder?.Dispose();
            _gzipDecoder?.Dispose();
            _brotliEncoder.Dispose();
            _brotliDecoder.Dispose();
        }
    }

    private static void RoundTrip(int codec, byte level, byte[] bytes, byte chunks, bool atStart, string what)
    {
        (int quality, int window) = Parameters(codec, level);
        ReadOnlySpan<byte> source = Guarded.Copy<byte>(bytes, atStart);

        // One-shot into the maximum size, over guarded memory and over arrays.
        int max = checked((int)MaxCompressed(codec, bytes.Length));
        Span<byte> dest = Out(max, !atStart);
        Check.That(TryCompress(codec, source, dest, out int written, quality, window), $"TryCompress into GetMaxCompressedLength {max}: {what}");
        byte[] compressed = dest[..written].ToArray();
        byte[] viaArray = new byte[max];
        Check.That(TryCompress(codec, bytes, viaArray, out int arrayWritten, quality, window) && viaArray.AsSpan(0, arrayWritten).SequenceEqual(compressed),
            $"TryCompress over arrays wrote {arrayWritten} bytes, over guarded memory {written}: {what}");

        // Exactly the compressed size, then one byte less.
        // Known (COMP-EXACT-1): DeflateEncoder.TryCompress needs one byte more than it writes.
        Span<byte> exact = Out(codec == 0 && !s_reportKnownIssues ? written + 1 : written, atStart);
        Check.That(TryCompress(codec, source, exact, out int exactWritten, quality, window) && exactWritten == written && exact[..exactWritten].SequenceEqual(compressed),
            $"TryCompress into exactly {written} bytes wrote {exactWritten}: {what}");
        if (written > 0)
        {
            Span<byte> small = Out(written - 1, !atStart);
            Check.That(!TryCompress(codec, source, small, out _, quality, window), $"TryCompress into {written - 1} < {written} bytes succeeded: {what}");
        }

        Decompresses(codec, compressed, bytes, chunks, atStart, $"one-shot output: {what}");

        // Streaming through small guarded buffers, then decompressing that.
        byte[] streamed = StreamCompress(codec, bytes, quality, window, chunks, atStart, what);
        Decompresses(codec, streamed, bytes, (byte)(chunks >> 4 | chunks << 4), !atStart, $"streamed output: {what}");

        // Interop with the stream classes (Brotli has no level / window there, and GZip / ZLib / Deflate
        // streams take a CompressionLevel).
        if (codec != 3)
        {
            byte[] fromStream = StreamClassCompress(codec, bytes, level);
            Decompresses(codec, fromStream, bytes, chunks, atStart, $"{Name(codec)}Stream output: {what}");
            Check.That(StreamClassDecompress(codec, compressed).AsSpan().SequenceEqual(bytes), $"{Name(codec)}Stream doesn't decompress the encoder's output: {what}");
        }
    }

    private static byte[] StreamCompress(int codec, byte[] bytes, int quality, int window, byte chunks, bool atStart, string what)
    {
        int inChunk = 1 + (chunks & 15) * 97 % 700, outChunk = 1 + (chunks >> 4) * 13;
        var output = new List<byte>();
        using var encoder = new Codec(codec, encode: true, quality, window);
        int position = 0, guard = 0;
        while (true)
        {
            Check.That(guard++ < 200000, $"streaming compression doesn't finish: {what}");
            int n = Math.Min(inChunk, bytes.Length - position);
            bool final = position + n == bytes.Length;
            ReadOnlySpan<byte> chunk = Guarded.Copy<byte>(bytes.AsSpan(position, n), atStart);
            Span<byte> dest = Out(outChunk, !atStart);
            OperationStatus status = encoder.Compress(chunk, dest, out int consumed, out int written, final);
            Check.That(consumed >= 0 && consumed <= n && written >= 0 && written <= outChunk, $"Compress consumed {consumed} of {n}, wrote {written} of {outChunk}: {what}");
            output.AddRange(dest[..written].ToArray());
            position += consumed;
            if (status == OperationStatus.Done && final && position == bytes.Length)
            {
                break;
            }

            Check.That(status is OperationStatus.Done or OperationStatus.DestinationTooSmall, $"Compress returned {status}: {what}");
            if ((chunks & 0x88) == 0x88 && status == OperationStatus.Done && !final)
            {
                // A flush in the middle.
                OperationStatus flushed;
                do
                {
                    Span<byte> f = Out(outChunk, atStart);
                    flushed = encoder.Flush(f, out int fw);
                    output.AddRange(f[..fw].ToArray());
                    Check.That(guard++ < 200000, $"Flush doesn't finish: {what}");
                }
                while (flushed == OperationStatus.DestinationTooSmall);
                Check.Equal(OperationStatus.Done, flushed, $"Flush: {what}");
            }
        }

        return output.ToArray();
    }

    /// <summary>The compressed data decompresses to the expected bytes: one-shot (exact and short destinations) and streaming.</summary>
    private static void Decompresses(int codec, byte[] compressed, byte[] expected, byte chunks, bool atStart, string what)
    {
        ReadOnlySpan<byte> source = Guarded.Copy<byte>(compressed, atStart);
        // Known (COMP-EMPTY-1): the zlib-based decoders fail to decompress an empty payload into an empty destination.
        Span<byte> dest = Out(expected.Length == 0 && codec != 3 && !s_reportKnownIssues ? 1 : expected.Length, !atStart);
        Check.That(TryDecompress(codec, source, dest, out int written) && written == expected.Length && dest[..written].SequenceEqual(expected),
            $"TryDecompress into exactly {expected.Length} bytes wrote {written}: {what}");
        if (expected.Length > 0)
        {
            Span<byte> small = Out(expected.Length - 1, atStart);
            Check.That(!TryDecompress(codec, source, small, out _), $"TryDecompress into {expected.Length - 1} < {expected.Length} bytes succeeded: {what}");
        }

        byte[] streamed = StreamDecompress(codec, compressed, chunks, atStart, out OperationStatus last, what);
        Check.That(last == OperationStatus.Done && streamed.AsSpan().SequenceEqual(expected), $"streaming decompression gave {last} with {streamed.Length} of {expected.Length} bytes: {what}");
    }

    private static byte[] StreamDecompress(int codec, byte[] compressed, byte chunks, bool atStart, out OperationStatus last, string what)
    {
        int inChunk = 1 + (chunks & 15) * 37 % 300, outChunk = 1 + (chunks >> 4) * 29;
        var output = new List<byte>();
        using var decoder = new Codec(codec, encode: false, 0, 0);
        int position = 0;
        last = OperationStatus.NeedMoreData;
        for (int i = 0; i < 3 * MaxOutput && output.Count <= MaxOutput; i++)
        {
            int n = Math.Min(inChunk, compressed.Length - position);
            ReadOnlySpan<byte> chunk = Guarded.Copy<byte>(compressed.AsSpan(position, n), atStart);
            Span<byte> dest = Out(outChunk, !atStart);
            last = decoder.Decompress(chunk, dest, out int consumed, out int written);
            Check.That(consumed >= 0 && consumed <= n && written >= 0 && written <= outChunk, $"Decompress consumed {consumed} of {n}, wrote {written} of {outChunk}: {what}");
            output.AddRange(dest[..written].ToArray());
            position += consumed;
            if (last is OperationStatus.Done or OperationStatus.InvalidData)
            {
                break;
            }

            if (last == OperationStatus.NeedMoreData && position == compressed.Length)
            {
                break;
            }
        }

        return output.ToArray();
    }

    private static byte[] StreamClassCompress(int codec, byte[] bytes, byte level)
    {
        var level2 = (CompressionLevel)(level % 4);
        var ms = new MemoryStream();
        using (Stream s = codec switch { 0 => new DeflateStream(ms, level2, true), 1 => new ZLibStream(ms, level2, true), _ => new GZipStream(ms, level2, true) })
        {
            s.Write(bytes);
        }

        return ms.ToArray();
    }

    private static byte[] StreamClassDecompress(int codec, byte[] compressed)
    {
        using Stream s = codec switch { 0 => new DeflateStream(new MemoryStream(compressed), CompressionMode.Decompress), 1 => new ZLibStream(new MemoryStream(compressed), CompressionMode.Decompress), _ => new GZipStream(new MemoryStream(compressed), CompressionMode.Decompress) };
        var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }

    /// <summary>Arbitrary data through the decoders: the same outcome from guarded memory as from arrays.</summary>
    private static void DecodeArbitrary(int codec, byte[] bytes, byte chunks, byte place, string what)
    {
        bool atStart = (place & 1) != 0;
        ReadOnlySpan<byte> source = Guarded.Copy<byte>(bytes, atStart);
        foreach (int size in (int[])[0, 1 + chunks % 64, 4096, 1 << 16])
        {
            byte[] array = new byte[size];
            bool ok = TryDecompress(codec, bytes, array, out int written);
            Span<byte> dest = Out(size, !atStart);
            bool guardedOk = TryDecompress(codec, source, dest, out int guardedWritten);
            Check.That(ok == guardedOk && written == guardedWritten && dest[..guardedWritten].SequenceEqual(array.AsSpan(0, written)),
                $"TryDecompress into {size}: {ok} {written} over arrays, {guardedOk} {guardedWritten} over guarded memory: {what}");
            if (ok && written > 0)
            {
                // Exactly the decompressed size works too.
                Span<byte> exact = Out(written, atStart);
                Check.That(TryDecompress(codec, source, exact, out int exactWritten) && exactWritten == written && exact.SequenceEqual(array.AsSpan(0, written)),
                    $"TryDecompress into exactly {written} bytes wrote {exactWritten}: {what}");
            }
        }

        // Streaming over guarded chunks against streaming over the whole array.
        byte[] streamed = StreamDecompress(codec, bytes, chunks, atStart, out OperationStatus last, what);
        using var decoder = new Codec(codec, encode: false, 0, 0);
        byte[] whole = new byte[MaxOutput + 1];
        OperationStatus status = decoder.Decompress(bytes, whole, out int c, out int w);
        // (Streaming stops at MaxOutput bytes, so it can end with DestinationTooSmall on big outputs.)
        if (status == OperationStatus.Done && streamed.Length <= MaxOutput && last != OperationStatus.DestinationTooSmall)
        {
            Check.That(last == OperationStatus.Done && streamed.AsSpan().SequenceEqual(whole.AsSpan(0, w)),
                $"streaming decompression in chunks gave {last} with {streamed.Length} bytes, all at once Done with {w}: {what}");
        }
    }
}
