#nullable disable warnings
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// Text I/O with small, irregular buffers: StreamReader (every built-in encoding, BOM detection)
/// over a stream that returns a few bytes per Read, read through guarded Span / Memory destinations
/// of varying sizes, ReadLine, Peek and ReadToEnd; BinaryReader.ReadChars; and StringBuilder edits
/// with CopyTo into exactly sized guarded spans. Everything is compared with one-shot decoding
/// (Encoding.GetString after the same BOM handling) or a string model.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     mode; byte 1 encoding; byte 2 stream chunk pattern; byte 3 read pattern
///   rest       the bytes
/// </remarks>
public static class TextIoTarget
{
    private static readonly Encoding[] s_encodings =
    [
        new UTF8Encoding(false), new UTF8Encoding(true), new UnicodeEncoding(false, false), new UnicodeEncoding(true, false),
        new UTF32Encoding(false, false), new UTF32Encoding(true, false), Encoding.Latin1, Encoding.ASCII,
    ];

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        Encoding encoding = s_encodings[input.Byte() % s_encodings.Length];
        byte chunks = input.Byte();
        byte reads = input.Byte();
        byte[] bytes = input.Rest().ToArray();
        if (bytes.Length > 8192)
        {
            return;
        }

        string what = $"mode {mode % 4} {encoding.WebName}{(encoding.GetPreamble().Length > 0 ? "+BOM" : "")} chunks {chunks:X2} reads {reads:X2}, {bytes.Length} bytes 0x{Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 48)))}";
        switch (mode % 4)
        {
            case 0: Reader(bytes, encoding, detect: (mode & 4) != 0, chunks, reads, what); break;
            case 1: Lines(bytes, encoding, detect: (mode & 4) != 0, chunks, what); break;
            case 2: BinaryChars(bytes, encoding, chunks, reads, what); break;
            default: Builder(bytes, reads, what); break;
        }
    }

    /// <summary>A stream that returns at most a few bytes per Read, following a pattern.</summary>
    private sealed class ChunkStream(byte[] data, byte pattern) : Stream
    {
        private int _position, _reads;

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            int n = Math.Min(buffer.Length, Math.Min(data.Length - _position, 1 + (pattern >> (_reads++ % 4 * 2) & 3) * (1 + (pattern >> 7) * 5)));
            data.AsSpan(_position, n).CopyTo(buffer);
            _position += n;
            return n;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => _position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>What StreamReader should produce: BOM detection (optional), the encoding's own preamble skipped, then GetString.</summary>
    private static string Expected(byte[] bytes, Encoding encoding, bool detect)
    {
        ReadOnlySpan<byte> b = bytes;
        if (detect)
        {
            (byte[] Bom, Encoding Encoding)[] boms =
            [
                ([0xFF, 0xFE, 0, 0], new UTF32Encoding(false, true)), ([0, 0, 0xFE, 0xFF], new UTF32Encoding(true, true)),
                ([0xEF, 0xBB, 0xBF], new UTF8Encoding(true)), ([0xFF, 0xFE], new UnicodeEncoding(false, true)), ([0xFE, 0xFF], new UnicodeEncoding(true, true)),
            ];
            foreach ((byte[] bom, Encoding e) in boms)
            {
                if (b.StartsWith(bom))
                {
                    return e.GetString(b[bom.Length..]);
                }
            }
        }

        byte[] preamble = encoding.GetPreamble();
        if (preamble.Length > 0 && b.StartsWith(preamble))
        {
            b = b[preamble.Length..];
        }

        return encoding.GetString(b);
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    // Known (SR-BOM-1): with BOM detection, a first Read of 1-2 bytes leaves detection pending, and it then
    // runs on later buffers (dropping or switching encodings on BOM-like bytes mid-stream) or misses a
    // BOM split across reads.
    private static bool BomLike(byte[] bytes) =>
        bytes.AsSpan().IndexOf((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]) >= 0 || bytes.AsSpan().IndexOf((ReadOnlySpan<byte>)[0xFF, 0xFE]) >= 0 ||
        bytes.AsSpan().IndexOf((ReadOnlySpan<byte>)[0xFE, 0xFF]) >= 0;

    private static void Reader(byte[] bytes, Encoding encoding, bool detect, byte chunks, byte reads, string what)
    {
        if (!s_reportKnownIssues && detect && BomLike(bytes))
        {
            return;
        }

        string expected = Expected(bytes, encoding, detect);
        using var reader = new StreamReader(new ChunkStream(bytes, chunks), encoding, detect, bufferSize: 1 + reads % 64);
        var sb = new StringBuilder();
        int k = 0;
        while (sb.Length < expected.Length + 8)
        {
            int size = 1 + (reads >> (k++ % 4 * 2) & 3) * 3;
            int n;
            switch (k % 5)
            {
                case 0:
                {
                    int c = reader.Read();
                    if (c < 0)
                    {
                        n = 0;
                        break;
                    }

                    int peeked = reader.Peek();
                    sb.Append((char)c);
                    Check.That(peeked == -1 || sb.Length < expected.Length && peeked == expected[sb.Length], $"Peek gave {peeked} at {sb.Length}: {what}");
                    n = 1;
                    break;
                }

                case 1:
                {
                    Memory<char> m = Guarded.CopyMemory<char>(new char[size], (k & 1) != 0);
                    n = reader.ReadAsync(m).AsTask().GetAwaiter().GetResult();
                    sb.Append(m.Span[..n]);
                    break;
                }

                case 2:
                {
                    Span<char> s = Guarded.Copy<char>(new char[size], (k & 2) != 0);
                    n = reader.ReadBlock(s);
                    sb.Append(s[..n]);
                    break;
                }

                default:
                {
                    Span<char> s = Guarded.Copy<char>(new char[size], (k & 1) == 0);
                    n = reader.Read(s);
                    sb.Append(s[..n]);
                    break;
                }
            }

            if (n == 0)
            {
                break;
            }

            if (k % 7 == 6)
            {
                sb.Append(reader.ReadToEnd());
                break;
            }
        }

        Check.Equal(expected, sb.ToString(), $"StreamReader text: {what}");
        Check.Equal(-1, reader.Read(), $"Read after the end: {what}");
    }

    private static void Lines(byte[] bytes, Encoding encoding, bool detect, byte chunks, string what)
    {
        if (!s_reportKnownIssues && detect && BomLike(bytes))
        {
            return;
        }

        string expected = Expected(bytes, encoding, detect);
        var model = new List<string>();
        using (var sr = new StringReader(expected))
        {
            while (sr.ReadLine() is string line)
            {
                model.Add(line);
            }
        }

        var lines = new List<string>();
        using var reader = new StreamReader(new ChunkStream(bytes, chunks), encoding, detect, bufferSize: 1 + chunks % 32);
        while (reader.ReadLine() is string line)
        {
            lines.Add(line);
        }

        Check.That(lines.SequenceEqual(model), $"StreamReader.ReadLine gives {lines.Count} lines, StringReader {model.Count}: {what}");
    }

    private static void BinaryChars(byte[] bytes, Encoding encoding, byte chunks, byte reads, string what)
    {
        if (encoding is UTF32Encoding || encoding.GetPreamble().Length > 0)
        {
            return; // BinaryReader doesn't skip preambles; keep to encodings without them
        }

        // BinaryReader never flushes its decoder, so an incomplete sequence at the end is dropped rather than replaced.
        Decoder decoder = encoding.GetDecoder();
        char[] decoded = new char[encoding.GetMaxCharCount(bytes.Length) + 2];
        string expected = new string(decoded, 0, decoder.GetChars(bytes, 0, bytes.Length, decoded, 0, flush: false));
        using var reader = new BinaryReader(new ChunkStream(bytes, chunks), encoding);
        var sb = new StringBuilder();
        int k = 0;
        while (true)
        {
            int count = 1 + (reads >> (k++ % 4 * 2) & 3) * 5;
            char[] chars;
            try
            {
                chars = reader.ReadChars(count);
            }
            catch (ArgumentException e) when (!s_reportKnownIssues && e.Message.Contains("output char buffer is too small", StringComparison.Ordinal))
            {
                // Known (BR-CHARS-1): ReadChars throws when the decoder produces more chars than are left
                // to read (a replacement plus the next char, or a surrogate pair for one char).
                return;
            }

            sb.Append(chars);
            if (chars.Length < count)
            {
                break;
            }
        }

        Check.Equal(expected, sb.ToString(), $"BinaryReader.ReadChars: {what}");
    }

    private static void Builder(byte[] bytes, byte reads, string what)
    {
        string text = Encoding.UTF8.GetString(bytes);
        var sb = new StringBuilder(1 + reads % 16);
        string model = "";
        var input = new FuzzInput(bytes);
        for (int i = 0; i < 12 && input.Remaining > 0; i++)
        {
            byte op = input.Byte();
            int a = input.Byte(), b = input.Byte();
            string piece = text.Substring(Math.Min(text.Length, a), Math.Min(text.Length - Math.Min(text.Length, a), b % 40));
            switch (op % 7)
            {
                case 0: sb.Append(Guarded.Copy<char>(piece.AsSpan(), (op & 8) != 0)); model += piece; break;
                case 1: { int at = model.Length == 0 ? 0 : a % (model.Length + 1); sb.Insert(at, piece); model = model.Insert(at, piece); break; }
                case 2: { int at = model.Length == 0 ? 0 : a % model.Length; int len = Math.Min(model.Length - at, b % 17); sb.Remove(at, len); model = model.Remove(at, len); break; }
                case 3:
                    if (piece.Length > 0)
                    {
                        string repl = new('x', b % 5);
                        sb.Replace(piece, repl);
                        model = model.Replace(piece, repl, StringComparison.Ordinal);
                    }

                    break;
                case 4: sb.Append(piece, 0, piece.Length).Append(a); model += piece + a; break;
                case 5: { char c = piece.Length > 0 ? piece[0] : 'q'; sb.Replace(c, '#'); model = model.Replace(c, '#'); break; }
                default: sb.Append(piece.AsSpan()).AppendLine(); model += piece + Environment.NewLine; break;
            }

            Check.Equal(model, sb.ToString(), $"StringBuilder after op {i} ({op % 7}): {what}");
            if (model.Length > 20000)
            {
                return; // repeated Replace("x", "xxxx") grows exponentially
            }
        }

        // CopyTo into exactly sized guarded spans, whole and in parts; GetChunks.
        string s = sb.ToString();
        Span<char> all = Guarded.Copy<char>(new char[s.Length], (reads & 1) != 0);
        sb.CopyTo(0, all, s.Length);
        Check.That(all.SequenceEqual(s), $"StringBuilder.CopyTo: {what}");
        if (s.Length > 2)
        {
            int start = reads % s.Length, len = (s.Length - start) / 2;
            Span<char> part = Guarded.Copy<char>(new char[len], (reads & 2) != 0);
            sb.CopyTo(start, part, len);
            Check.That(part.SequenceEqual(s.AsSpan(start, len)), $"StringBuilder.CopyTo({start}, {len}): {what}");
        }

        var chunks = new StringBuilder();
        foreach (ReadOnlyMemory<char> chunk in sb.GetChunks())
        {
            chunks.Append(chunk.Span);
        }

        Check.Equal(s, chunks.ToString(), $"StringBuilder.GetChunks: {what}");
    }
}
