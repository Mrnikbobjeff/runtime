#nullable disable warnings
using System.Buffers;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Xml;

namespace SharpFuzzHarness;

/// <summary>
/// Streaming parsers fed the same bytes in small, irregular pieces and in one piece, which must give
/// the same result: Utf8JsonReader over a multi-segment ReadOnlySequence; JsonSerializer.DeserializeAsync
/// and JsonDocument.ParseAsync over a stream returning a few bytes per read; the decompression streams
/// (Deflate / ZLib / GZip / Brotli) over such a stream with small read buffers; XmlReader (byte-level
/// encoding detection) over such a stream.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     mode; byte 1 chunk pattern
///   rest       the bytes
/// </remarks>
public static class ChunkedTarget
{
    private sealed class ChunkStream(byte[] data, byte pattern) : Stream
    {
        private int _position, _reads;

        private int Next(int max) => Math.Min(max, Math.Min(data.Length - _position, 1 + (pattern >> (_reads++ % 4 * 2) & 3) * (1 + (pattern >> 7) * 9)));

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            int n = Next(buffer.Length);
            data.AsSpan(_position, n).CopyTo(buffer);
            _position += n;
            return n;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => new(Read(buffer.Span));
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => Task.FromResult(Read(buffer, offset, count));
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

    private sealed class Segment : ReadOnlySequenceSegment<byte>
    {
        public Segment(ReadOnlyMemory<byte> memory, long index)
        {
            Memory = memory;
            RunningIndex = index;
        }

        public Segment Append(ReadOnlyMemory<byte> memory)
        {
            var next = new Segment(memory, RunningIndex + Memory.Length);
            Next = next;
            return next;
        }
    }

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        byte pattern = input.Byte();
        byte[] bytes = input.Rest().ToArray();
        if (bytes.Length > 8192)
        {
            return;
        }

        string what = $"mode {mode % 4} pattern {pattern:X2}, {bytes.Length} bytes 0x{Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 48)))}";
        switch (mode % 4)
        {
            case 0: JsonSegments(bytes, pattern, (mode & 4) != 0, what); break;
            case 1: JsonAsync(bytes, pattern, what); break;
            case 2: Decompress(bytes, pattern, mode, what); break;
            default: Xml(bytes, pattern, what); break;
        }
    }

    private static string Tokens(ref Utf8JsonReader reader)
    {
        var sb = new StringBuilder();
        try
        {
            while (reader.Read() && sb.Length < 20000)
            {
                sb.Append(reader.TokenType).Append(reader.TokenStartIndex).Append(':');
                if (reader.TokenType is JsonTokenType.String or JsonTokenType.PropertyName)
                {
                    try
                    {
                        sb.Append(Check.Escape(reader.GetString(), 1 << 16)).Append(reader.ValueIsEscaped ? "\\" : "");
                    }
                    catch (InvalidOperationException e)
                    {
                        sb.Append(e.GetType().Name);
                    }
                }
                else if (reader.TokenType == JsonTokenType.Number)
                {
                    sb.Append(Encoding.UTF8.GetString(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan.ToArray()));
                    sb.Append(reader.TryGetInt64(out long l) ? "/" + l : "").Append(reader.TryGetDouble(out double d) ? "/" + d.ToString("R") : "");
                }

                sb.Append(';');
            }
        }
        catch (JsonException)
        {
            // The single- and multi-segment readers word some errors differently ("Expected end of comment"
            // vs "Unexpected end of data while reading a comment"), so only that there was one.
            sb.Append("error");
            return sb.ToString();
        }

        return sb.Append(" end ").Append(reader.BytesConsumed).ToString();
    }

    private static void JsonSegments(byte[] bytes, byte pattern, bool comments, string what)
    {
        var options = new JsonReaderOptions { CommentHandling = comments ? JsonCommentHandling.Allow : JsonCommentHandling.Disallow, AllowTrailingCommas = (pattern & 1) != 0, MaxDepth = 64 };
        var single = new Utf8JsonReader(bytes, options);
        string expected = Tokens(ref single);

        // Split into segments of 1-4 (or more) bytes following the pattern.
        Segment first = null, last = null;
        int position = 0, k = 0;
        while (position < bytes.Length || first is null)
        {
            int n = Math.Min(bytes.Length - position, 1 + (pattern >> (k++ % 4 * 2) & 3) * (1 + (pattern >> 6)));
            ReadOnlyMemory<byte> piece = bytes.AsSpan(position, n).ToArray(); // a separate array per segment
            last = first is null ? first = new Segment(piece, 0) : last.Append(piece);
            position += n;
            if (n == 0)
            {
                break;
            }
        }

        var multi = new Utf8JsonReader(new ReadOnlySequence<byte>(first, 0, last, last.Memory.Length), options);
        string actual = Tokens(ref multi);
        Check.Equal(expected, actual, $"Utf8JsonReader over {k} segments vs one span: {what}");
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    // JSON-UTF8-1: JsonDocument keeps invalid UTF-8 in strings, which GetRawText / writing then can't transcode.
    private static bool JsonAllowed(Exception e) => e is JsonException || e is InvalidOperationException && e.Message.Contains("UTF-8", StringComparison.Ordinal);

    private static void JsonAsync(byte[] bytes, byte pattern, string what)
    {
        // The stream APIs skip a UTF-8 BOM, the span ones don't (by design).
        if (bytes.AsSpan().StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]))
        {
            return;
        }

        var options = new JsonSerializerOptions { MaxDepth = 64, DefaultBufferSize = 1 + pattern % 16 };
        var sync = Outcome<string>.Of(() => JsonSerializer.Serialize(JsonSerializer.Deserialize<JsonElement>(bytes, options)), JsonAllowed);
        var async = Outcome<string>.Of(() => JsonSerializer.Serialize(JsonSerializer.DeserializeAsync<JsonElement>(new ChunkStream(bytes, pattern), options).AsTask().GetAwaiter().GetResult()), JsonAllowed);
        Check.That(sync.SameAs(async) || !sync.Ok && !async.Ok, $"DeserializeAsync<JsonElement>(chunked) [{async}] vs Deserialize [{sync}]: {what}");

        var list = Outcome<string>.Of(() => JsonSerializer.Serialize(JsonSerializer.Deserialize<List<Dictionary<string, object>>>(bytes, options)), JsonAllowed);
        var listAsync = Outcome<string>.Of(() => JsonSerializer.Serialize(JsonSerializer.DeserializeAsync<List<Dictionary<string, object>>>(new ChunkStream(bytes, pattern), options).AsTask().GetAwaiter().GetResult()), JsonAllowed);
        Check.That(list.SameAs(listAsync) || !list.Ok && !listAsync.Ok, $"DeserializeAsync<List<Dictionary>>(chunked) [{listAsync}] vs Deserialize [{list}]: {what}");

        var doc = Outcome<string>.Of(() => { using var d = JsonDocument.Parse(bytes); return d.RootElement.GetRawText(); }, JsonAllowed);
        var docAsync = Outcome<string>.Of(() => { using var d = JsonDocument.ParseAsync(new ChunkStream(bytes, pattern)).GetAwaiter().GetResult(); return d.RootElement.GetRawText(); }, JsonAllowed);
        Check.That(doc.SameAs(docAsync) || !doc.Ok && !docAsync.Ok, $"JsonDocument.ParseAsync(chunked) [{docAsync}] vs Parse [{doc}]: {what}");
    }

    private static Stream Decompressor(int codec, Stream s) => codec switch
    {
        0 => new DeflateStream(s, CompressionMode.Decompress),
        1 => new ZLibStream(s, CompressionMode.Decompress),
        2 => new GZipStream(s, CompressionMode.Decompress),
        _ => new BrotliStream(s, CompressionMode.Decompress),
    };

    private static Outcome<string> ReadAll(Stream s, int bufferSize)
    {
        return Outcome<string>.Of(() =>
        {
            var ms = new MemoryStream();
            byte[] buffer = new byte[bufferSize];
            int n;
            while (ms.Length <= 1 << 18 && (n = s.Read(buffer, 0, buffer.Length)) > 0)
            {
                ms.Write(buffer, 0, n);
            }

            return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(ms.ToArray())) + ":" + ms.Length;
            // Known (BROTLI-EXC-1): BrotliStream reports corrupt data with InvalidOperationException.
        }, e => e is InvalidDataException || !s_reportKnownIssues && e is InvalidOperationException && e.StackTrace?.Contains("BrotliStream", StringComparison.Ordinal) == true ||
            // Known (ZLIB-DICT-1): a zlib header asking for a preset dictionary throws ZLibException.
            !s_reportKnownIssues && e.GetType().Name == "ZLibException");
    }

    private static void Decompress(byte[] bytes, byte pattern, byte mode, string what)
    {
        int codec = mode >> 2 & 3;
        // Valid compressed data from the input, or the input itself.
        byte[] compressed = bytes;
        if ((mode & 16) != 0)
        {
            var ms = new MemoryStream();
            using (Stream c = codec switch { 0 => new DeflateStream(ms, CompressionLevel.Fastest, true), 1 => new ZLibStream(ms, CompressionLevel.Fastest, true), 2 => new GZipStream(ms, CompressionLevel.Fastest, true), _ => new BrotliStream(ms, CompressionLevel.Fastest, true) })
            {
                c.Write(bytes);
            }

            compressed = ms.ToArray();
            if ((mode & 32) != 0 && codec == 2)
            {
                compressed = [.. compressed, .. compressed]; // two gzip members
            }
        }

        using Stream whole = Decompressor(codec, new MemoryStream(compressed));
        Outcome<string> expected = ReadAll(whole, 1 << 16);
        using Stream chunked = Decompressor(codec, new ChunkStream(compressed, pattern));
        Outcome<string> actual = ReadAll(chunked, 1 + pattern % 37);
        // A truncated or corrupt stream may be noticed at a different point, but valid data must decompress the same.
        Check.That(expected.SameAs(actual) || !expected.Ok && !actual.Ok || (mode & 16) == 0 && (!expected.Ok || !actual.Ok),
            $"{Decompressor(codec, Stream.Null).GetType().Name} over chunks [{actual}] vs one read [{expected}]: {what}");
        if ((mode & 16) != 0)
        {
            Check.That(expected.Ok && actual.Ok && expected.Value == actual.Value, $"valid {codec} data: chunked [{actual}] vs whole [{expected}]: {what}");
        }
    }

    private static string Nodes(XmlReader reader)
    {
        var sb = new StringBuilder();
        try
        {
            while (reader.Read() && sb.Length < 20000)
            {
                // A node is recorded once its value has been read: over chunks the reader may return a text
                // node and fail when its value is read, where the whole buffer fails in Read itself.
                var node = new StringBuilder();
                node.Append(reader.NodeType).Append(':').Append(reader.Name).Append('=').Append(Check.Escape(reader.Value, 4096));
                while (reader.MoveToNextAttribute())
                {
                    node.Append(' ').Append(reader.Name).Append('=').Append(Check.Escape(reader.Value, 4096));
                }

                sb.Append(node).Append(';');
            }
        }
        catch (XmlException e)
        {
            // Decoding errors are reported at positions that depend on where the chunks end.
            // Messages quote the offending token as far as the current buffer goes, and positions depend on
            // where chunks end, so only that there was an error.
            _ = e;
            sb.Append("error");
        }

        return System.Text.RegularExpressions.Regex.Replace(sb.ToString(), @"(Text|Whitespace|SignificantWhitespace):=""[^""]*"";error", "error");
    }

    private static void Xml(byte[] bytes, byte pattern, string what)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1 << 20, IgnoreWhitespace = (pattern & 1) != 0 };
        static string Read(Func<XmlReader> create)
        {
            try
            {
                return Nodes(create());
            }
            catch (XmlException e)
            {
                _ = e;
                return "error";
            }
        }

        string expected = Read(() => XmlReader.Create(new MemoryStream(bytes), settings));
        string actual = Read(() => XmlReader.Create(new ChunkStream(bytes, pattern), settings));
        // Nodes before an error depend on how much was decoded at once (one buffer decodes, and fails, up
        // front), so when both fail that's agreement; otherwise the results must match.
        bool bothFail = expected.EndsWith("error", StringComparison.Ordinal) && actual.EndsWith("error", StringComparison.Ordinal);
        Check.That(bothFail || expected == actual, $"XmlReader over chunks [{Check.Escape(actual, 600)}] vs one read [{Check.Escape(expected, 600)}]: {what}");
    }
}
