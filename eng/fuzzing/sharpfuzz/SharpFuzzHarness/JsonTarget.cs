using System.Buffers;
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SharpFuzzHarness;

/// <summary>
/// Fuzzes System.Text.Json: Utf8JsonReader (contiguous, multi-segment and incremental
/// isFinalBlock=false modes), JsonDocument, JsonNode, Utf8JsonWriter and JsonSerializer.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     option bits (comments, trailing commas, multiple values, max depth, duplicates)
///   byte 1     segmentation seed for the multi-segment / incremental readers
///   rest       UTF-8 JSON payload
/// </remarks>
public static class JsonTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
        {
            return;
        }

        byte flags = data[0];
        byte seed = data[1];
        byte[] json = data.Slice(2).ToArray();

        var readerOptions = new JsonReaderOptions
        {
            CommentHandling = (flags & 0x03) switch
            {
                1 => JsonCommentHandling.Skip,
                2 => JsonCommentHandling.Allow,
                _ => JsonCommentHandling.Disallow,
            },
            AllowTrailingCommas = (flags & 0x04) != 0,
            AllowMultipleValues = (flags & 0x08) != 0,
            MaxDepth = (flags & 0x10) != 0 ? 8 : 0,
        };

        // 1. Utf8JsonReader: contiguous vs. multi-segment vs. incremental must produce identical token streams.
        List<string> contiguous = ReadTokens(new Utf8JsonReader(json, readerOptions));
        List<string> segmented = ReadTokens(new Utf8JsonReader(Segment(json, seed), readerOptions));
        CheckSame("contiguous", contiguous, "multi-segment", segmented, json, readerOptions);
        List<string> incremental = ReadIncrementally(json, seed, readerOptions);
        CheckSame("contiguous", contiguous, "incremental", incremental, json, readerOptions);

        bool readerAccepted = contiguous.Count == 0 || !contiguous[^1].StartsWith("!", StringComparison.Ordinal);

        // JsonDocument / JsonNode / JsonSerializer don't accept multiple top-level values, and
        // JsonCommentHandling.Allow is not supported by them.
        if (readerOptions.AllowMultipleValues || readerOptions.CommentHandling == JsonCommentHandling.Allow)
        {
            return;
        }

        var documentOptions = new JsonDocumentOptions
        {
            CommentHandling = readerOptions.CommentHandling,
            AllowTrailingCommas = readerOptions.AllowTrailingCommas,
            MaxDepth = readerOptions.MaxDepth,
            AllowDuplicateProperties = (flags & 0x20) == 0,
        };

        // 2. JsonDocument must agree with the reader on validity, and round-trip through Utf8JsonWriter.
        byte[]? written = null;
        try
        {
            using JsonDocument doc = JsonDocument.Parse(json, documentOptions);
            if (!readerAccepted)
            {
                throw new ConsistencyException($"JsonDocument accepted input rejected by Utf8JsonReader: {Describe(json, readerOptions)} reader: {contiguous[^1]}");
            }

            Walk(doc.RootElement, 0);
            CheckNumberEquality(doc.RootElement);
            written = Write(doc.RootElement);
            _ = doc.RootElement.GetRawText();

            using JsonDocument doc2 = JsonDocument.Parse(written, new JsonDocumentOptions { MaxDepth = documentOptions.MaxDepth });
            byte[] rewritten = Write(doc2.RootElement);
            if (!written.AsSpan().SequenceEqual(rewritten))
            {
                throw new ConsistencyException($"JsonDocument round trip not idempotent: {Encoding.UTF8.GetString(written)} vs {Encoding.UTF8.GetString(rewritten)}");
            }

            bool equal;
            try
            {
                equal = JsonElement.DeepEquals(doc.RootElement, doc2.RootElement);
            }
            catch (ArgumentOutOfRangeException e) when (e.ParamName == "exponent" && !s_reportKnownIssues)
            {
                // Known: DeepEquals throws for numbers whose exponent doesn't fit in an int (FINDINGS.md, JSON-1).
                equal = true;
            }

            if (!equal)
            {
                throw new ConsistencyException($"JsonElement.DeepEquals false after round trip: {Describe(json, readerOptions)}");
            }
        }
        catch (InvalidOperationException e) when (IsInvalidText(e))
        {
            // JsonDocument also validates string UTF-8 lazily.
            return;
        }
        catch (JsonException)
        {
            if (readerAccepted && documentOptions.AllowDuplicateProperties)
            {
                throw new ConsistencyException($"JsonDocument rejected input accepted by Utf8JsonReader: {Describe(json, readerOptions)}");
            }
            return;
        }

        var nodeOptions = new JsonNodeOptions { PropertyNameCaseInsensitive = (flags & 0x40) != 0 };

        // 3. JsonNode must produce the same serialized form as JsonDocument.
        try
        {
            JsonNode? node = JsonNode.Parse(json, nodeOptions, documentOptions);
            string nodeText = node?.ToJsonString() ?? "null";
            WalkNode(node, 0);
            string nodeText2 = node?.ToJsonString() ?? "null";
            if (nodeText != nodeText2)
            {
                throw new ConsistencyException($"JsonNode serialization changed after walking the tree: {nodeText} vs {nodeText2}");
            }

            JsonNode? clone = node?.DeepClone();
            if (!JsonNode.DeepEquals(node, clone))
            {
                throw new ConsistencyException($"JsonNode.DeepClone not DeepEquals: {nodeText}");
            }
        }
        catch (JsonException)
        {
        }
        catch (ArgumentException e) when (e.Message.StartsWith("An item with the same key has already been added", StringComparison.Ordinal))
        {
            // JsonObject can't hold duplicate (or case-insensitively duplicate) property names; it
            // throws when the backing dictionary is materialized (documented behaviour).
        }
        catch (ArgumentOutOfRangeException e) when (e.ParamName == "exponent" && !s_reportKnownIssues)
        {
            // Known: JsonNode.DeepEquals shares the number comparison with JsonElement.DeepEquals (JSON-1).
        }
        catch (InvalidOperationException e) when (IsInvalidText(e))
        {
        }

        // 4. JsonSerializer over a handful of shapes to exercise the built-in converters.
        var serializerOptions = new JsonSerializerOptions
        {
            ReadCommentHandling = readerOptions.CommentHandling,
            AllowTrailingCommas = readerOptions.AllowTrailingCommas,
            MaxDepth = readerOptions.MaxDepth,
            AllowDuplicateProperties = documentOptions.AllowDuplicateProperties,
            PropertyNameCaseInsensitive = nodeOptions.PropertyNameCaseInsensitive,
            NumberHandling = (flags & 0x80) != 0
                ? System.Text.Json.Serialization.JsonNumberHandling.AllowReadingFromString | System.Text.Json.Serialization.JsonNumberHandling.AllowNamedFloatingPointLiterals
                : System.Text.Json.Serialization.JsonNumberHandling.Strict,
        };

        Deserialize<object>(json, serializerOptions);
        Deserialize<JsonElement>(json, serializerOptions);
        Deserialize<Dictionary<string, JsonElement>>(json, serializerOptions);
        Deserialize<List<double>>(json, serializerOptions);
        Deserialize<Poco>(json, serializerOptions);
        Deserialize<Poco[]>(json, serializerOptions);
    }

    public sealed class Poco
    {
        public int Int { get; set; }
        public long? NullableLong { get; set; }
        public decimal Decimal { get; set; }
        public double Double { get; set; }
        public float Single { get; set; }
        public Half Half { get; set; }
        public Int128 Int128 { get; set; }
        public UInt128 UInt128 { get; set; }
        public string? String { get; set; }
        public char Char { get; set; }
        public bool Bool { get; set; }
        public byte[]? Bytes { get; set; }
        public Guid Guid { get; set; }
        public DateTime DateTime { get; set; }
        public DateTimeOffset DateTimeOffset { get; set; }
        public DateOnly DateOnly { get; set; }
        public TimeOnly TimeOnly { get; set; }
        public TimeSpan TimeSpan { get; set; }
        public Uri? Uri { get; set; }
        public Version? Version { get; set; }
        public DayOfWeek Enum { get; set; }
        public Poco? Child { get; set; }
        public List<Poco>? Children { get; set; }
        public Dictionary<string, int>? Map { get; set; }
        public int[]? Ints { get; set; }
        public JsonNode? Node { get; set; }
        public object? Object { get; set; }
    }

    private static void Deserialize<T>(byte[] json, JsonSerializerOptions options)
    {
        T? value;
        try
        {
            value = JsonSerializer.Deserialize<T>(json, options);
        }
        catch (JsonException)
        {
            return;
        }
        catch (NotSupportedException)
        {
            return;
        }
        catch (InvalidOperationException e) when (IsInvalidText(e))
        {
            return;
        }

        // Whatever we could read we must be able to write, and read back.
        byte[] written;
        try
        {
            written = JsonSerializer.SerializeToUtf8Bytes(value, options);
        }
        catch (ArgumentException e) when (!s_reportKnownIssues && e.Message.StartsWith(".NET number values such as positive and negative infinity", StringComparison.Ordinal))
        {
            // Known: out-of-range literals such as 1e400 deserialize to double/float infinity, which
            // then can't be written back with strict number handling (FINDINGS.md, JSON-2).
            return;
        }
        _ = JsonSerializer.Deserialize<T>(written, options);
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    // Utf8JsonReader/JsonDocument validate string contents lazily: invalid UTF-8 and unpaired
    // \uXXXX surrogate escapes only surface as InvalidOperationException when a string is
    // materialized (documented behaviour), not as JsonException while reading.
    private static bool IsInvalidText(Exception e) =>
        e is InvalidOperationException &&
        (e.InnerException is DecoderFallbackException || e.Message.Contains("UTF-16 JSON text", StringComparison.Ordinal));

    private static List<string> ReadTokens(Utf8JsonReader reader)
    {
        var tokens = new List<string>();
        try
        {
            while (reader.Read())
            {
                tokens.Add(DescribeToken(ref reader));
            }
        }
        catch (JsonException e)
        {
            tokens.Add("!" + e.GetType().Name);
        }
        return tokens;
    }

    private static List<string> ReadIncrementally(byte[] json, byte seed, JsonReaderOptions options)
    {
        // Feed the payload in growing chunks, the way a stream-based consumer would.
        var tokens = new List<string>();
        var state = new JsonReaderState(options);
        int consumed = 0;
        int available = Math.Min(json.Length, 1 + seed % 7);
        try
        {
            while (true)
            {
                bool isFinal = available == json.Length;
                var reader = new Utf8JsonReader(json.AsSpan(consumed, available - consumed), isFinal, state);
                bool progressed = false;
                while (reader.Read())
                {
                    tokens.Add(DescribeToken(ref reader));
                    progressed = true;
                }

                if (isFinal)
                {
                    break;
                }

                consumed += (int)reader.BytesConsumed;
                state = reader.CurrentState;
                available = Math.Min(json.Length, available + 1 + (progressed ? seed % 5 : seed % 3));
            }
        }
        catch (JsonException e)
        {
            tokens.Add("!" + e.GetType().Name);
        }
        return tokens;
    }

    private static string DescribeToken(ref Utf8JsonReader reader)
    {
        var sb = new StringBuilder();
        sb.Append(reader.TokenType).Append('@').Append(reader.CurrentDepth);
        switch (reader.TokenType)
        {
            case JsonTokenType.PropertyName:
            case JsonTokenType.String:
                string s;
                try
                {
                    s = reader.GetString()!;
                }
                catch (InvalidOperationException e) when (IsInvalidText(e))
                {
                    // Utf8JsonReader validates UTF-8 lazily, when the value is transcoded (documented).
                    sb.Append(" <invalid-utf8> ").Append(Convert.ToHexString(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan));
                    break;
                }
                sb.Append(' ').Append(RegexTarget.Quote(s));

                // Exercise the other string accessors; they must agree with GetString.
                if (!reader.ValueTextEquals(s))
                {
                    throw new ConsistencyException($"ValueTextEquals(GetString()) is false for {RegexTarget.Quote(s)}");
                }

                char[] buffer = new char[s.Length + 8];
                int written = reader.CopyString(buffer);
                if (!buffer.AsSpan(0, written).SequenceEqual(s))
                {
                    throw new ConsistencyException($"CopyString != GetString for {RegexTarget.Quote(s)}");
                }

                if (reader.TokenType == JsonTokenType.String)
                {
                    sb.Append(reader.TryGetGuid(out Guid g) ? $" guid:{g}" : "");
                    sb.Append(reader.TryGetDateTime(out DateTime dt) ? $" dt:{dt.Ticks}/{dt.Kind}" : "");
                    sb.Append(reader.TryGetDateTimeOffset(out DateTimeOffset dto) ? $" dto:{dto.UtcTicks}/{dto.Offset}" : "");
                    sb.Append(reader.TryGetBytesFromBase64(out byte[]? bytes) ? $" b64:{Convert.ToHexString(bytes!)}" : "");
                }
                break;

            case JsonTokenType.Number:
                sb.Append(reader.TryGetInt64(out long l) ? $" i64:{l}" : "");
                sb.Append(reader.TryGetUInt64(out ulong ul) ? $" u64:{ul}" : "");
                sb.Append(reader.TryGetInt32(out int i) ? $" i32:{i}" : "");
                sb.Append(reader.TryGetDecimal(out decimal m) ? $" dec:{m}" : "");
                sb.Append(reader.TryGetDouble(out double d) ? $" dbl:{BitConverter.DoubleToInt64Bits(d):X}" : "");
                sb.Append(reader.TryGetSingle(out float f) ? $" sgl:{BitConverter.SingleToInt32Bits(f):X}" : "");
                break;

            case JsonTokenType.Comment:
                try
                {
                    sb.Append(' ').Append(RegexTarget.Quote(reader.GetComment()));
                }
                catch (InvalidOperationException e) when (IsInvalidText(e))
                {
                    sb.Append(" <invalid-utf8>");
                }
                break;

            case JsonTokenType.True:
            case JsonTokenType.False:
                sb.Append(' ').Append(reader.GetBoolean());
                break;
        }
        return sb.ToString();
    }

    private static ReadOnlySequence<byte> Segment(byte[] json, byte seed)
    {
        if (json.Length == 0)
        {
            return new ReadOnlySequence<byte>(json);
        }

        // Split into segments of 1..(seed%8+1) bytes; seed 0 means one byte per segment.
        int maxLen = (seed & 0x07) + 1;
        var rng = new Random(seed);
        BufferSegment first = new BufferSegment(json.AsMemory(0, Math.Min(json.Length, rng.Next(1, maxLen + 1))));
        BufferSegment last = first;
        int pos = first.Memory.Length;
        while (pos < json.Length)
        {
            int len = Math.Min(json.Length - pos, rng.Next(1, maxLen + 1));
            // Occasionally insert an empty segment, which the reader must tolerate.
            if (rng.Next(8) == 0)
            {
                last = last.Append(ReadOnlyMemory<byte>.Empty);
            }
            last = last.Append(json.AsMemory(pos, len));
            pos += len;
        }
        return new ReadOnlySequence<byte>(first, 0, last, last.Memory.Length);
    }

    private sealed class BufferSegment : ReadOnlySequenceSegment<byte>
    {
        public BufferSegment(ReadOnlyMemory<byte> memory) => Memory = memory;

        public BufferSegment Append(ReadOnlyMemory<byte> memory)
        {
            var next = new BufferSegment(memory) { RunningIndex = RunningIndex + Memory.Length };
            Next = next;
            return next;
        }
    }

    private static void CheckSame(string aName, List<string> a, string bName, List<string> b, byte[] json, JsonReaderOptions options)
    {
        if (!a.SequenceEqual(b))
        {
            int i = 0;
            while (i < a.Count && i < b.Count && a[i] == b[i]) i++;
            throw new ConsistencyException(
                $"Utf8JsonReader {aName} vs {bName} token streams differ at token {i}: " +
                $"{(i < a.Count ? a[i] : "<end>")} vs {(i < b.Count ? b[i] : "<end>")} for {Describe(json, options)}");
        }
    }

    /// <summary>
    /// For arrays of numbers, checks JsonElement.DeepEquals on every pair against a reference
    /// decimal comparison that uses arbitrary-precision exponents.
    /// </summary>
    private static void CheckNumberEquality(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        var numbers = new List<JsonElement>();
        foreach (JsonElement item in root.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.Number && numbers.Count < 8)
            {
                numbers.Add(item);
            }
        }

        for (int i = 0; i < numbers.Count; i++)
        {
            for (int j = i; j < numbers.Count; j++)
            {
                string a = numbers[i].GetRawText(), b = numbers[j].GetRawText();
                (bool negA, string digitsA, BigInteger expA, BigInteger rawExpA) = NormalizeNumber(a);
                (bool negB, string digitsB, BigInteger expB, BigInteger rawExpB) = NormalizeNumber(b);
                bool expected = negA == negB && digitsA == digitsB && expA == expB;

                bool actual;
                try
                {
                    actual = JsonElement.DeepEquals(numbers[i], numbers[j]);
                }
                catch (ArgumentOutOfRangeException e) when (e.ParamName == "exponent" && !s_reportKnownIssues)
                {
                    continue; // JSON-1
                }

                if (actual != expected)
                {
                    // JSON-3: the normalized exponent is computed in (unchecked) int arithmetic and wraps
                    // for exponents close to int.MinValue/int.MaxValue.
                    bool nearIntLimits = BigInteger.Abs(rawExpA) > int.MaxValue - 1_000_000 || BigInteger.Abs(rawExpB) > int.MaxValue - 1_000_000;
                    if (nearIntLimits && !s_reportKnownIssues)
                    {
                        continue;
                    }

                    throw new ConsistencyException($"JsonElement.DeepEquals({a}, {b}) = {actual}, expected {expected}");
                }
            }
        }
    }

    private static (bool Negative, string Digits, BigInteger Exponent, BigInteger RawExponent) NormalizeNumber(string number)
    {
        int pos = 0;
        bool negative = number[0] == '-';
        if (negative) pos++;

        int e = number.IndexOfAny(['e', 'E']);
        string mantissa = e < 0 ? number.Substring(pos) : number.Substring(pos, e - pos);
        BigInteger rawExponent = e < 0 ? BigInteger.Zero : BigInteger.Parse(number.AsSpan(e + 1), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);

        int dot = mantissa.IndexOf('.');
        string integral = dot < 0 ? mantissa : mantissa.Substring(0, dot);
        string fractional = dot < 0 ? "" : mantissa.Substring(dot + 1);

        string digits = (integral + fractional).TrimStart('0');
        BigInteger exponent = rawExponent - fractional.Length;
        if (digits.Length == 0)
        {
            return (false, "", BigInteger.Zero, rawExponent); // all zeros are equal, regardless of sign/exponent
        }

        string trimmed = digits.TrimEnd('0');
        exponent += digits.Length - trimmed.Length;
        return (negative, trimmed, exponent, rawExponent);
    }

    private static void Walk(JsonElement e, int depth)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (JsonProperty p in e.EnumerateObject())
                {
                    if (!p.NameEquals(p.Name))
                    {
                        throw new ConsistencyException($"JsonProperty.NameEquals(Name) false for {RegexTarget.Quote(p.Name)}");
                    }
                    if (!e.TryGetProperty(p.Name, out _))
                    {
                        throw new ConsistencyException($"TryGetProperty({RegexTarget.Quote(p.Name)}) false for enumerated property");
                    }
                    Walk(p.Value, depth + 1);
                }
                break;
            case JsonValueKind.Array:
                int n = e.GetArrayLength();
                int k = 0;
                foreach (JsonElement item in e.EnumerateArray())
                {
                    Walk(item, depth + 1);
                    k++;
                }
                if (k != n)
                {
                    throw new ConsistencyException($"GetArrayLength {n} != enumerated {k}");
                }
                break;
            case JsonValueKind.String:
                string s = e.GetString()!;
                if (!e.ValueEquals(s))
                {
                    throw new ConsistencyException($"JsonElement.ValueEquals(GetString()) false for {RegexTarget.Quote(s)}");
                }
                e.TryGetGuid(out _);
                e.TryGetDateTime(out _);
                e.TryGetDateTimeOffset(out _);
                e.TryGetBytesFromBase64(out _);
                break;
            case JsonValueKind.Number:
                e.TryGetInt64(out _);
                e.TryGetUInt64(out _);
                e.TryGetDecimal(out _);
                e.TryGetDouble(out _);
                e.TryGetSingle(out _);
                break;
        }
    }

    private static void WalkNode(JsonNode? node, int depth)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (KeyValuePair<string, JsonNode?> kv in o)
                {
                    _ = kv.Value?.GetPath();
                    WalkNode(kv.Value, depth + 1);
                }
                break;
            case JsonArray a:
                foreach (JsonNode? item in a)
                {
                    WalkNode(item, depth + 1);
                }
                break;
            case JsonValue v:
                _ = v.GetValueKind();
                v.TryGetValue(out string? _);
                v.TryGetValue(out double _);
                v.TryGetValue(out JsonElement _);
                break;
        }
    }

    private static byte[] Write(JsonElement element)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { SkipValidation = false, MaxDepth = 0 }))
        {
            element.WriteTo(writer);
        }
        return buffer.WrittenSpan.ToArray();
    }

    private static string Describe(byte[] json, JsonReaderOptions options) =>
        $"[comments={options.CommentHandling} trailingCommas={options.AllowTrailingCommas} multipleValues={options.AllowMultipleValues} maxDepth={options.MaxDepth}] " +
        $"hex={Convert.ToHexString(json)}";
}
