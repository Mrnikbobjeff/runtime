#nullable disable warnings
using System.Buffers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace SharpFuzzHarness;

/// <summary>
/// JsonSerializer and JsonNode over guarded memory (see <see cref="Guarded"/>): deserializing a model
/// whose properties go through most built-in converters (numbers including Half / Int128, dates,
/// Guid, Version, Uri, base64 byte arrays, enums, collections, JsonElement), from a UTF-8 span, a
/// char span and a string; serializing into an IBufferWriter that hands out exactly the requested
/// size. Checks: the three overloads agree; only JsonException escapes; serialization into exactly
/// sized buffers matches serialization to a string; a round trip is idempotent.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     options bits; byte 1 root type and placement
///   rest       the JSON, UTF-8 (up to 8 KB)
/// </remarks>
public static class UnsafeJsonTarget
{
    public sealed class Model
    {
        public int I { get; set; }
        public long L { get; set; }
        public double D { get; set; }
        public float F { get; set; }
        public decimal M { get; set; }
        public Half H { get; set; }
        public Int128 Big { get; set; }
        public UInt128 UBig { get; set; }
        public string S { get; set; }
        public char C { get; set; }
        public byte[] Bytes { get; set; }
        public DateTime Dt { get; set; }
        public DateTimeOffset Dto { get; set; }
        public DateOnly Date { get; set; }
        public TimeOnly Time { get; set; }
        public TimeSpan Ts { get; set; }
        public Guid G { get; set; }
        public Version V { get; set; }
        public Uri U { get; set; }
        public DayOfWeek E { get; set; }
        public int? N { get; set; }
        public List<int> List { get; set; }
        public Dictionary<string, double> Map { get; set; }
        public long[] Arr { get; set; }
        public Model Child { get; set; }
        public JsonElement? Extra { get; set; }
        public object Obj { get; set; }
    }

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte flags = input.Byte();
        byte kind = input.Byte();
        byte[] utf8 = input.Rest().ToArray();
        if (utf8.Length > 8192)
        {
            return;
        }

        var options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = (flags & 1) != 0,
            NumberHandling = ((flags & 2) != 0 ? JsonNumberHandling.AllowReadingFromString : 0) | ((flags & 4) != 0 ? JsonNumberHandling.AllowNamedFloatingPointLiterals : 0),
            AllowTrailingCommas = (flags & 8) != 0,
            ReadCommentHandling = (flags & 16) != 0 ? JsonCommentHandling.Skip : JsonCommentHandling.Disallow,
            AllowDuplicateProperties = (flags & 32) == 0,
            MaxDepth = 32,
        };
        if ((flags & 64) != 0)
        {
            options.Converters.Add(new JsonStringEnumConverter());
        }

        bool atStart = (kind & 1) != 0;
        string what = $"flags {flags:X2} kind {kind:X2} {Check.Show(Encoding.UTF8.GetString(utf8))}";
        switch ((kind >> 1) % 3)
        {
            case 0: RoundTrip<Model>(utf8, options, atStart, what); break;
            case 1: RoundTrip<Dictionary<string, JsonElement>>(utf8, options, atStart, what); break;
            default: Node(utf8, options, atStart, what); break;
        }
    }

    private static bool Allowed(Exception e) => e is JsonException;

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    private static void RoundTrip<T>(byte[] utf8, JsonSerializerOptions options, bool atStart, string what)
    {
        Outcome<string> Deserialize(Func<T> f) => Outcome<string>.Of(() => Serialize(f(), options), Allowed);
        ReadOnlySpan<byte> guarded = Guarded.Copy<byte>(utf8, atStart);
        byte[] copy = guarded.ToArray();
        var fromArray = Deserialize(() => JsonSerializer.Deserialize<T>(utf8, options));
        // Spans can't be captured, so the guarded copy is read through a Memory over the same slot.
        Memory<byte> guardedMemory = Guarded.CopyMemory<byte>(copy, atStart);
        var fromGuarded = Deserialize(() => JsonSerializer.Deserialize<T>(guardedMemory.Span, options));
        Check.That(fromArray.SameAs(fromGuarded), $"Deserialize<{typeof(T).Name}>(guarded utf8) {fromGuarded} vs (array) {fromArray}: {what}");

        string text = Encoding.UTF8.GetString(utf8);
        if (Encoding.UTF8.GetByteCount(text) == utf8.Length && !text.Contains('�'))
        {
            Memory<char> chars = Guarded.CopyMemory<char>(text.AsSpan(), !atStart);
            var fromChars = Deserialize(() => JsonSerializer.Deserialize<T>(chars.Span, options));
            var fromString = Deserialize(() => JsonSerializer.Deserialize<T>(text, options));
            Check.That(fromChars.SameAs(fromString) && fromString.SameAs(fromArray), $"Deserialize<{typeof(T).Name}>(chars) {fromChars}, (string) {fromString}, (utf8) {fromArray}: {what}");
        }

        // JSON-FLOAT-1 (informational): numbers beyond float / double range read as infinities, which the
        // serializer then won't write without AllowNamedFloatingPointLiterals.
        if (!fromArray.Ok || fromArray.Value == "non-finite")
        {
            return;
        }

        // Serializing again is idempotent, and serializing into exactly sized guarded buffers gives the same bytes.
        string first = fromArray.Value;
        var again = Outcome<string>.Of(() => Serialize(JsonSerializer.Deserialize<T>(first, options), options), Allowed);
        Check.That(again.Ok && again.Value == first, $"round trip of {Check.Show(first)} gives {again}: {what}");
        var writer = new GuardedBufferWriter(!atStart);
        using (var w = new Utf8JsonWriter(writer))
        {
            JsonSerializer.Serialize(w, JsonSerializer.Deserialize<T>(first, options), options);
        }

        Check.That(Encoding.UTF8.GetString(writer.Written.ToArray()) == first, $"Serialize into exactly sized buffers wrote {Check.Show(Encoding.UTF8.GetString(writer.Written.ToArray()))}, to a string {Check.Show(first)}: {what}");
    }

    private static string Serialize<T>(T value, JsonSerializerOptions options)
    {
        try
        {
            return JsonSerializer.Serialize(value, options);
        }
        catch (ArgumentException e) when (e.Message.Contains("NaN", StringComparison.Ordinal) || e.Message.Contains("infinity", StringComparison.OrdinalIgnoreCase))
        {
            // Non-finite doubles only serialize with AllowNamedFloatingPointLiterals (they can come from strings).
            return "non-finite";
        }
    }

    private static void Node(byte[] utf8, JsonSerializerOptions options, bool atStart, string what)
    {
        var nodeOptions = new JsonNodeOptions { PropertyNameCaseInsensitive = options.PropertyNameCaseInsensitive };
        var documentOptions = new JsonDocumentOptions { AllowTrailingCommas = options.AllowTrailingCommas, CommentHandling = options.ReadCommentHandling, MaxDepth = 32, AllowDuplicateProperties = options.AllowDuplicateProperties };
        // Known (JSON-SURR-1): ToJsonString of a string with an escaped lone surrogate throws InvalidOperationException.
        static bool NodeAllowed(Exception e) => e is JsonException or ArgumentException || !s_reportKnownIssues && e is InvalidOperationException && e.Message.Contains("UTF-16", StringComparison.Ordinal);
        var fromArray = Outcome<string>.Of(() => JsonNode.Parse(utf8, nodeOptions, documentOptions)?.ToJsonString() ?? "null", NodeAllowed);
        Memory<byte> guarded = Guarded.CopyMemory<byte>(utf8, atStart);
        var fromGuarded = Outcome<string>.Of(() =>
        {
            var reader = new Utf8JsonReader(guarded.Span, new JsonReaderOptions { AllowTrailingCommas = documentOptions.AllowTrailingCommas, CommentHandling = documentOptions.CommentHandling, MaxDepth = 32 });
            return JsonNode.Parse(ref reader, nodeOptions)?.ToJsonString() ?? "null";
        }, NodeAllowed);
        if (fromArray.Ok && fromGuarded.Ok)
        {
            Check.Equal(fromArray.Value, fromGuarded.Value, $"JsonNode.Parse(ref reader over guarded memory) vs Parse(array): {what}");
        }

        if (fromArray.Ok && fromArray.Value != "null")
        {
            JsonNode node = JsonNode.Parse(fromArray.Value, nodeOptions);
            try
            {
                JsonNode clone = node.DeepClone();
                Check.That(JsonNode.DeepEquals(node, clone), $"DeepClone isn't DeepEquals: {what}");
            }
            catch (ArgumentException e) when (e is not ArgumentOutOfRangeException || !s_reportKnownIssues)
            {
                // A JsonObject with duplicate property names (also ones that only differ in case, with
                // PropertyNameCaseInsensitive) throws when its dictionary is first built, by design.
                // Known (JSON-DEEPEQ-1): DeepEquals throws ArgumentOutOfRangeException for numbers whose
                // exponent doesn't fit in an int.
                return;
            }
            var writer = new GuardedBufferWriter(atStart);
            using (var w = new Utf8JsonWriter(writer))
            {
                node.WriteTo(w);
            }

            Check.Equal(fromArray.Value, Encoding.UTF8.GetString(writer.Written.ToArray()), $"JsonNode.WriteTo into exactly sized buffers: {what}");
        }
    }

    /// <summary>An IBufferWriter that hands out exactly the requested size, in guarded memory, and collects what's advanced.</summary>
    private sealed class GuardedBufferWriter(bool atStart) : IBufferWriter<byte>
    {
        private Memory<byte> _current;
        public readonly List<byte> Written = [];

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            int size = Math.Max(sizeHint, 1);
            _current = size <= Guarded.SlotBytes ? Guarded.CopyMemory<byte>(new byte[size], atStart) : new byte[size];
            return _current;
        }

        public Span<byte> GetSpan(int sizeHint = 0) => GetMemory(sizeHint).Span;

        public void Advance(int count)
        {
            Check.That(count >= 0 && count <= _current.Length, $"Advance({count}) past the {_current.Length} bytes handed out");
            Written.AddRange(_current.Span[..count].ToArray());
            _current = default;
        }
    }
}
