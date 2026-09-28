#nullable disable warnings
using System.Runtime.Serialization.Json;
using System.Text;
using System.Text.Json;
using System.Xml;

namespace SharpFuzzHarness;

/// <summary>
/// The DataContract JSON stack (JsonReaderWriterFactory: its own JSON parser mapped onto an XML infoset,
/// System.Private.DataContractSerialization) against System.Text.Json: JSON that Utf8JsonReader accepts
/// must be accepted and give the same string values and number texts; reading from a byte array and from
/// a stream that returns a few bytes per read must agree; and copying through the JSON writer must read
/// back the same.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     options / chunk pattern
///   rest       the JSON, UTF-8
/// </remarks>
public static class DcJsonTarget
{
    private sealed class ChunkStream(byte[] data, byte pattern) : Stream
    {
        private int _position, _reads;

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = Math.Min(count, Math.Min(data.Length - _position, 1 + (pattern >> (_reads++ % 4 * 2) & 3) * 5));
            Array.Copy(data, _position, buffer, offset, n);
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

    private static XmlDictionaryReaderQuotas Quotas => new() { MaxDepth = 64, MaxStringContentLength = 1 << 16, MaxArrayLength = 1 << 16, MaxBytesPerRead = 1 << 16, MaxNameTableCharCount = 1 << 16 };

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte pattern = input.Byte();
        byte[] bytes = input.Rest().ToArray();
        if (bytes.Length > 8192)
        {
            return;
        }

        string what = $"pattern {pattern:X2} {Check.Show(Encoding.UTF8.GetString(bytes))}";
        var fromBytes = Outcome<string>.Of(() => Nodes(JsonReaderWriterFactory.CreateJsonReader(bytes, Quotas)), Allowed);
        var fromStream = Outcome<string>.Of(() => Nodes(JsonReaderWriterFactory.CreateJsonReader(new ChunkStream(bytes, pattern), Encoding.UTF8, Quotas, null)), Allowed);
        Check.That(fromBytes.SameAs(fromStream) || !fromBytes.Ok && !fromStream.Ok, $"CreateJsonReader(stream) [{fromStream}] vs (bytes) [{fromBytes}]: {what}");

        // JSON that System.Text.Json accepts (a single value, no comments), with its strings and numbers.
        // "__type" (the DataContract type hint) becomes an attribute, by design.
        var stj = Outcome<List<string>>.Of(() => Values(bytes), e => e is JsonException or InvalidOperationException);
        if (bytes.AsSpan().IndexOf("\"__type\""u8) >= 0)
        {
            return;
        }

        if (stj.Ok && fromBytes.Ok)
        {
            List<string> dc = DcValues(bytes);
            Check.That(dc.SequenceEqual(stj.Value), $"DataContract JSON values [{string.Join(" ", dc.Take(20))}] vs System.Text.Json [{string.Join(" ", stj.Value.Take(20))}]: {what}");
        }
        else if (stj.Ok && !fromBytes.Ok)
        {
            Check.That(false, $"System.Text.Json accepts it, CreateJsonReader throws {fromBytes}: {what}");
        }

        if (fromBytes.Ok)
        {
            // Copy through the JSON writer and read back.
            var ms = new MemoryStream();
            var copied = Outcome<bool>.Of(() =>
            {
                using XmlDictionaryWriter w = JsonReaderWriterFactory.CreateJsonWriter(ms, Encoding.UTF8, ownsStream: false);
                w.WriteNode(JsonReaderWriterFactory.CreateJsonReader(bytes, Quotas), true);
                return true;
            }, e => Allowed(e) || e is InvalidOperationException or ArgumentException);
            if (copied.Ok)
            {
                byte[] written = ms.ToArray();
                // Compared as values: the copy merges adjacent text and writes escaped names unescaped.
                var again = Outcome<string>.Of(() => string.Join(" ", DcValues(written)), Allowed);
                string original = string.Join(" ", DcValues(bytes));
                Check.That(again.Ok && again.Value == original, $"copy {Check.Show(Encoding.UTF8.GetString(written))} reads as [{again}], original [{original}]: {what}");
            }
        }
    }

    // DCJSON-CTRL-1 (informational): a raw control character in a string throws FormatException, where other
    // malformed JSON throws XmlException (DataContractJsonSerializer wraps both in SerializationException).
    private static bool Allowed(Exception e) => e is XmlException or FormatException or System.Runtime.Serialization.SerializationException || e is InvalidOperationException && e.Message.Contains("quota", StringComparison.OrdinalIgnoreCase);

    private static string Nodes(XmlDictionaryReader reader)
    {
        var sb = new StringBuilder();
        using (reader)
        {
            while (reader.Read() && sb.Length < 50000)
            {
                sb.Append(reader.NodeType).Append(':').Append(reader.LocalName);
                if (reader.NodeType == XmlNodeType.Element)
                {
                    sb.Append('[').Append(reader.GetAttribute("type")).Append('|').Append(reader.GetAttribute("item")).Append(']');
                }
                else if (reader.NodeType == XmlNodeType.Text)
                {
                    sb.Append('=').Append(Check.Escape(reader.Value, 1 << 16));
                }

                sb.Append(';');
            }
        }

        return sb.ToString();
    }

    /// <summary>String values, property names and number texts in document order, per System.Text.Json.</summary>
    private static List<string> Values(byte[] bytes)
    {
        var list = new List<string>();
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = 64 });
        while (reader.Read())
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.PropertyName: list.Add("name:" + Check.Escape(reader.GetString(), 1 << 16)); break;
                case JsonTokenType.String: list.Add("string:" + Check.Escape(reader.GetString(), 1 << 16)); break;
                case JsonTokenType.Number: list.Add("number:" + Encoding.UTF8.GetString(reader.ValueSpan)); break;
                case JsonTokenType.True: list.Add("true"); break;
                case JsonTokenType.False: list.Add("false"); break;
                case JsonTokenType.Null: list.Add("null"); break;
            }
        }

        return list;
    }

    /// <summary>The same list from the DataContract reader's infoset (element names or item attributes, typed text; adjacent text merged).</summary>
    private static List<string> DcValues(byte[] bytes)
    {
        var list = new List<string>();
        using XmlDictionaryReader reader = JsonReaderWriterFactory.CreateJsonReader(bytes, Quotas);
        var parents = new Stack<(string Type, StringBuilder Text)>();
        while (reader.Read())
        {
            if (reader.NodeType == XmlNodeType.Element)
            {
                string type = reader.GetAttribute("type") ?? "string";
                string name = reader.GetAttribute("item") ?? reader.LocalName;
                if (parents.Count > 0 && parents.Peek().Type == "object")
                {
                    list.Add("name:" + Check.Escape(name, 1 << 16));
                }

                if (reader.IsEmptyElement)
                {
                    Close(list, type, null);
                    continue;
                }

                parents.Push((type, type is "object" or "array" ? null : new StringBuilder()));
            }
            else if (reader.NodeType == XmlNodeType.EndElement)
            {
                (string type, StringBuilder text) = parents.Pop();
                Close(list, type, text);
            }
            else if (reader.NodeType is XmlNodeType.Text or XmlNodeType.Whitespace or XmlNodeType.SignificantWhitespace && parents.Count > 0)
            {
                parents.Peek().Text?.Append(reader.Value);
            }
        }

        return list;
    }

    private static void Close(List<string> list, string type, StringBuilder text)
    {
        switch (type)
        {
            case "object" or "array": break;
            case "null": list.Add("null"); break;
            case "number": list.Add("number:" + text); break;
            case "boolean": list.Add(text?.ToString() ?? ""); break;
            default: list.Add("string:" + Check.Escape(text?.ToString() ?? "", 1 << 16)); break;
        }
    }
}
