#nullable disable warnings
using System.Text;
using System.Xml;

namespace SharpFuzzHarness;

/// <summary>
/// Fuzzes XmlDictionaryReader (System.Private.DataContractSerialization): the WCF binary XML reader /
/// writer and the UTF-8 text reader, which is a separate XML parser from System.Private.Xml's.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     0x01: the rest is UTF-8 text XML, otherwise binary XML
///   rest       the document
/// Checks: only XmlException (and quota exceptions) are thrown; a binary document copied through
/// XmlDictionaryWriter.CreateBinaryWriter (WriteNode) reads back as the same nodes, and so does one
/// copied to text and read with the text reader; for text XML both XmlDictionaryReader.CreateTextReader
/// and XmlReader.Create accept it or reject it, and see the same nodes.
/// </remarks>
public static class BinaryXmlTarget
{
    private static readonly XmlDictionary s_dictionary = CreateDictionary();

    private static XmlDictionary CreateDictionary()
    {
        var d = new XmlDictionary();
        foreach (string s in (string[])["Envelope", "http://www.w3.org/2003/05/soap-envelope", "Header", "Body", "a", "b", "xmlns", "i", "http://www.w3.org/2001/XMLSchema-instance", "type", "nil", "Value"])
        {
            d.Add(s);
        }

        return d;
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    private static XmlDictionaryReaderQuotas Quotas => new() { MaxDepth = 64, MaxStringContentLength = 65536, MaxArrayLength = 65536, MaxBytesPerRead = 65536, MaxNameTableCharCount = 65536 };

    // Known (BINXML-ENC-1): CreateTextReader indexes past the end of an unterminated XML declaration
    // encoding (<?xml version='1.0' encoding='utf-8) and throws IndexOutOfRangeException.
    private static bool Allowed(Exception e) => e is XmlException or DecoderFallbackException or InvalidDataException ||
        e is InvalidOperationException && e.Message.Contains("quota", StringComparison.OrdinalIgnoreCase) ||
        !s_reportKnownIssues && e is IndexOutOfRangeException && e.StackTrace?.Contains("CheckUTF8DeclarationEncoding", StringComparison.Ordinal) == true;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        byte[] bytes = input.Rest().ToArray();
        string what = $"{((mode & 1) != 0 ? "text" : "binary")} XML 0x{Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 64)))}{(bytes.Length > 64 ? "..." : "")}";
        if ((mode & 1) != 0)
        {
            Text(bytes, what);
        }
        else
        {
            Binary(bytes, what);
        }
    }

    private static void Binary(byte[] bytes, string what)
    {
        var nodes = Outcome<List<string>>.Of(() => Nodes(XmlDictionaryReader.CreateBinaryReader(bytes, 0, bytes.Length, s_dictionary, Quotas)), Allowed);
        if (!nodes.Ok)
        {
            return;
        }

        // Copy through the binary writer and read back.
        var ms = new MemoryStream();
        using (XmlDictionaryWriter writer = XmlDictionaryWriter.CreateBinaryWriter(ms, s_dictionary, null, ownsStream: false))
        {
            using XmlDictionaryReader reader = XmlDictionaryReader.CreateBinaryReader(bytes, 0, bytes.Length, s_dictionary, Quotas);
            var copied = Outcome<bool>.Of(() => { writer.WriteNode(reader, defattr: true); return true; }, e => Allowed(e) || e is ArgumentException or InvalidOperationException);
            if (!copied.Ok)
            {
                return; // e.g. content the writer refuses (invalid surrogates in names)
            }
        }

        byte[] rewritten = ms.ToArray();
        var again = Outcome<List<string>>.Of(() => Nodes(XmlDictionaryReader.CreateBinaryReader(rewritten, 0, rewritten.Length, s_dictionary, Quotas)), Allowed);
        // Known (BINXML-DT-1): copying a DateTime record through the binary writer drops its Kind
        // ("...Z" / "+hh:mm" becomes unspecified).
        // Empty text records ("") produce no node once copied.
        static List<string> Kinds(List<string> list) => s_reportKnownIssues ? list :
            list.Where(t => t != "Text:||=\"\"").Select(t => System.Text.RegularExpressions.Regex.Replace(t, @"(\d{4}-\d\d-\d\dT[\d:.]+)(Z|[+-]\d\d:\d\d)", "$1")).ToList();
        Check.That(again.Ok && Kinds(again.Value).SequenceEqual(Kinds(nodes.Value)),
            $"binary copy 0x{Convert.ToHexString(rewritten.AsSpan(0, Math.Min(rewritten.Length, 64)))} reads as {(again.Ok ? string.Join(" ", again.Value) : again.ToString())}, original {string.Join(" ", nodes.Value)}: {what}");
    }

    private static void Text(byte[] bytes, string what)
    {
        var dc = Outcome<List<string>>.Of(() => Normalize(Nodes(XmlDictionaryReader.CreateTextReader(bytes, Quotas))), Allowed);
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1 << 20 };
        var xml = Outcome<List<string>>.Of(() => Normalize(Nodes(XmlReader.Create(new MemoryStream(bytes), settings))), Allowed);
        if (dc.Ok && xml.Ok)
        {
            Check.That(dc.Value.SequenceEqual(xml.Value), $"XmlDictionaryReader.CreateTextReader reads [{string.Join(" ", dc.Value)}], XmlReader reads [{string.Join(" ", xml.Value)}]: {what}");
        }
    }

    /// <summary>The nodes as tokens: kind, qualified name and namespace, value, and sorted attributes.</summary>
    private static List<string> Nodes(XmlReader reader)
    {
        var nodes = new List<string>();
        using (reader)
        {
            while (reader.Read() && nodes.Count < 5000)
            {
                var sb = new StringBuilder();
                sb.Append(reader.NodeType).Append(':').Append(reader.Prefix).Append('|').Append(reader.LocalName).Append('|').Append(reader.NamespaceURI);
                if (reader.NodeType is XmlNodeType.Text or XmlNodeType.CDATA or XmlNodeType.Whitespace or XmlNodeType.SignificantWhitespace or XmlNodeType.Comment or XmlNodeType.ProcessingInstruction)
                {
                    sb.Append('=').Append(Check.Show(reader.Value));
                }

                if (reader.NodeType == XmlNodeType.Element)
                {
                    sb.Append(reader.IsEmptyElement ? "/" : "");
                    var attributes = new List<string>();
                    while (reader.MoveToNextAttribute())
                    {
                        attributes.Add($"{reader.Prefix}|{reader.LocalName}|{reader.NamespaceURI}={Check.Show(reader.Value)}");
                    }

                    reader.MoveToElement();
                    attributes.Sort(StringComparer.Ordinal);
                    sb.Append('[').Append(string.Join(",", attributes)).Append(']');
                }

                nodes.Add(sb.ToString());
            }
        }

        return nodes;
    }

    /// <summary>Makes the two text readers comparable: drops the XML declaration, turns CDATA into text and merges adjacent text.</summary>
    private static List<string> Normalize(List<string> nodes)
    {
        var result = new List<string>();
        foreach (string node in nodes)
        {
            if (node.StartsWith("XmlDeclaration:", StringComparison.Ordinal))
            {
                continue;
            }

            string n = node.StartsWith("CDATA:", StringComparison.Ordinal) ? "Text:" + node["CDATA:".Length..] : node;
            // The two readers split character data into text and whitespace nodes differently.
            foreach (string ws in (string[])["Whitespace:", "SignificantWhitespace:"])
            {
                if (n.StartsWith(ws, StringComparison.Ordinal))
                {
                    n = "Text:" + n[ws.Length..];
                }
            }

            // Adjacent text (or whitespace) nodes may be split differently by the two readers: merge them.
            string kind = n[..(n.IndexOf(':') + 1)];
            if (result.Count > 0 && kind is "Text:" or "Whitespace:" or "SignificantWhitespace:" && result[^1].StartsWith(kind, StringComparison.Ordinal))
            {
                string previous = result[^1];
                result[^1] = previous[..^1] + n[(n.IndexOf("=\"", StringComparison.Ordinal) + 2)..];
                continue;
            }

            result.Add(n);
        }

        return result;
    }
}
