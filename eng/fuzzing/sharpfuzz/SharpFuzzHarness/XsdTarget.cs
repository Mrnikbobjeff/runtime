#nullable disable warnings
using System.Xml;
using System.Xml.Schema;

namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Xml.Schema: compiling XSD schemas and validating documents against them.</summary>
/// <remarks>
/// Input layout:
///   byte 0     0x01 process inline schemas
///   segments   the schema, the document
/// Checks: schema compilation and validation report problems through the ValidationEventHandler or
/// XmlException / XmlSchemaException only; the validating XmlReader and XmlDocument.Validate
/// (a separate validator) agree on whether the document is valid.
/// </remarks>
public static class XsdTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte flags = input.Byte();
        string schemaText = input.Segment();
        string documentText = input.Segment();
        if (schemaText.Length + documentText.Length > 8192)
        {
            return;
        }

        string what = $"schema {Check.Show(schemaText)}, document {Check.Show(documentText)}";
        var parse = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1 << 20 };
        var set = new XmlSchemaSet { XmlResolver = null };
        int schemaErrors = 0;
        set.ValidationEventHandler += (_, e) => schemaErrors++;
        try
        {
            set.Add(null, XmlReader.Create(new StringReader(schemaText), parse));
            set.Compile();
        }
        catch (Exception e) when (e is XmlException or XmlSchemaException)
        {
            return;
        }

        foreach (XmlSchema schema in set.Schemas())
        {
            var sw = new StringWriter();
            schema.Write(sw);
        }

        // The default flags (as XmlDocument.Validate uses), plus inline schemas on request.
        var validation = XmlSchemaValidationFlags.ProcessIdentityConstraints | XmlSchemaValidationFlags.AllowXmlAttributes |
            ((flags & 1) != 0 ? XmlSchemaValidationFlags.ProcessInlineSchema : 0);
        int readerErrors = 0;
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 1 << 20,
            ValidationType = ValidationType.Schema, Schemas = set, ValidationFlags = validation,
        };
        settings.ValidationEventHandler += (_, e) => readerErrors += e.Severity == XmlSeverityType.Error ? 1 : 0;
        try
        {
            using XmlReader reader = XmlReader.Create(new StringReader(documentText), settings);
            while (reader.Read())
            {
            }
        }
        catch (Exception e) when (e is XmlException or XmlSchemaException)
        {
            return;
        }

        if ((flags & 1) != 0)
        {
            return; // XmlDocument.Validate doesn't process inline schemas
        }

        var doc = new XmlDocument { XmlResolver = null };
        try
        {
            doc.Load(XmlReader.Create(new StringReader(documentText), parse));
        }
        catch (XmlException)
        {
            return;
        }

        doc.Schemas = set;
        int documentErrors = 0;
        doc.Validate((_, e) => documentErrors += e.Severity == XmlSeverityType.Error ? 1 : 0);
        Check.That((readerErrors == 0) == (documentErrors == 0), $"validating reader: {readerErrors} errors, XmlDocument.Validate: {documentErrors} errors for {what}");
    }
}
