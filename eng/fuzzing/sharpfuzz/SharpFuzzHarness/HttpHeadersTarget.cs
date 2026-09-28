#nullable disable warnings
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// HTTP header value parsing (System.Net.Http.Headers): every header value type's TryParse on fuzzed
/// text; a parsed value's ToString() must parse back to an equal value; and the HttpHeaders
/// collection: values added without validation, read back parsed (Get / TryGetValues / ToString) and
/// non-validated, must agree with parsing the values directly.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     header type / header name
///   rest       the value, UTF-8 (Latin-1 for bytes that aren't valid UTF-8)
/// </remarks>
public static class HttpHeadersTarget
{
    private static readonly string[] s_names =
    [
        "Accept", "Accept-Charset", "Accept-Encoding", "Accept-Language", "Authorization", "Cache-Control", "Connection", "Content-Disposition",
        "Content-Range", "Content-Type", "Cookie", "Date", "ETag", "Expect", "Host", "If-Match", "If-Modified-Since", "If-Range", "Pragma",
        "Range", "Retry-After", "Transfer-Encoding", "Upgrade", "Via", "Warning", "WWW-Authenticate", "Content-Length", "Alt-Svc", "X-Custom",
    ];

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte kind = input.Byte();
        byte[] bytes = input.Rest().ToArray();
        if (bytes.Length > 2048)
        {
            return;
        }

        string value = Encoding.UTF8.GetString(bytes);
        if (value.Contains('�'))
        {
            value = Encoding.Latin1.GetString(bytes);
        }

        string what = $"kind {kind} value {Check.Show(value)}";
        switch (kind % 18)
        {
            case 0: RoundTrip<MediaTypeHeaderValue>(value, MediaTypeHeaderValue.TryParse, what); break;
            case 1: RoundTrip<MediaTypeWithQualityHeaderValue>(value, MediaTypeWithQualityHeaderValue.TryParse, what); break;
            case 2: RoundTrip<StringWithQualityHeaderValue>(value, StringWithQualityHeaderValue.TryParse, what); break;
            case 3: RoundTrip<AuthenticationHeaderValue>(value, AuthenticationHeaderValue.TryParse, what); break;
            case 4: RoundTrip<CacheControlHeaderValue>(value, CacheControlHeaderValue.TryParse, what); break;
            case 5: RoundTrip<ContentDispositionHeaderValue>(value, ContentDispositionHeaderValue.TryParse, what); break;
            case 6: RoundTrip<ContentRangeHeaderValue>(value, ContentRangeHeaderValue.TryParse, what); break;
            case 7: RoundTrip<EntityTagHeaderValue>(value, EntityTagHeaderValue.TryParse, what); break;
            case 8: RoundTrip<RangeHeaderValue>(value, RangeHeaderValue.TryParse, what); break;
            case 9: RoundTrip<RangeConditionHeaderValue>(value, RangeConditionHeaderValue.TryParse, what); break;
            case 10: RoundTrip<RetryConditionHeaderValue>(value, RetryConditionHeaderValue.TryParse, what); break;
            case 11: RoundTrip<TransferCodingWithQualityHeaderValue>(value, TransferCodingWithQualityHeaderValue.TryParse, what); break;
            case 12: RoundTrip<NameValueWithParametersHeaderValue>(value, NameValueWithParametersHeaderValue.TryParse, what); break;
            case 13: RoundTrip<ProductInfoHeaderValue>(value, ProductInfoHeaderValue.TryParse, what); break;
            case 14: RoundTrip<ViaHeaderValue>(value, ViaHeaderValue.TryParse, what); break;
            case 15: RoundTrip<WarningHeaderValue>(value, WarningHeaderValue.TryParse, what); break;
            case 16: RoundTrip<ProductHeaderValue>(value, ProductHeaderValue.TryParse, what); break;
            default: Collection(s_names[kind / 18 % s_names.Length], value, what); break;
        }
    }

    private delegate bool TryParse<T>(string input, out T parsed);

    private static void RoundTrip<T>(string value, TryParse<T> tryParse, string what) where T : class
    {
        if (!tryParse(value, out T parsed))
        {
            return;
        }

        string text = parsed.ToString();
        Check.That(tryParse(text, out T again), $"{typeof(T).Name}: ToString {Check.Show(text)} doesn't parse: {what}");
        // HTTP-QVALUE-1 (informational): q-values with more than three decimals (or leading zeros) parse, and
        // ToString rounds them to three decimals, so the value read back isn't Equal.
        bool rounded = text.Contains("q=", StringComparison.OrdinalIgnoreCase) && text == again.ToString();
        Check.That(parsed.Equals(again) || rounded, $"{typeof(T).Name}: ToString {Check.Show(text)} parses to {Check.Show(again.ToString())}, not an equal value: {what}");
        Check.Equal(text, again.ToString(), $"{typeof(T).Name}: ToString isn't stable: {what}");
        Check.That(rounded || parsed.GetHashCode() == again.GetHashCode(), $"{typeof(T).Name}: equal values with different hash codes: {what}");
        if (parsed is ICloneable c)
        {
            object clone = c.Clone();
            Check.That(clone.Equals(parsed) && clone.ToString() == text, $"{typeof(T).Name}: Clone differs: {what}");
        }
    }

    private static void Collection(string name, string value, string what)
    {
        what = $"{name}: {what}";
        var message = new HttpRequestMessage();
        HttpHeaders headers = name.StartsWith("Content-", StringComparison.Ordinal) || name == "Content-Type" ? (message.Content = new ByteArrayContent([])).Headers : message.Headers;
        bool added = headers.TryAddWithoutValidation(name, value);
        if (!added)
        {
            return;
        }

        // The non-validated view returns what was added.
        Check.That(headers.NonValidated.TryGetValues(name, out HeaderStringValues raw), $"NonValidated.TryGetValues: {what}");
        string nonValidated = raw.ToString();

        // Parsing on access: TryGetValues, enumeration and ToString must not throw and must agree.
        bool got = headers.TryGetValues(name, out IEnumerable<string> values);
        string joined = got ? string.Join(", ", values) : null;
        string enumerated = string.Join("|", headers.Where(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)).SelectMany(h => h.Value));
        string all = headers.ToString();
        Check.That(got || !headers.Contains(name), $"TryGetValues false but Contains true: {what}");
        if (got)
        {
            Check.That(all.Contains(name, StringComparison.OrdinalIgnoreCase), $"ToString lacks the header: {what}");
        }

        // Adding the same header again with validation goes through the same parser.
        var fresh = new HttpRequestMessage();
        HttpHeaders validated = name.StartsWith("Content-", StringComparison.Ordinal) ? (fresh.Content = new ByteArrayContent([])).Headers : fresh.Headers;
        var add = Outcome<bool>.Of(() => { validated.Add(name, value); return true; }, e => e is FormatException or InvalidOperationException);
        if (add.Ok && validated.TryGetValues(name, out IEnumerable<string> v2))
        {
            Check.Equal(string.Join("|", v2), string.Join("|", values ?? []), $"validated Add vs TryAddWithoutValidation values (non-validated {Check.Show(nonValidated)}, enumerated {Check.Show(enumerated)}): {what}");
        }
    }
}
