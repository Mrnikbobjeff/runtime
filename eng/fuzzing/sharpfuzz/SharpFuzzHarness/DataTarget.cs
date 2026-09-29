#nullable disable warnings
using System.Data;
using System.Data.Common;
using System.Globalization;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Data.Common: connection string parsing / building and DataTable expressions.</summary>
/// <remarks>
/// Input layout:
///   byte 0     low 2 bits: 0 parse a connection string, 1 build one from key/value pairs,
///              2-3 DataTable expressions; 0x04 ODBC rules
///   mode 0     segment: connection string
///   mode 1     up to 4 x (segment key, segment value)
///   mode 2-3   segments: filter, column expression, Compute expression, sort; then row data
/// Checks: a parsed connection string serializes (ConnectionString) to one that parses back to the
/// same pairs; pairs set through the indexer or AppendKeyValuePair parse back as exactly those
/// pairs (no key/value injection); expressions only fail with the documented exceptions and
/// DataTable.Select agrees with a DataView over the same filter.
/// </remarks>
public static class DataTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        bool odbc = (mode & 4) != 0;
        switch (mode & 3)
        {
            case 0:
                Parse(input.Segment(), odbc);
                break;
            case 1:
                Build(ref input, odbc);
                break;
            default:
                Expressions(ref input);
                break;
        }
    }

    private static List<KeyValuePair<string, string>> Pairs(DbConnectionStringBuilder builder) =>
        builder.Keys.Cast<string>().Select(k => new KeyValuePair<string, string>(k, (string)builder[k])).ToList();

    private static string Show(List<KeyValuePair<string, string>> pairs) => string.Join(", ", pairs.Select(p => $"{Check.Show(p.Key)}={Check.Show(p.Value)}"));

    /// <summary>
    /// Under ODBC rules a value that needs quoting is written as {value} with '}' doubled, and parsing
    /// keeps the braces as part of the value (the Driver value is always braced); whitespace around a
    /// value isn't preserved. So ODBC values are compared without braces and surrounding whitespace.
    /// </summary>
    private static string Normalize(string value, bool odbc, bool parsed = true)
    {
        if (!odbc)
        {
            return value;
        }

        value = value.Trim();
        if (parsed && value.Length >= 2 && value[0] == '{' && value[^1] == '}')
        {
            value = value[1..^1].Replace("}}", "}").Trim();
        }

        return value;
    }

    private static void SamePairs(List<KeyValuePair<string, string>> expected, List<KeyValuePair<string, string>> actual, string what, bool odbc = false, bool raw = false)
    {
        // A key set to "" is written as "key=", which parses as no value at all: the key is dropped.
        // Parsing lower-cases keys (ToLowerInvariant, which differs from the builder's OrdinalIgnoreCase for a few characters).
        // Under ODBC rules "{}" is a value of its own (kept with its braces), so only values that are empty
        // either way are dropped.
        expected = expected.Where(e => Normalize(e.Value, odbc, !raw).Length > 0 || Normalize(e.Value, odbc, false).Length > 0).ToList();
        actual = actual.Where(a => Normalize(a.Value, odbc).Length > 0 || Normalize(a.Value, odbc, false).Length > 0).ToList();
        bool same = expected.Count == actual.Count && expected.All(e => actual.Any(a =>
            a.Key.ToLowerInvariant() == e.Key.ToLowerInvariant() && (Normalize(a.Value, odbc) == Normalize(e.Value, odbc, !raw) || Normalize(a.Value, odbc, false) == Normalize(e.Value, odbc, false))));
        Check.That(same, $"pairs [{Show(actual)}], expected [{Show(expected)}] for {what}");
    }

    private static void Parse(string text, bool odbc)
    {
        var builder = new DbConnectionStringBuilder(odbc);
        try
        {
            builder.ConnectionString = text;
        }
        catch (ArgumentException)
        {
            return;
        }

        string what = $"connection string {Check.Show(text)} (odbc {odbc})";
        List<KeyValuePair<string, string>> pairs = Pairs(builder);
        foreach (KeyValuePair<string, string> pair in pairs)
        {
            Check.That(builder.ContainsKey(pair.Key) && builder.TryGetValue(pair.Key.ToUpperInvariant(), out object v) && (string)v == pair.Value,
                $"lookup of {Check.Show(pair.Key)} for {what}");
        }

        string serialized = builder.ConnectionString;
        var again = new DbConnectionStringBuilder(odbc);
        var parsed = Outcome<bool>.Of(() => { again.ConnectionString = serialized; return true; }, e => e is ArgumentException);
        Check.That(parsed.Ok, $"serialized {Check.Show(serialized)} doesn't parse ({parsed}) for {what}");
        SamePairs(pairs, Pairs(again), $"serialized {Check.Show(serialized)} of {what}", odbc);
        if (!odbc && pairs.All(p => p.Value.Length > 0))
        {
            Check.Equal(serialized, again.ConnectionString, $"serializing again, {what}");
            Check.That(builder.EquivalentTo(again), $"EquivalentTo after round trip for {what}");
        }

    }

    private static void Build(ref FuzzInput input, bool odbc)
    {
        var builder = new DbConnectionStringBuilder(odbc);
        var appended = new StringBuilder();
        var expected = new List<KeyValuePair<string, string>>();
        var viaAppend = new List<KeyValuePair<string, string>>();
        for (int i = 0; i < 4 && input.Remaining > 0; i++)
        {
            string key = input.Segment();
            string value = input.Segment();
            // Known (DATA-ODBC-KEY-1): under ODBC rules a '=' in a key isn't escaped, so the key/value
            // boundary moves when the string is parsed again ("a=b" = "c" -> "a=b=c" -> "a" = "b=c").
            // Known (DATA-ODBC-CTRL-1): nor are keys with whitespace or values with control characters
            // quoted, which the ODBC parser then rejects; nor values where whitespace comes before a '{'
            // (" {x"), which the parser reads as the start of a braced value.
            // Known (DATA-DOLLAR-1): the key validation and value quoting regexes end in '$', which also
            // matches before a final '\n', so a key or value ending in '\n' is accepted / left unquoted
            // and parsing trims the newline off.
            if (!s_reportKnownIssues &&
                (key.EndsWith('\n') || value.EndsWith('\n') ||
                 odbc && (key.AsSpan().IndexOfAny("=;{}") >= 0 || key.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)) || value.Any(char.IsControl) ||
                  value.Length > 0 && char.IsWhiteSpace(value[0]) && value.TrimStart().StartsWith('{'))))
            {
                continue;
            }

            try
            {
                builder[key] = value;
                expected.RemoveAll(p => string.Equals(p.Key, key, StringComparison.OrdinalIgnoreCase));
                expected.Add(new(key, value));
            }
            catch (ArgumentException)
            {
            }

            int length = appended.Length;
            try
            {
                DbConnectionStringBuilder.AppendKeyValuePair(appended, key, value, odbc);
                viaAppend.RemoveAll(p => string.Equals(p.Key, key, StringComparison.OrdinalIgnoreCase));
                viaAppend.Add(new(key, value));
            }
            catch (ArgumentException)
            {
                appended.Length = length;
            }
        }

        // The builder keeps the first spelling of a key; values are what was set last.
        string what = $"pairs [{Show(expected)}] (odbc {odbc})";
        SamePairs(expected, Pairs(builder), $"indexer, {what}");
        string serialized = builder.ConnectionString;
        var parsed = new DbConnectionStringBuilder(odbc);
        var ok = Outcome<bool>.Of(() => { parsed.ConnectionString = serialized; return true; }, e => e is ArgumentException);
        Check.That(ok.Ok, $"ConnectionString {Check.Show(serialized)} doesn't parse ({ok}) for {what}");
        SamePairs(expected, Pairs(parsed), $"ConnectionString {Check.Show(serialized)} for {what}", odbc, raw: true);

        string text = appended.ToString();
        what = $"AppendKeyValuePair pairs [{Show(viaAppend)}] -> {Check.Show(text)} (odbc {odbc})";
        var fromAppend = new DbConnectionStringBuilder(odbc);
        ok = Outcome<bool>.Of(() => { fromAppend.ConnectionString = text; return true; }, e => e is ArgumentException);
        Check.That(ok.Ok, $"doesn't parse ({ok}): {what}");
        SamePairs(viaAppend, Pairs(fromAppend), what, odbc, raw: true);
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    // Expression errors are InvalidExpressionException (a DataException) or OverflowException; bad sort
    // strings and column names are ArgumentException.
    // Arithmetic (DivideByZeroException), conversions of literals (FormatException) and unknown columns
    // in a sort (IndexOutOfRangeException "Cannot find column") surface unwrapped, as they always have.
    private static bool Documented(Exception e) => e is DataException or OverflowException or DivideByZeroException or FormatException ||
        e.GetType() == typeof(ArgumentException) ||
        e is IndexOutOfRangeException && e.Message.StartsWith("Cannot find ", StringComparison.Ordinal) ||
        !s_reportKnownIssues && IsKnown(e);

    // Known (see FINDINGS-CORELIB.md): DATA-SELECT-1, Select(filter, sort) with a column repeated in the
    // sort throws IndexOutOfRangeException from Select.CreateIndex; DATA-OVERFLOW-1, an overflow in an
    // operand of AND / OR makes ExprException.Overflow throw NullReferenceException; DATA-EXPR-LEAK-1,
    // SUBSTRING arguments and Convert type names leak ArgumentOutOfRange / InvalidCast / FileLoad exceptions.
    private static bool IsKnown(Exception e)
    {
        string trace = e.StackTrace ?? "";
        return e switch
        {
            IndexOutOfRangeException => trace.Contains("Select.CreateIndex", StringComparison.Ordinal),
            NullReferenceException => trace.Contains("ExprException.Overflow", StringComparison.Ordinal),
            ArgumentOutOfRangeException or InvalidCastException => trace.Contains("FunctionNode.EvalFunction", StringComparison.Ordinal),
            System.IO.FileLoadException => true,
            _ => false,
        };
    }

    private static void Expressions(ref FuzzInput input)
    {
        string filter = input.Segment();
        string expression = input.Segment();
        string compute = input.Segment();
        string sort = input.Segment();
        if (filter.Length + expression.Length + compute.Length + sort.Length > 2048)
        {
            return;
        }

        DataSet set = NewDataSet(ref input);
        DataTable table = set.Tables["T"];
        string what = $"filter {Check.Show(filter)}, expression {Check.Show(expression)}, compute {Check.Show(compute)}, sort {Check.Show(sort)}";

        var selected = Outcome<DataRow[]>.Of(() => table.Select(filter, sort), Documented);
        var view = Outcome<DataRowView[]>.Of(() => new DataView(table, filter, sort, DataViewRowState.CurrentRows).Cast<DataRowView>().ToArray(), Documented);
        if (selected.Ok && view.Ok)
        {
            Check.That(selected.Value.Length == view.Value.Length, $"Select gave {selected.Value.Length} rows, DataView {view.Value.Length}: {what}");
            if (sort.Length == 0)
            {
                // Without a sort the order is unspecified, but the rows must be the same.
                Check.That(selected.Value.OrderBy(r => r["id"]).SequenceEqual(view.Value.Select(v => v.Row).OrderBy(r => r["id"])), $"Select and DataView rows differ: {what}");
            }
        }

        _ = Outcome<object>.Of(() => table.Compute(compute, filter), Documented);

        if (expression.Length > 0)
        {
            foreach (Type type in (Type[])[typeof(object), typeof(string), typeof(double), typeof(bool)])
            {
                var column = Outcome<DataColumn>.Of(() => new DataColumn("x", type, expression), Documented);
                if (!column.Ok)
                {
                    continue;
                }

                var added = Outcome<bool>.Of(() => { table.Columns.Add(column.Value); return true; }, Documented);
                if (added.Ok)
                {
                    foreach (DataRow row in table.Rows)
                    {
                        _ = Outcome<object>.Of(() => row["x"], Documented);
                    }

                    _ = Outcome<DataRow[]>.Of(() => table.Select("x IS NOT NULL", "x"), Documented);
                    table.Columns.Remove("x");
                }

                if (!added.Ok || type != typeof(object))
                {
                    break;
                }
            }
        }
    }

    private static DataSet NewDataSet(ref FuzzInput input)
    {
        var set = new DataSet { Locale = CultureInfo.InvariantCulture };
        DataTable t = set.Tables.Add("T");
        t.Columns.Add("id", typeof(int));
        t.Columns.Add("s", typeof(string));
        t.Columns.Add("d", typeof(double));
        t.Columns.Add("m", typeof(decimal));
        t.Columns.Add("b", typeof(bool));
        t.Columns.Add("t", typeof(DateTime));
        t.Columns.Add("ts", typeof(TimeSpan));
        t.Columns.Add("g", typeof(Guid));
        t.Columns.Add("l", typeof(long));
        DataTable c = set.Tables.Add("C");
        c.Columns.Add("id", typeof(int));
        c.Columns.Add("pid", typeof(int));
        c.Columns.Add("v", typeof(int));
        set.Relations.Add("R", t.Columns["id"], c.Columns["pid"], createConstraints: false);

        for (int i = 0; i < 4; i++)
        {
            int n = input.Int32();
            bool isNull = (n & 0xF) == 0xF;
            t.Rows.Add(i, isNull ? DBNull.Value : input.Segment(), n / 7.0, (decimal)n / 100, (n & 1) != 0,
                new DateTime(2000, 1, 1).AddSeconds((uint)n), TimeSpan.FromSeconds(n % 100000), new Guid(n, 0, 0, new byte[8]), (long)n << 20);
            c.Rows.Add(i, i % 3, n % 100);
        }

        return set;
    }
}
