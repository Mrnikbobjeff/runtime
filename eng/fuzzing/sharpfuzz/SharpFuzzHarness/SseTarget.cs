#nullable disable warnings
using System.Net.ServerSentEvents;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Net.ServerSentEvents: SseParser against a reference parser, and SseFormatter round trips.</summary>
/// <remarks>
/// Input layout:
///   byte 0     0x01 enumerate asynchronously; 0x02 use SseParser.Create(stream) (string items);
///              0x04 also format the segments of the stream as items and parse them back
///   byte 1     read-size pattern of the stream the parser reads from
///   rest       the event stream
/// Checks: the items (data, type, id, retry), LastEventId and ReconnectionInterval match a direct
/// implementation of the WHATWG event stream parsing algorithm, however the stream is split into
/// reads; items written by SseFormatter parse back to the same items.
/// </remarks>
public static class SseTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte flags = input.Byte();
        byte pattern = input.Byte();
        byte[] stream = input.Rest().ToArray();
        string what = $"event stream 0x{Convert.ToHexString(stream.AsSpan(0, Math.Min(stream.Length, 96)))}{(stream.Length > 96 ? "..." : "")} (flags 0x{flags:X2}, reads 0x{pattern:X2})";

        List<Item> expected = Reference(stream, out string lastEventId, out TimeSpan reconnection);
        List<Item> actual = Parse(new ChunkedStream(stream, pattern), (flags & 1) != 0, (flags & 2) != 0, out string actualLastId, out TimeSpan actualReconnection);
        Compare(expected, actual, (flags & 2) != 0, what);
        Check.Equal(lastEventId, actualLastId, $"LastEventId for {what}");
        Check.Equal(reconnection, actualReconnection, $"ReconnectionInterval for {what}");

        if ((flags & 4) != 0)
        {
            RoundTrip(stream, (flags & 1) != 0);
        }
    }

    private readonly record struct Item(string Type, byte[] Data, string Id, TimeSpan? Retry);

    private static List<Item> Parse(Stream stream, bool async, bool strings, out string lastEventId, out TimeSpan reconnection)
    {
        var items = new List<Item>();
        if (strings)
        {
            SseParser<string> parser = SseParser.Create(stream);
            foreach (SseItem<string> item in Enumerate(parser.Enumerate, parser.EnumerateAsync, async))
            {
                items.Add(new Item(item.EventType, Encoding.UTF8.GetBytes(item.Data), item.EventId, item.ReconnectionInterval));
            }

            lastEventId = parser.LastEventId;
            reconnection = parser.ReconnectionInterval;
        }
        else
        {
            string typeSeen = null;
            SseParser<byte[]> parser = SseParser.Create(stream, (type, bytes) =>
            {
                typeSeen = type;
                return bytes.ToArray();
            });
            foreach (SseItem<byte[]> item in Enumerate(parser.Enumerate, parser.EnumerateAsync, async))
            {
                Check.Equal(item.EventType, typeSeen, "event type passed to the item parser vs SseItem.EventType");
                items.Add(new Item(item.EventType, item.Data, item.EventId, item.ReconnectionInterval));
            }

            lastEventId = parser.LastEventId;
            reconnection = parser.ReconnectionInterval;
        }

        return items;
    }

    private static IEnumerable<T> Enumerate<T>(Func<IEnumerable<T>> sync, Func<CancellationToken, IAsyncEnumerable<T>> async, bool useAsync)
    {
        if (!useAsync)
        {
            foreach (T item in sync())
            {
                yield return item;
            }

            yield break;
        }

        IAsyncEnumerator<T> e = async(default).GetAsyncEnumerator();
        try
        {
            while (e.MoveNextAsync().AsTask().GetAwaiter().GetResult())
            {
                yield return e.Current;
            }
        }
        finally
        {
            e.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }

    private static void Compare(List<Item> expected, List<Item> actual, bool strings, string what)
    {
        Check.That(expected.Count == actual.Count, $"{actual.Count} items, expected {expected.Count} ({Describe(expected)} vs {Describe(actual)}) for {what}");
        for (int i = 0; i < expected.Count; i++)
        {
            Item e = expected[i], a = actual[i];
            byte[] data = strings ? Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(e.Data)) : e.Data;
            Check.That(data.AsSpan().SequenceEqual(a.Data), $"item {i} data {Check.Show(a.Data)}, expected {Check.Show(data)} for {what}");
            Check.Equal(e.Type, a.Type, $"item {i} EventType for {what}");
            Check.Equal(e.Id, a.Id, $"item {i} EventId for {what}");
            Check.Equal(e.Retry, a.Retry, $"item {i} ReconnectionInterval for {what}");
        }
    }

    private static string Describe(List<Item> items) => string.Join(", ", items.Select(i => $"[{Check.Show(i.Type)} {Check.Show(i.Data)} id {Check.Show(i.Id)} retry {i.Retry}]"));

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    /// <summary>
    /// The WHATWG "interpreting an event stream" algorithm. EventId and ReconnectionInterval are the
    /// per-event values SseItem reports (the event's own id / retry fields), which the spec has no
    /// notion of; they're reset when an event is dispatched.
    /// </summary>
    private static List<Item> Reference(byte[] stream, out string lastEventId, out TimeSpan reconnection)
    {
        var items = new List<Item>();
        lastEventId = "";
        reconnection = Timeout.InfiniteTimeSpan;
        string eventType = null;
        var dataBuffer = new List<byte>();
        bool dataAppended = false;
        string eventId = null;
        TimeSpan? retry = null;

        int pos = stream.AsSpan().StartsWith("﻿"u8) ? 3 : 0;
        while (true)
        {
            int nl = stream.AsSpan(pos).IndexOfAny((byte)'\r', (byte)'\n');
            if (nl < 0)
            {
                break; // an unterminated last line is discarded along with any pending event
            }

            ReadOnlySpan<byte> line = stream.AsSpan(pos, nl);
            pos += nl + (stream[pos + nl] == '\r' && pos + nl + 1 < stream.Length && stream[pos + nl + 1] == '\n' ? 2 : 1);

            if (line.IsEmpty)
            {
                // Dispatch: nothing is dispatched without data, but the event type buffer is reset either way.
                // Known (SSE-TYPE-1): SseParser reports an empty "event:" field as type "" rather than "message",
                // and (SSE-TYPE-2) keeps the event type of a blank line without data for the next event.
                if (dataAppended)
                {
                    items.Add(new Item(eventType is null || (s_reportKnownIssues && eventType.Length == 0) ? SseParser.EventTypeDefault : eventType, dataBuffer.ToArray(), eventId, retry));
                    eventId = null;
                    retry = null;
                    eventType = null;
                }

                if (s_reportKnownIssues)
                {
                    eventType = null;
                }

                dataBuffer.Clear();
                dataAppended = false;
                continue;
            }

            int colon = line.IndexOf((byte)':');
            ReadOnlySpan<byte> field = colon < 0 ? line : line.Slice(0, colon);
            ReadOnlySpan<byte> value = colon < 0 ? default : line.Slice(colon + 1);
            if (!value.IsEmpty && value[0] == ' ')
            {
                value = value.Slice(1);
            }

            if (field.SequenceEqual("event"u8))
            {
                eventType = Encoding.UTF8.GetString(value);
            }
            else if (field.SequenceEqual("data"u8))
            {
                if (dataAppended)
                {
                    dataBuffer.Add((byte)'\n');
                }

                dataBuffer.AddRange(value.ToArray());
                dataAppended = true;
            }
            else if (field.SequenceEqual("id"u8))
            {
                if (!value.Contains((byte)0))
                {
                    lastEventId = eventId = Encoding.UTF8.GetString(value);
                }
            }
            else if (field.SequenceEqual("retry"u8))
            {
                // Known (SSE-RETRY-1): the value is parsed with long.TryParse, which ignores trailing U+0000,
                // so "retry: 5<NUL>" sets 5 ms although the field isn't all digits.
                if (!s_reportKnownIssues)
                {
                    value = value.TrimEnd((byte)0);
                }

                if (!value.IsEmpty && !value.ContainsAnyExceptInRange((byte)'0', (byte)'9'))
                {
                    // Values beyond TimeSpan's range can't be represented and are ignored.
                    System.Numerics.BigInteger ms = System.Numerics.BigInteger.Parse(Encoding.ASCII.GetString(value));
                    if (ms <= (long)(TimeSpan.MaxValue.Ticks / TimeSpan.TicksPerMillisecond))
                    {
                        long v = (long)ms;
                        retry = v == TimeSpan.MaxValue.Ticks / TimeSpan.TicksPerMillisecond ? TimeSpan.MaxValue : TimeSpan.FromMilliseconds(v);
                        reconnection = retry.Value;
                    }
                }
            }
        }

        return items;
    }

    /// <summary>Formats items taken from the input with SseFormatter and parses them back.</summary>
    private static void RoundTrip(byte[] stream, bool async)
    {
        var source = new List<SseItem<string>>();
        var input = new FuzzInput(stream);
        while (input.Remaining > 0 && source.Count < 8)
        {
            byte kind = input.Byte();
            string data = input.Segment();
            string type = (kind & 1) != 0 ? input.Segment() : null;
            string id = (kind & 2) != 0 ? input.Segment().Replace((char)1, (char)0) : null;
            TimeSpan? retry = (kind & 4) != 0 ? TimeSpan.FromTicks((long)((ulong)(uint)input.Int32() * (ulong)input.Int32() & long.MaxValue)) : null;
            try
            {
                source.Add(new SseItem<string>(data, type) { EventId = id, ReconnectionInterval = retry });
            }
            catch (ArgumentException) when (HasLineBreak(type) || HasLineBreak(id))
            {
            }
        }

        var destination = new MemoryStream();
        SseFormatter.WriteAsync(ToAsync(source), destination).GetAwaiter().GetResult();
        byte[] formatted = destination.ToArray();
        string what = $"SseFormatter output {Check.Show(Encoding.UTF8.GetString(formatted))}";

        List<Item> parsed = Parse(new MemoryStream(formatted), async, strings: true, out _, out _);
        Check.That(parsed.Count == source.Count, $"{parsed.Count} items parsed back from {source.Count} formatted: {what}");
        for (int i = 0; i < source.Count; i++)
        {
            SseItem<string> s = source[i];
            Item p = parsed[i];
            // Line breaks in the data become LF; strings are written as UTF-8 (lone surrogates become U+FFFD).
            string data = Utf8RoundTrip(s.Data).Replace("\r\n", "\n").Replace('\r', '\n');
            Check.Equal(data, Encoding.UTF8.GetString(p.Data), $"item {i} data: {what}");
            Check.Equal(Utf8RoundTrip(s.EventType), p.Type, $"item {i} EventType: {what}");

            // Known (SSE-FORMAT-1): SseItem.EventId accepts U+0000 but the parser ignores an id field that contains it.
            if (s_reportKnownIssues || s.EventId?.Contains('\0') != true)
            {
                Check.Equal(Utf8RoundTrip(s.EventId), p.Id, $"item {i} EventId: {what}");
            }

            // retry is written in whole milliseconds (via TimeSpan.TotalMilliseconds, a double).
            if (s.ReconnectionInterval is TimeSpan r)
            {
                Check.That(p.Retry is TimeSpan pr && Math.Abs(pr.Ticks / TimeSpan.TicksPerMillisecond - r.Ticks / TimeSpan.TicksPerMillisecond) <= 1,
                    $"item {i} ReconnectionInterval {p.Retry}, expected {r}: {what}");
            }
            else
            {
                Check.Equal(null, p.Retry, $"item {i} ReconnectionInterval: {what}");
            }
        }
    }

    private static bool HasLineBreak(string s) => s is not null && s.AsSpan().IndexOfAny('\r', '\n') >= 0;

    private static string Utf8RoundTrip(string s) => s is null ? null : Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(s));

    private static async IAsyncEnumerable<SseItem<string>> ToAsync(List<SseItem<string>> items)
    {
        foreach (SseItem<string> item in items)
        {
            yield return item;
        }

        await Task.CompletedTask;
    }

    /// <summary>A read-only stream that returns at most a few bytes per read, in a pattern taken from the input.</summary>
    private sealed class ChunkedStream(byte[] data, byte pattern) : Stream
    {
        private int _position;
        private int _reads;

        private int NextSize()
        {
            int shift = _reads++ % 4 * 2;
            return (pattern >> shift & 3) switch
            {
                0 => 1,
                1 => 2 + (_reads & 3),
                2 => 7 + pattern % 13,
                _ => 4096,
            };
        }

        public override int Read(Span<byte> buffer)
        {
            int n = Math.Min(Math.Min(buffer.Length, NextSize()), data.Length - _position);
            data.AsSpan(_position, n).CopyTo(buffer);
            _position += n;
            return n;
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => new(Read(buffer.Span));

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => Task.FromResult(Read(buffer, offset, count));

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
