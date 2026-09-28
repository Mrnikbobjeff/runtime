#nullable disable warnings
using System.Net.WebSockets;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// The managed WebSocket (WebSocket.CreateFromStream) receiving fuzzed frames: header parsing, payload
/// unmasking (vectorized XOR through Unsafe, straight into the caller's buffer), fragmentation, control
/// frames, UTF-8 validation of text messages and per-message deflate. Receive buffers are guarded
/// Memory of assorted sizes (see <see cref="Guarded"/>). For uncompressed input, a simple frame decoder
/// is the model: the data messages received must match its unmasked payloads, and malformed frames may
/// only end in WebSocketException / a Close.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     options (bit 0 server role, bit 1 per-message deflate); byte 1 receive buffer sizes
///   rest       the frames as they arrive on the stream
/// </remarks>
public static class WebSocketTarget
{
    /// <summary>A stream that reads the fuzz data (a few bytes at a time) and discards what the socket writes.</summary>
    private sealed class FrameStream(byte[] data, byte pattern) : Stream
    {
        private int _position, _reads;

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            int n = Math.Min(buffer.Length, Math.Min(data.Length - _position, 1 + (pattern >> (_reads++ % 4 * 2) & 3) * 7));
            data.AsSpan(_position, n).CopyTo(buffer);
            _position += n;
            return n;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => new(Read(buffer.Span));
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => Task.FromResult(Read(buffer, offset, count));
        public override void Write(byte[] buffer, int offset, int count) { }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => default;
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => Task.CompletedTask;
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte options = input.Byte();
        byte sizes = input.Byte();
        byte[] frames = input.Rest().ToArray();
        if (frames.Length > 1 << 16)
        {
            return;
        }

        bool server = (options & 1) != 0, deflate = (options & 2) != 0;
        string what = $"{(server ? "server" : "client")}{(deflate ? " deflate" : "")} sizes {sizes:X2}, {frames.Length} bytes 0x{Convert.ToHexString(frames.AsSpan(0, Math.Min(frames.Length, 48)))}";
        var wsOptions = new WebSocketCreationOptions
        {
            IsServer = server,
            KeepAliveInterval = TimeSpan.Zero,
            DangerousDeflateOptions = deflate ? new WebSocketDeflateOptions { ClientMaxWindowBits = 9 + (sizes & 7) % 7, ServerMaxWindowBits = 9 + (sizes >> 3 & 7) % 7 } : null,
        };
        using WebSocket socket = WebSocket.CreateFromStream(new FrameStream(frames, (byte)(sizes ^ options)), wsOptions);
        var received = new List<(WebSocketMessageType Type, byte[] Data)>();
        var message = new List<byte>();
        string failure = null;
        int k = 0;
        try
        {
            while (received.Count < 64 && socket.State == WebSocketState.Open)
            {
                int size = 1 + (sizes >> (k++ % 4 * 2) & 3) * 11;
                Memory<byte> buffer = Guarded.CopyMemory<byte>(new byte[size], (k & 1) != 0);
                ValueWebSocketReceiveResult result = socket.ReceiveAsync(buffer, default).AsTask().GetAwaiter().GetResult();
                Check.That(result.Count >= 0 && result.Count <= size, $"ReceiveAsync reported {result.Count} bytes into {size}: {what}");
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    break;
                }

                message.AddRange(buffer.Span[..result.Count].ToArray());
                if (result.EndOfMessage)
                {
                    received.Add((result.MessageType, message.ToArray()));
                    message.Clear();
                }
            }
        }
        catch (WebSocketException e)
        {
            failure = e.WebSocketErrorCode.ToString();
        }
        catch (Exception e) when (e is IOException or OperationCanceledException)
        {
            failure = e.GetType().Name;
        }

        if (deflate)
        {
            return; // no model for compressed payloads; the checks above (no crash, counts in range) still apply
        }

        List<(WebSocketMessageType, byte[])> model = Model(frames, server, out string modelFailure);
        // Everything the socket delivered must be a prefix of what the model decodes (it may stop early on
        // an error the model doesn't check, e.g. an invalid close code), and each message must be the model's.
        for (int i = 0; i < received.Count; i++)
        {
            Check.That(i < model.Count && received[i].Type == model[i].Item1 && received[i].Data.AsSpan().SequenceEqual(model[i].Item2),
                $"message {i} ({received[i].Type}, {received[i].Data.Length} bytes 0x{Convert.ToHexString(received[i].Data.AsSpan(0, Math.Min(32, received[i].Data.Length)))}) differs from the model's {(i < model.Count ? $"({model[i].Item1}, {model[i].Item2.Length} bytes)" : "(none)")}; socket failure {failure}, model {modelFailure}: {what}");
        }

        if (failure is null && modelFailure is null && received.Count < 64)
        {
            Check.Equal(model.Count, received.Count, $"messages received vs model (socket state {socket.State}): {what}");
        }
    }

    /// <summary>A minimal RFC 6455 decoder: data messages (text / binary) with their unmasked payloads, until a close or an error.</summary>
    private static List<(WebSocketMessageType, byte[])> Model(byte[] frames, bool server, out string failure)
    {
        var messages = new List<(WebSocketMessageType, byte[])>();
        var current = new List<byte>();
        WebSocketMessageType? type = null;
        int p = 0;
        failure = null;
        while (true)
        {
            if (frames.Length - p < 2)
            {
                failure = "eof";
                return messages;
            }

            byte b0 = frames[p], b1 = frames[p + 1];
            bool fin = (b0 & 0x80) != 0, masked = (b1 & 0x80) != 0;
            int opcode = b0 & 0x0F;
            if ((b0 & 0x70) != 0 || masked != server)
            {
                failure = "header";
                return messages;
            }

            long length = b1 & 0x7F;
            p += 2;
            if (length == 126)
            {
                if (frames.Length - p < 2) { failure = "eof"; return messages; }
                length = frames[p] << 8 | frames[p + 1];
                p += 2;
            }
            else if (length == 127)
            {
                if (frames.Length - p < 8) { failure = "eof"; return messages; }
                length = (long)System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(frames.AsSpan(p));
                p += 8;
                if (length < 0) { failure = "length"; return messages; }
            }

            byte[] mask = null;
            if (masked)
            {
                if (frames.Length - p < 4) { failure = "eof"; return messages; }
                mask = frames.AsSpan(p, 4).ToArray();
                p += 4;
            }

            if (length > frames.Length - p)
            {
                failure = "eof";
                return messages;
            }

            byte[] payload = frames.AsSpan(p, (int)length).ToArray();
            p += (int)length;
            for (int i = 0; mask is not null && i < payload.Length; i++)
            {
                payload[i] ^= mask[i & 3];
            }

            if (opcode >= 8)
            {
                if (!fin || length > 125 || opcode > 10) { failure = "control"; return messages; }
                if (opcode == 8) { failure = "close"; return messages; }
                continue; // ping / pong
            }

            if (opcode is 1 or 2)
            {
                if (type is not null) { failure = "continuation expected"; return messages; }
                type = opcode == 1 ? WebSocketMessageType.Text : WebSocketMessageType.Binary;
            }
            else if (opcode == 0)
            {
                if (type is null) { failure = "unexpected continuation"; return messages; }
            }
            else
            {
                failure = "opcode";
                return messages;
            }

            current.AddRange(payload);
            if (fin)
            {
                // Known (WS-UTF8-1): when the final fragment of a text message is empty, the socket skips the
                // end-of-message UTF-8 check and delivers the message even if it's invalid.
                bool skipCheck = !s_reportKnownIssues && opcode == 0 && length == 0;
                if (type == WebSocketMessageType.Text && !skipCheck && !System.Text.Unicode.Utf8.IsValid(current.ToArray()))
                {
                    failure = "utf8";
                    return messages;
                }

                messages.Add((type.Value, current.ToArray()));
                current.Clear();
                type = null;
            }
        }
    }
}
