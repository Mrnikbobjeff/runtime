#nullable disable warnings
using System.IO.Pipes;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// System.IO.Pipes over the Unix implementation (pipe(2) for anonymous pipes with handle strings passed
/// between the two ends, Unix domain sockets for named pipes with fuzzed names): connect / disconnect
/// cycles, reads and writes through spans against guard pages, ReadMode / TransmissionMode, partial
/// reads, IsConnected, handle inheritability, and the client handle string parsing. Every byte written
/// must come out in order.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     kind (anonymous / named); byte 1 flags; then a name segment (named pipes), then chunks
/// </remarks>
public static unsafe class PipesTarget
{
    private static int s_names;
    private static readonly bool s_trace = Environment.GetEnvironmentVariable("SHARPFUZZ_TRACE") is not null;
    private static void Trace(string step) { if (s_trace) Console.WriteLine($"  [pipes] {step}"); }

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte kind = input.Byte();
        byte flags = input.Byte();
        if ((kind & 1) == 0)
        {
            Anonymous(ref input, flags);
        }
        else
        {
            Named(ref input, flags);
        }
    }

    private static void Anonymous(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        var direction = (flags & 2) != 0 ? PipeDirection.In : PipeDirection.Out;
        var inheritability = (flags & 4) != 0 ? HandleInheritability.Inheritable : HandleInheritability.None;
        using var server = new AnonymousPipeServerStream(direction, inheritability, (flags >> 3) * 512);
        string handle = server.GetClientHandleAsString();
        Check.That(int.TryParse(handle, out int fd) && fd >= 0, $"client handle string {Check.Show(handle)}");
        using var client = new AnonymousPipeClientStream(direction == PipeDirection.In ? PipeDirection.Out : PipeDirection.In, handle);
        // (DisposeLocalCopyOfClientHandle is for a parent that handed the descriptor to a child process; here it would close the client's descriptor.)
        Check.Equal(PipeTransmissionMode.Byte, server.TransmissionMode, "anonymous TransmissionMode");
        Check.That(server.IsConnected && client.IsConnected, "anonymous pipe not connected");
        Check.That(!server.CanSeek && !client.CanSeek, "anonymous pipe CanSeek");
        PipeStream writer = direction == PipeDirection.Out ? server : client;
        PipeStream reader = direction == PipeDirection.Out ? client : server;
        Check.That(writer.CanWrite && !writer.CanRead && reader.CanRead && !reader.CanWrite, "anonymous pipe directions");
        Transfer(writer, reader, ref input, atStart, "anonymous");
        writer.Dispose();
        Check.Equal(0, reader.Read(new byte[8]), "anonymous pipe EOF after the writer closed");
        // (A handle string is an OS descriptor the client takes ownership of, so no garbage strings: they'd close a live descriptor.)
    }

    private static void Named(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        string raw = Encoding.UTF8.GetString(input.SegmentBytes()).Replace("\0", "").Replace("�", "");
        string name = (raw.Length > 60 ? raw.Substring(0, 60) : raw) + "-" + Environment.ProcessId + "-" + s_names++;
        if (name.Length == 0 || name.Contains('/'))
        {
            name = "sf" + name.Replace("/", "_");
        }

        var options = (flags & 2) != 0 ? PipeOptions.Asynchronous : PipeOptions.None;
        string what = $"named pipe {Check.Show(name)} options {options}";
        NamedPipeServerStream server;
        try
        {
            server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, options, (flags >> 4) * 256, (flags >> 4) * 256);
        }
        catch (Exception e) when (e is ArgumentException or IOException or PathTooLongException or PlatformNotSupportedException)
        {
            // Names map to a socket path under the temp directory; long or odd names may not fit sockaddr_un.
            return;
        }

        using (server)
        {
            using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, options);
            Trace($"server created for {Check.Show(name)}");
            Task wait = server.WaitForConnectionAsync();
            client.Connect(10000);
            Trace("client connected");
            wait.GetAwaiter().GetResult();
            Trace("server accepted");
            Check.That(server.IsConnected && client.IsConnected, $"{what}: not connected");
            Check.Equal(PipeTransmissionMode.Byte, server.TransmissionMode, $"{what}: TransmissionMode");
            Check.Equal(PipeTransmissionMode.Byte, client.ReadMode, $"{what}: client ReadMode");
            try
            {
                client.ReadMode = PipeTransmissionMode.Message;
                Check.That(false, $"{what}: Message read mode accepted on Unix");
            }
            catch (Exception e) when (e is PlatformNotSupportedException or IOException or ArgumentOutOfRangeException)
            {
            }

            Check.That(server.CanRead && server.CanWrite && client.CanRead && client.CanWrite, $"{what}: InOut capabilities");
            Transfer(client, server, ref input, atStart, what + " client->server");
            Transfer(server, client, ref input, !atStart, what + " server->client");
            // Disconnect, then a second client on the same server.
            Trace("transfers done");
            server.Disconnect();
            Check.That(!server.IsConnected, $"{what}: still connected after Disconnect");
            using var second = new NamedPipeClientStream(".", name, PipeDirection.InOut, options);
            Task wait2 = server.WaitForConnectionAsync();
            second.Connect(10000);
            Trace("second connected");
            wait2.GetAwaiter().GetResult();
            Trace("second accepted");
            Check.That(server.IsConnected, $"{what}: second connection");
            Transfer(second, server, ref input, atStart, what + " second client");
            second.Dispose();
            Check.Equal(0, server.Read(new byte[4]), $"{what}: EOF after the client closed");
        }

        Trace("named done");
        // A client for a pipe that doesn't exist fails with a timeout, never a crash.
        using var orphan = new NamedPipeClientStream(".", name + "-none", PipeDirection.In);
        try
        {
            orphan.Connect(1);
            Check.That(false, $"{what}: connected to a pipe that doesn't exist");
        }
        catch (Exception e) when (e is TimeoutException or IOException)
        {
        }
    }

    private static void Transfer(PipeStream writer, PipeStream reader, ref FuzzInput input, bool atStart, string what)
    {
        var pending = new Queue<byte>();
        for (int step = 0; step < 12 && input.Remaining > 0; step++)
        {
            int kind = input.Byte() % 4;
            int length = input.UInt16() % 3000;
            switch (kind)
            {
                case 0:
                {
                    byte[] payload = new byte[length];
                    ReadOnlySpan<byte> pattern = input.Bytes(Math.Min(length, 16));
                    for (int i = 0; i < length; i++)
                    {
                        payload[i] = pattern.Length == 0 ? (byte)i : pattern[i % pattern.Length];
                    }

                    writer.Write(payload);
                    writer.Flush();
                    foreach (byte b in payload)
                    {
                        pending.Enqueue(b);
                    }

                    break;
                }
                case 1 when pending.Count > 0:
                {
                    int n = Math.Min(Math.Max(1, length), pending.Count);
                    Span<byte> dest = new(Guarded.Allocate(n, atStart), n);
                    int read = reader.Read(dest);
                    Check.That(read > 0 && read <= n, $"{what}: Read returned {read} of {n}");
                    for (int i = 0; i < read; i++)
                    {
                        Check.Equal(pending.Dequeue(), dest[i], $"{what}: byte {i} of {read}");
                    }

                    break;
                }
                case 2 when pending.Count > 0:
                {
                    int n = Math.Min(Math.Max(1, length), pending.Count);
                    byte[] dest = new byte[n];
                    reader.ReadExactly(dest);
                    for (int i = 0; i < n; i++)
                    {
                        Check.Equal(pending.Dequeue(), dest[i], $"{what}: ReadExactly byte {i}");
                    }

                    break;
                }
                case 3 when pending.Count > 0:
                {
                    Memory<byte> dest = Guarded.CopyMemory<byte>(new byte[Math.Min(Math.Max(1, length), pending.Count)], atStart);
                    int read = reader.ReadAsync(dest).AsTask().GetAwaiter().GetResult();
                    Check.That(read > 0 && read <= dest.Length, $"{what}: ReadAsync returned {read}");
                    for (int i = 0; i < read; i++)
                    {
                        Check.Equal(pending.Dequeue(), dest.Span[i], $"{what}: ReadAsync byte {i}");
                    }

                    break;
                }
            }
        }

        byte[] rest = new byte[pending.Count];
        reader.ReadExactly(rest);
        Check.That(rest.SequenceEqual(pending), $"{what}: drained bytes differ");
    }
}
