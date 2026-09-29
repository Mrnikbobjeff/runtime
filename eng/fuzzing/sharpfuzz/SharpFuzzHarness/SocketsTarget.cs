#nullable disable warnings
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// The socket address layer and live loopback sockets: SocketAddress from arbitrary bytes into
/// IPEndPoint / UnixDomainSocketEndPoint (Create / Serialize round trips, sizes, equality); UDP
/// datagrams over 127.0.0.1 and ::1 with sends and receives through spans against guard pages,
/// scatter / gather buffer lists, ReceiveFrom / ReceiveMessageFrom with the kernel-provided sender
/// address and packet information, truncation; Unix domain datagram sockets bound to fuzzed paths
/// (the kernel reports the sender's path back through sockaddr_un); and raw socket options read
/// into exactly sized spans.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     operation; byte 1 flags
///   rest       data
/// </remarks>
public static unsafe class SocketsTarget
{
    private static int s_paths;
    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte op = input.Byte();
        byte flags = input.Byte();
        switch (op % 4)
        {
            case 0: Addresses(ref input, flags); break;
            case 1: Udp(ref input, flags, ipv6: false); break;
            case 2: Udp(ref input, flags, ipv6: true); break;
            default: UnixDomain(ref input, flags); break;
        }
    }

    // ------------------------------------------------------------ SocketAddress parsing

    private static void Addresses(ref FuzzInput input, byte flags)
    {
        int size = input.Byte();
        AddressFamily family = (flags & 3) switch { 0 => AddressFamily.InterNetwork, 1 => AddressFamily.InterNetworkV6, 2 => AddressFamily.Unix, _ => (AddressFamily)input.Byte() };
        string what = $"SocketAddress({family}, {size})";
        SocketAddress sa;
        try
        {
            sa = new SocketAddress(family, size);
        }
        catch (ArgumentOutOfRangeException)
        {
            Check.That(size < SocketAddress.GetMaximumAddressSize(family) || size > 2, $"{what}: rejected");
            return;
        }
        catch (PlatformNotSupportedException)
        {
            // An address family the platform doesn't map (fuzzed family byte).
            Check.That(family is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6 or AddressFamily.Unix), $"{what}: PlatformNotSupportedException");
            return;
        }

        Check.Equal(size, sa.Size, $"{what}: Size");
        Check.Equal(family, sa.Family, $"{what}: Family");
        ReadOnlySpan<byte> raw = input.Bytes(Math.Max(0, size - 2));
        raw.CopyTo(sa.Buffer.Span.Slice(2));
        Check.Equal(family, sa.Family, $"{what}: Family after writing the buffer");
        // Indexer and Buffer agree.
        for (int i = 2; i < size; i++)
        {
            Check.Equal(sa.Buffer.Span[i], sa[i], $"{what}: indexer at {i}");
        }

        // Endpoints from the bytes.
        EndPoint prototype = family switch
        {
            AddressFamily.InterNetwork => new IPEndPoint(IPAddress.Any, 0),
            AddressFamily.InterNetworkV6 => new IPEndPoint(IPAddress.IPv6Any, 0),
            AddressFamily.Unix => new UnixDomainSocketEndPoint("/tmp/x"),
            _ => null,
        };
        if (prototype is null)
        {
            return;
        }

        EndPoint ep;
        try
        {
            ep = prototype.Create(sa);
        }
        catch (Exception e) when (e is ArgumentException or ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            // Too short for the family, or the wrong family: documented ArgumentException; anything else would be a finding.
            Check.That(e is not IndexOutOfRangeException, $"{what}: Create threw IndexOutOfRangeException");
            return;
        }

        Check.Equal(family, ep.AddressFamily, $"{what}: created endpoint family");
        string text = ep.ToString();
        SocketAddress back = ep.Serialize();
        Check.Equal(family, back.Family, $"{what}: serialized family");
        EndPoint again = prototype.Create(back);
        Check.Equal(text, again.ToString(), $"{what}: Create / Serialize / Create text");
        Check.That(ep.Equals(again) && ep.GetHashCode() == again.GetHashCode(), $"{what}: endpoint equality after a round trip: {text}");
        if (ep is IPEndPoint ip)
        {
            // Port and address bytes are taken straight from the buffer.
            Check.Equal(sa[2] << 8 | sa[3], ip.Port, $"{what}: port");
            byte[] address = ip.Address.GetAddressBytes();
            Check.That(address.AsSpan().SequenceEqual(sa.Buffer.Span.Slice(family == AddressFamily.InterNetwork ? 4 : 8, address.Length)), $"{what}: address bytes");
            if (family == AddressFamily.InterNetworkV6)
            {
                // Known (SOCKADDR-SCOPE-1): Create keeps sin6_scope_id only for link-local addresses.
                uint scope = BitConverter.ToUInt32(sa.Buffer.Span.Slice(24, 4));
                if (ip.Address.IsIPv6LinkLocal || s_reportKnownIssues)
                {
                    Check.Equal(scope, (uint)ip.Address.ScopeId, $"{what}: scope id");
                }
                else
                {
                    Check.That(ip.Address.ScopeId == 0 || ip.Address.ScopeId == scope, $"{what}: scope id {ip.Address.ScopeId} is neither 0 nor {scope}");
                }

                Check.Equal(28, back.Size, $"{what}: serialized IPv6 size");
            }
            else
            {
                Check.Equal(16, back.Size, $"{what}: serialized IPv4 size");
            }

            Check.That(IPEndPoint.TryParse(text, out IPEndPoint parsed) && parsed.Equals(ip), $"{what}: ToString / TryParse round trip of {text}");
            // Guarded TryWriteBytes.
            int len = address.Length;
            Span<byte> exact = new(Guarded.Allocate(len, (flags & 4) != 0), len);
            Check.That(ip.Address.TryWriteBytes(exact, out int written) && written == len && exact.SequenceEqual(address), $"{what}: TryWriteBytes exact");
            Span<byte> shortSpan = new(Guarded.Allocate(len - 1, (flags & 4) == 0), len - 1);
            Check.That(!ip.Address.TryWriteBytes(shortSpan, out _), $"{what}: TryWriteBytes short");
        }
        else if (ep is UnixDomainSocketEndPoint uds)
        {
            Check.That(uds.ToString() is not null, $"{what}: UnixDomainSocketEndPoint text");
        }

        // A fresh UDS endpoint from fuzzed text.
        string path = Encoding.UTF8.GetString(input.Rest()).Replace("\0", "");
        try
        {
            var fresh = new UnixDomainSocketEndPoint(path);
            SocketAddress serialized = fresh.Serialize();
            Check.That(serialized.Size >= 2 && serialized.Size <= 110, $"UnixDomainSocketEndPoint({Check.Show(path)}).Serialize().Size = {serialized.Size}");
            Check.Equal(fresh.ToString(), fresh.Create(serialized).ToString(), $"UnixDomainSocketEndPoint({Check.Show(path)}) round trip");
        }
        catch (ArgumentException)
        {
            Check.That(path.Length == 0 || Encoding.UTF8.GetByteCount(path) > 107, $"UnixDomainSocketEndPoint({Check.Show(path)}) rejected a valid path");
        }
    }

    // ------------------------------------------------------------ UDP loopback

    private static readonly byte[] s_sentinel = [0xAA, 0xBB, 0xCC, 0xDD];

    private static void Udp(ref FuzzInput input, byte flags, bool ipv6)
    {
        bool atStart = (flags & 1) != 0;
        byte[] payload = input.Bytes(Math.Min(input.Remaining, 1400)).ToArray();
        IPAddress loopback = ipv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback;
        using var a = new Socket(loopback.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        using var b = new Socket(loopback.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        a.Bind(new IPEndPoint(loopback, 0));
        b.Bind(new IPEndPoint(loopback, 0));
        a.ReceiveTimeout = b.ReceiveTimeout = 5000;
        var aEnd = (IPEndPoint)a.LocalEndPoint;
        var bEnd = (IPEndPoint)b.LocalEndPoint;
        string what = $"UDP {(ipv6 ? "IPv6" : "IPv4")} {payload.Length} bytes";

        // SendTo with a SocketAddress, ReceiveFrom into a guarded span of exactly the payload size.
        SocketAddress bAddress = bEnd.Serialize();
        Check.Equal(payload.Length, a.SendTo(payload, SocketFlags.None, bAddress), $"{what}: SendTo");
        Span<byte> exact = new(Guarded.Allocate(payload.Length, atStart), payload.Length);
        var sender = new SocketAddress(loopback.AddressFamily);
        int received = b.ReceiveFrom(exact, SocketFlags.None, sender);
        Check.Equal(payload.Length, received, $"{what}: ReceiveFrom length");
        Check.That(exact.SequenceEqual(payload), $"{what}: ReceiveFrom contents");
        Check.That(sender.Equals(aEnd.Serialize()), $"{what}: sender address {sender} != {aEnd.Serialize()}");
        Check.That(aEnd.Create(sender).Equals(aEnd), $"{what}: sender endpoint {aEnd.Create(sender)} != {aEnd}");

        // Gather send from segments, scatter receive into segments with sentinels around each.
        int segments = flags % 4 + 1;
        var sendList = new List<ArraySegment<byte>>();
        int offset = 0;
        for (int i = 0; i < segments; i++)
        {
            int n = i == segments - 1 ? payload.Length - offset : payload.Length / segments;
            sendList.Add(new ArraySegment<byte>(payload, offset, n));
            offset += n;
        }

        Check.Equal(payload.Length, b.SendTo(payload, aEnd), $"{what}: SendTo endpoint");
        b.Connect(aEnd);
        Check.Equal(payload.Length, b.Send(sendList, SocketFlags.None), $"{what}: gather Send");
        var receiveList = new List<ArraySegment<byte>>();
        var backing = new List<byte[]>();
        int capacity = 0;
        for (int i = 0; i < segments; i++)
        {
            int n = (flags >> 2) % 3 == 0 ? payload.Length / segments : input.Byte() % 700;
            byte[] buffer = new byte[n + 8];
            s_sentinel.CopyTo(buffer, 0);
            s_sentinel.CopyTo(buffer, n + 4);
            backing.Add(buffer);
            receiveList.Add(new ArraySegment<byte>(buffer, 4, n));
            capacity += n;
        }

        // First the datagram sent with SendTo(endpoint), whole, then the gathered one, possibly truncated.
        byte[] first = new byte[Math.Max(payload.Length, 1)];
        Check.Equal(payload.Length, a.Receive(first), $"{what}: Receive first datagram");
        Check.That(first.AsSpan(0, payload.Length).SequenceEqual(payload), $"{what}: first datagram contents");
        int expected = Math.Min(capacity, payload.Length);
        int scattered;
        try
        {
            scattered = a.Receive(receiveList, SocketFlags.None);
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.MessageSize)
        {
            Check.That(capacity < payload.Length, $"{what}: MessageSize with capacity {capacity}");
            scattered = -1;
        }

        if (scattered >= 0)
        {
            Check.Equal(expected, scattered, $"{what}: scatter Receive into {capacity} bytes");
            int taken = 0;
            foreach (byte[] buffer in backing)
            {
                int n = buffer.Length - 8;
                int used = Math.Min(n, Math.Max(0, expected - taken));
                Check.That(buffer.AsSpan(4, used).SequenceEqual(payload.AsSpan(taken, used)), $"{what}: scatter segment contents");
                Check.That(buffer.AsSpan(0, 4).SequenceEqual(s_sentinel) && buffer.AsSpan(n + 4, 4).SequenceEqual(s_sentinel), $"{what}: scatter Receive wrote outside its segment");
                taken += used;
            }
        }

        // ReceiveMessageFrom with packet information, and truncation flagged.
        b.SetSocketOption(ipv6 ? SocketOptionLevel.IPv6 : SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
        Check.Equal(payload.Length, a.SendTo(payload, bEnd), $"{what}: SendTo for ReceiveMessageFrom");
        int room = payload.Length == 0 ? 0 : payload.Length - (flags >> 4) % Math.Max(1, payload.Length);
        Span<byte> partial = new(Guarded.Allocate(room, !atStart), room);
        SocketFlags msgFlags = SocketFlags.None;
        EndPoint from = new IPEndPoint(loopback.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
        int got = b.ReceiveMessageFrom(partial, ref msgFlags, ref from, out IPPacketInformation packetInfo);
        Check.Equal(room, got, $"{what}: ReceiveMessageFrom into {room} bytes");
        Check.That(partial.SequenceEqual(payload.AsSpan(0, room)), $"{what}: ReceiveMessageFrom contents");
        Check.Equal(room < payload.Length, (msgFlags & SocketFlags.Truncated) != 0, $"{what}: Truncated flag for {room} of {payload.Length}");
        Check.That(((IPEndPoint)from).Equals(aEnd), $"{what}: ReceiveMessageFrom sender {from} != {aEnd}");
        Check.That(packetInfo.Address.Equals(loopback), $"{what}: packet information address {packetInfo.Address}");
        Check.Equal(0, a.Available, $"{what}: nothing left on a");
        Check.Equal(0, b.Available, $"{what}: nothing left on b");
        Check.That(!a.Poll(0, SelectMode.SelectRead), $"{what}: Poll on an empty socket");

        // Raw socket options into exactly sized spans.
        Span<byte> option = new(Guarded.Allocate(4, atStart), 4);
        int optLen = a.GetRawSocketOption(1 /* SOL_SOCKET */, 8 /* SO_RCVBUF */, option);
        Check.Equal(4, optLen, $"{what}: SO_RCVBUF length");
        Check.That(BitConverter.ToInt32(option) > 0, $"{what}: SO_RCVBUF value");
        Span<byte> two = new(Guarded.Allocate(2, !atStart), 2);
        int shortLen = a.GetRawSocketOption(1, 8, two);
        Check.That(shortLen <= 2, $"{what}: SO_RCVBUF into 2 bytes returned {shortLen}");
        Check.Equal(a.ReceiveBufferSize, BitConverter.ToInt32(option), $"{what}: ReceiveBufferSize vs raw option");
    }

    // ------------------------------------------------------------ Unix domain datagram sockets

    private static void UnixDomain(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        bool abstractName = (flags & 2) != 0;
        byte[] nameBytes = input.SegmentBytes().ToArray();
        // A file system path under /dev/shm (no slashes or NULs in the name, at most 60 bytes), or an abstract name.
        string name = Encoding.UTF8.GetString(nameBytes).Replace("/", "").Replace("\0", "").Replace("�", "");
        name = name.Length > 40 ? name.Substring(0, 40) : name;
        if (name.Length > 0 && char.IsHighSurrogate(name[^1]))
        {
            name = name.Substring(0, name.Length - 1);
        }

        name = name.Replace("\uFFFD", "");
        string pathA = abstractName ? "\0sf-" + name + s_paths++ : $"/dev/shm/sf-{Environment.ProcessId}-{s_paths++}-{name}";
        string pathB = abstractName ? "\0sf-" + name + s_paths++ : $"/dev/shm/sf-{Environment.ProcessId}-{s_paths++}";
        byte[] payload = input.Bytes(Math.Min(input.Remaining, 1000)).ToArray();
        string what = $"UDS {(abstractName ? "abstract" : "path")} {Check.Show(pathA)} {payload.Length} bytes";
        UnixDomainSocketEndPoint endA, endB;
        try
        {
            endA = new UnixDomainSocketEndPoint(pathA);
            endB = new UnixDomainSocketEndPoint(pathB);
        }
        catch (ArgumentOutOfRangeException)
        {
            Check.That(Encoding.UTF8.GetByteCount(pathA) > 100, $"{what}: path rejected");
            return;
        }

        using var a = new Socket(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified);
        using var b = new Socket(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified);
        try
        {
            a.Bind(endA);
            b.Bind(endB);
            a.ReceiveTimeout = b.ReceiveTimeout = 5000;
            Check.Equal(!abstractName, File.Exists(pathA), $"{what}: socket file exists");
            Check.Equal(endA.ToString(), a.LocalEndPoint.ToString(), $"{what}: LocalEndPoint");
            Check.Equal(payload.Length, a.SendTo(payload, endB), $"{what}: SendTo");
            Span<byte> exact = new(Guarded.Allocate(payload.Length, atStart), payload.Length);
            EndPoint sender = new UnixDomainSocketEndPoint("/tmp/placeholder");
            int received = b.ReceiveFrom(exact, ref sender);
            Check.Equal(payload.Length, received, $"{what}: ReceiveFrom length");
            Check.That(exact.SequenceEqual(payload), $"{what}: ReceiveFrom contents");
            Check.Equal(endA.ToString(), sender.ToString(), $"{what}: sender path reported by the kernel");
            // And the other way with a SocketAddress.
            Check.Equal(payload.Length, b.SendTo(payload, SocketFlags.None, endA.Serialize()), $"{what}: SendTo(SocketAddress)");
            var senderAddress = new SocketAddress(AddressFamily.Unix);
            Span<byte> exact2 = new(Guarded.Allocate(payload.Length, !atStart), payload.Length);
            Check.Equal(payload.Length, a.ReceiveFrom(exact2, SocketFlags.None, senderAddress), $"{what}: ReceiveFrom(SocketAddress) length");
            Check.That(exact2.SequenceEqual(payload), $"{what}: ReceiveFrom(SocketAddress) contents");
            Check.Equal(endB.ToString(), endB.Create(senderAddress).ToString(), $"{what}: sender SocketAddress -> endpoint");
        }
        catch (SocketException e) when (e.SocketErrorCode == SocketError.AddressAlreadyInUse && !abstractName)
        {
            // A leftover file from a killed process; nothing to check.
        }
        finally
        {
            if (!abstractName)
            {
                File.Delete(pathA);
                File.Delete(pathB);
            }
        }
    }
}
