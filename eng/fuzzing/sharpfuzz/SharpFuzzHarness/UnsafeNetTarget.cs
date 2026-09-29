#nullable disable warnings
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// System.Net parsing / formatting over spans that sit against a guard page (see <see cref="Guarded"/>):
/// IPAddress (char and UTF-8 parsers, TryFormat, TryWriteBytes, the span constructor), IPNetwork,
/// IPEndPoint, PhysicalAddress and the span Uri.TryEscapeDataString / TryUnescapeDataString. The span
/// results are compared with the string overloads, and formatting goes into exactly sized and short
/// destinations.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     operation; byte 1 placement bits
///   rest       the text, UTF-8 (up to 512 bytes)
/// </remarks>
public static class UnsafeNetTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte op = input.Byte();
        byte place = input.Byte();
        byte[] utf8 = input.Rest().ToArray();
        if (utf8.Length > 512)
        {
            return;
        }

        string text = Encoding.UTF8.GetString(utf8);
        bool atStart = (place & 1) != 0;
        ReadOnlySpan<char> chars = Guarded.Copy<char>(text.AsSpan(), atStart);
        ReadOnlySpan<byte> bytes = Guarded.Copy<byte>(utf8, !atStart);
        string what = $"op {op % 6} {Check.Show(text)}";
        switch (op % 6)
        {
            case 0: Address(text, chars, utf8, bytes, atStart, what); break;
            case 1: Network(text, chars, atStart, what); break;
            case 2: EndPoint(text, chars, what); break;
            case 3: Escape(text, chars, atStart, what); break;
            case 4: Physical(text, chars, what); break;
            default: AddressBytes(utf8, place, what); break;
        }
    }

    private static Span<T> Out<T>(int length, bool atStart) => Guarded.Copy<T>(new T[length], atStart);

    // ScopeId is only defined for IPv6 (it throws SocketException for IPv4).
    private static bool Same(IPAddress a, IPAddress b) =>
        a.Equals(b) && (a.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6 || a.ScopeId == b.ScopeId);

    private static void Address(string text, ReadOnlySpan<char> chars, byte[] utf8, ReadOnlySpan<byte> bytes, bool atStart, string what)
    {
        bool ok = IPAddress.TryParse(text, out IPAddress fromString);
        bool spanOk = IPAddress.TryParse(chars, out IPAddress fromSpan);
        Check.That(ok == spanOk && (!ok || Same(fromString, fromSpan)), $"IPAddress.TryParse(span) {spanOk} {fromSpan}, (string) {ok} {fromString}: {what}");
        bool utf8Ok = IPAddress.TryParse(bytes, out IPAddress fromUtf8);
        if (Encoding.UTF8.GetByteCount(text) == utf8.Length && !text.Contains('�'))
        {
            Check.That(utf8Ok == ok && (!ok || Same(fromUtf8, fromString)), $"IPAddress.TryParse(utf8) {utf8Ok} {fromUtf8} vs (string) {ok} {fromString}: {what}");
        }

        Check.Equal(ok, IPAddress.IsValid(chars), $"IPAddress.IsValid(span): {what}");
        if (!ok)
        {
            return;
        }

        Formats(fromString, atStart, what);
    }

    /// <summary>TryFormat / TryWriteBytes of an address into exactly sized and short guarded destinations, and a round trip.</summary>
    private static void Formats(IPAddress address, bool atStart, string what)
    {
        string s = address.ToString();
        Span<char> exact = Out<char>(s.Length, atStart);
        Check.That(address.TryFormat(exact, out int written) && written == s.Length && exact.SequenceEqual(s), $"TryFormat into exactly {s.Length} chars wrote {written}: {what}");
        Check.That(!address.TryFormat(Out<char>(s.Length - 1, !atStart), out _), $"TryFormat into {s.Length - 1} chars succeeded: {what}");
        byte[] u = Encoding.UTF8.GetBytes(s);
        Span<byte> exact8 = Out<byte>(u.Length, !atStart);
        Check.That(address.TryFormat(exact8, out written) && written == u.Length && exact8.SequenceEqual(u), $"UTF-8 TryFormat into exactly {u.Length} bytes wrote {written}: {what}");
        Check.That(!address.TryFormat(Out<byte>(u.Length - 1, atStart), out _), $"UTF-8 TryFormat into {u.Length - 1} bytes succeeded: {what}");

        int size = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 16 : 4;
        Span<byte> raw = Out<byte>(size, atStart);
        Check.That(address.TryWriteBytes(raw, out written) && written == size && raw.SequenceEqual(address.GetAddressBytes()), $"TryWriteBytes into {size}: {what}");
        Check.That(!address.TryWriteBytes(Out<byte>(size - 1, !atStart), out _), $"TryWriteBytes into {size - 1} succeeded: {what}");

        IPAddress again = IPAddress.Parse(s);
        Check.That(Same(again, address), $"ToString {Check.Show(s)} parses as {again}: {what}");
        IPAddress fromBytes = size == 16 ? new IPAddress(Guarded.Copy<byte>(address.GetAddressBytes(), atStart), address.ScopeId) : new IPAddress(Guarded.Copy<byte>(address.GetAddressBytes(), atStart));
        Check.That(fromBytes.Equals(address), $"new IPAddress(span) gives {fromBytes}: {what}");
        if (size == 16)
        {
            _ = (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address.MapToIPv6(), address.IsIPv6LinkLocal, address.IsIPv6UniqueLocal, address.IsIPv6Teredo);
        }
    }

    private static void Network(string text, ReadOnlySpan<char> chars, bool atStart, string what)
    {
        bool ok = IPNetwork.TryParse(text, out IPNetwork fromString);
        bool spanOk = IPNetwork.TryParse(chars, out IPNetwork fromSpan);
        Check.That(ok == spanOk && (!ok || fromString.Equals(fromSpan)), $"IPNetwork.TryParse(span) {spanOk} {fromSpan}, (string) {ok} {fromString}: {what}");
        if (!ok)
        {
            return;
        }

        string s = fromString.ToString();
        Span<char> exact = Out<char>(s.Length, atStart);
        Check.That(fromString.TryFormat(exact, out int written) && written == s.Length && exact.SequenceEqual(s), $"IPNetwork.TryFormat into exactly {s.Length} wrote {written}: {what}");
        Check.That(!fromString.TryFormat(Out<char>(s.Length - 1, !atStart), out _), $"IPNetwork.TryFormat into {s.Length - 1} succeeded: {what}");
        byte[] u = Encoding.UTF8.GetBytes(s);
        Span<byte> exact8 = Out<byte>(u.Length, !atStart);
        Check.That(fromString.TryFormat(exact8, out written) && written == u.Length && exact8.SequenceEqual(u), $"IPNetwork UTF-8 TryFormat into exactly {u.Length} wrote {written}: {what}");
        Check.That(IPNetwork.Parse(s).Equals(fromString), $"IPNetwork ToString {Check.Show(s)} doesn't parse back: {what}");
        Check.That(fromString.Contains(fromString.BaseAddress), $"IPNetwork doesn't contain its base address: {what}");
    }

    private static void EndPoint(string text, ReadOnlySpan<char> chars, string what)
    {
        bool ok = IPEndPoint.TryParse(text, out IPEndPoint fromString);
        bool spanOk = IPEndPoint.TryParse(chars, out IPEndPoint fromSpan);
        Check.That(ok == spanOk && (!ok || fromString.Equals(fromSpan)), $"IPEndPoint.TryParse(span) {spanOk} {fromSpan}, (string) {ok} {fromString}: {what}");
        if (ok)
        {
            string s = fromString.ToString();
            Check.That(IPEndPoint.TryParse(s, out IPEndPoint again) && again.Equals(fromString), $"IPEndPoint ToString {Check.Show(s)} parses as {again}: {what}");
        }
    }

    private static void Escape(string text, ReadOnlySpan<char> chars, bool atStart, string what)
    {
        // Escaping: the span API against the string one, into exactly sized and short destinations.
        var escaped = Outcome<string>.Of(() => Uri.EscapeDataString(text), e => e is UriFormatException);
        if (escaped.Ok)
        {
            string e = escaped.Value;
            Span<char> exact = Out<char>(e.Length, atStart);
            Check.That(Uri.TryEscapeDataString(chars, exact, out int written) && written == e.Length && exact.SequenceEqual(e), $"TryEscapeDataString into exactly {e.Length} wrote {written}: {what}");
            if (e.Length > 0)
            {
                Check.That(!Uri.TryEscapeDataString(chars, Out<char>(e.Length - 1, !atStart), out _), $"TryEscapeDataString into {e.Length - 1} succeeded: {what}");
            }

            Check.Equal(e, Uri.EscapeDataString(chars), $"EscapeDataString(span): {what}");
        }

        string u = Uri.UnescapeDataString(text);
        Span<char> exactU = Out<char>(u.Length, !atStart);
        Check.That(Uri.TryUnescapeDataString(chars, exactU, out int w) && w == u.Length && exactU.SequenceEqual(u), $"TryUnescapeDataString into exactly {u.Length} wrote {w}: {what}");
        if (u.Length > 0)
        {
            Check.That(!Uri.TryUnescapeDataString(chars, Out<char>(u.Length - 1, atStart), out _), $"TryUnescapeDataString into {u.Length - 1} succeeded: {what}");
        }

        Check.Equal(u, Uri.UnescapeDataString(chars), $"UnescapeDataString(span): {what}");
    }

    private static void Physical(string text, ReadOnlySpan<char> chars, string what)
    {
        bool ok = PhysicalAddress.TryParse(text, out PhysicalAddress fromString);
        bool spanOk = PhysicalAddress.TryParse(chars, out PhysicalAddress fromSpan);
        Check.That(ok == spanOk && (!ok || fromString.Equals(fromSpan)), $"PhysicalAddress.TryParse(span) {spanOk} {fromSpan}, (string) {ok} {fromString}: {what}");
        if (ok)
        {
            Check.That(PhysicalAddress.Parse(fromString.ToString()).Equals(fromString), $"PhysicalAddress ToString {fromString} doesn't parse back: {what}");
        }
    }

    private static void AddressBytes(byte[] raw, byte place, string what)
    {
        // Addresses from raw bytes (4 or 16), formatted.
        if (raw.Length < 4)
        {
            return;
        }

        bool v6 = (place & 2) != 0 && raw.Length >= 16;
        byte[] b = raw.AsSpan(0, v6 ? 16 : 4).ToArray();
        IPAddress address = v6 ? new IPAddress(Guarded.Copy<byte>(b, (place & 1) != 0), (place & 4) != 0 ? raw[^1] : 0) : new IPAddress(Guarded.Copy<byte>(b, (place & 1) != 0));
        Formats(address, (place & 8) != 0, $"{address} from 0x{Convert.ToHexString(b)}: {what}");
    }
}
