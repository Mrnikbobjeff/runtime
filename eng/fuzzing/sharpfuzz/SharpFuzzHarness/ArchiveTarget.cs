#nullable disable warnings
using System.Formats.Tar;
using System.IO.Compression;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// Archive readers over fuzzed bytes: ZipArchive (the synchronous API and the asynchronous one added in
/// .NET 10) and TarReader (GetNextEntry / GetNextEntryAsync). Entry metadata and content read through
/// the synchronous and asynchronous paths must agree, and malformed archives may only fail with the
/// documented exceptions (InvalidDataException, and for tar also FormatException / EndOfStreamException
/// is not documented, so it is reported).
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     format (bit 0: zip or tar) and options
///   rest       the archive
/// </remarks>
public static class ArchiveTarget
{
    private const int MaxEntries = 64, MaxContent = 1 << 16;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        byte[] bytes = input.Rest().ToArray();
        if (bytes.Length > 1 << 16)
        {
            return;
        }

        string what = $"{((mode & 1) == 0 ? "zip" : "tar")} mode {mode:X2}, {bytes.Length} bytes 0x{Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 48)))}";
        if ((mode & 1) == 0)
        {
            var sync = Outcome<string>.Of(() => Zip(bytes, (mode & 2) != 0), Allowed);
            var async = Outcome<string>.Of(() => ZipAsync(bytes, (mode & 2) != 0).GetAwaiter().GetResult(), Allowed);
            Check.That(sync.SameAs(async), $"ZipArchive sync [{sync}] vs async [{async}]: {what}");
        }
        else
        {
            // Truncated tar data throws EndOfStreamException, an IOException, which GetNextEntry documents.
            var sync = Outcome<string>.Of(() => Tar(bytes, (mode & 2) != 0), e => Allowed(e) || e is EndOfStreamException);
            var async = Outcome<string>.Of(() => TarAsync(bytes, (mode & 2) != 0).GetAwaiter().GetResult(), e => Allowed(e) || e is EndOfStreamException);
            Check.That(sync.SameAs(async), $"TarReader sync [{sync}] vs async [{async}]: {what}");
        }
    }

    private static bool Allowed(Exception e) => e is InvalidDataException;

    private static string Describe(ZipArchiveEntry e) =>
        $"{Check.Show(e.FullName)} {e.Length}/{e.CompressedLength} crc {e.Crc32:X8} attr {e.ExternalAttributes:X} {e.LastWriteTime:O} enc {e.IsEncrypted} comment {Check.Show(e.Comment)}";

    private static string Content(Stream s)
    {
        var ms = new MemoryStream();
        byte[] buffer = new byte[4096];
        int n;
        while (ms.Length < MaxContent && (n = s.Read(buffer, 0, buffer.Length)) > 0)
        {
            ms.Write(buffer, 0, n);
        }

        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(ms.ToArray()))[..16] + ":" + ms.Length;
    }

    private static async Task<string> ContentAsync(Stream s)
    {
        var ms = new MemoryStream();
        byte[] buffer = new byte[4096];
        int n;
        while (ms.Length < MaxContent && (n = await s.ReadAsync(buffer)) > 0)
        {
            ms.Write(buffer, 0, n);
        }

        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(ms.ToArray()))[..16] + ":" + ms.Length;
    }

    private static string Zip(byte[] bytes, bool utf8Names)
    {
        var sb = new StringBuilder();
        using var archive = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read, leaveOpen: false, utf8Names ? Encoding.UTF8 : null);
        sb.Append("comment ").Append(Check.Show(archive.Comment)).Append(';');
        foreach (ZipArchiveEntry entry in archive.Entries.Take(MaxEntries))
        {
            sb.Append(Describe(entry));
            string content;
            try
            {
                using Stream s = entry.Open();
                content = Content(s);
            }
            catch (InvalidDataException e)
            {
                content = e.GetType().Name + ": " + e.Message;
            }

            sb.Append(" = ").Append(content).Append(';');
        }

        return sb.ToString();
    }

    private static async Task<string> ZipAsync(byte[] bytes, bool utf8Names)
    {
        var sb = new StringBuilder();
        await using ZipArchive archive = await ZipArchive.CreateAsync(new MemoryStream(bytes), ZipArchiveMode.Read, leaveOpen: false, utf8Names ? Encoding.UTF8 : null);
        sb.Append("comment ").Append(Check.Show(archive.Comment)).Append(';');
        foreach (ZipArchiveEntry entry in archive.Entries.Take(MaxEntries))
        {
            sb.Append(Describe(entry));
            string content;
            try
            {
                await using Stream s = await entry.OpenAsync();
                content = await ContentAsync(s);
            }
            catch (InvalidDataException e)
            {
                content = e.GetType().Name + ": " + e.Message;
            }

            sb.Append(" = ").Append(content).Append(';');
        }

        return sb.ToString();
    }

    private static string Describe(TarEntry e) =>
        $"{e.Format} {e.EntryType} {Check.Show(e.Name)} -> {Check.Show(e.LinkName)} {e.Length} mode {(int)e.Mode:X} uid {e.Uid} gid {e.Gid} {e.ModificationTime:O} chk {e.Checksum} off {e.DataOffset}" +
        (e is PosixTarEntry p ? $" user {Check.Show(p.UserName)} group {Check.Show(p.GroupName)} dev {p.DeviceMajor}:{p.DeviceMinor}" : "") +
        (e is PaxTarEntry pax ? $" pax [{string.Join(",", pax.ExtendedAttributes.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => Check.Show(kv.Key) + "=" + Check.Show(kv.Value)))}]" : "") +
        (e is GnuTarEntry gnu ? $" gnu {gnu.AccessTime:O} {gnu.ChangeTime:O}" : "");

    private static string Tar(byte[] bytes, bool copy)
    {
        var sb = new StringBuilder();
        using var reader = new TarReader(new MemoryStream(bytes), leaveOpen: false);
        for (int i = 0; i < MaxEntries && reader.GetNextEntry(copy) is TarEntry entry; i++)
        {
            sb.Append(Describe(entry));
            if (entry.DataStream is Stream s)
            {
                sb.Append(" = ").Append(Content(s));
            }

            sb.Append(';');
        }

        return sb.ToString();
    }

    private static async Task<string> TarAsync(byte[] bytes, bool copy)
    {
        var sb = new StringBuilder();
        await using var reader = new TarReader(new MemoryStream(bytes), leaveOpen: false);
        for (int i = 0; i < MaxEntries && await reader.GetNextEntryAsync(copy) is TarEntry entry; i++)
        {
            sb.Append(Describe(entry));
            if (entry.DataStream is Stream s)
            {
                sb.Append(" = ").Append(await ContentAsync(s));
            }

            sb.Append(';');
        }

        return sb.ToString();
    }
}
