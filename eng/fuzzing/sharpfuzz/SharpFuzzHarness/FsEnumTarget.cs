#nullable disable warnings
using System.IO.Enumeration;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// The file system layer over System.Native with fuzzed names: files, directories and symbolic links
/// created under a fresh /dev/shm directory with names from the input (any bytes except '/' and NUL,
/// so invalid UTF-8 names round-trip through the runtime's UTF-8 handling), then enumerated through
/// Directory.EnumerateFileSystemEntries, DirectoryInfo and FileSystemEnumerator (readdir buffers,
/// FileSystemEntry spans, name matching with fuzzed patterns) and read back with FileSystemInfo
/// (attributes, link targets through readlink's growing buffer, ResolveLinkTarget). Everything
/// created must be enumerated exactly once with the right kind, and every entry must resolve.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     flags; then NUL-separated name segments (kind byte + name); the last segment is a match pattern
/// </remarks>
public static class FsEnumTarget
{
    private static int s_dirs;
    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte flags = input.Byte();
        string root = $"/dev/shm/sharpfuzz-fsenum-{Environment.ProcessId}-{s_dirs++}";
        Directory.CreateDirectory(root);
        try
        {
            Exercise(root, ref input, flags);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string Name(ReadOnlySpan<byte> bytes)
    {
        // Any bytes but '/' and NUL; the runtime decodes names as UTF-8 (invalid sequences become U+FFFD and
        // can't be recreated exactly, so such names are only enumerated, never compared by text).
        byte[] clean = bytes.ToArray().Where(b => b != (byte)'/' && b != 0).Take(200).ToArray();
        return Encoding.UTF8.GetString(clean);
    }

    private static void Exercise(string root, ref FuzzInput input, byte flags)
    {
        var expected = new Dictionary<string, char>(StringComparer.Ordinal); // name -> f / d / l
        var links = new Dictionary<string, string>(StringComparer.Ordinal);
        string pattern = null;
        int count = 0;
        while (input.Remaining > 0 && count < 24)
        {
            byte kind = input.Byte();
            string name = Name(input.SegmentBytes());
            if (input.Remaining == 0)
            {
                pattern = name;
                break;
            }

            if (name.Length == 0 || name is "." or ".." || name.Contains('�') && (kind & 8) != 0 || expected.ContainsKey(name))
            {
                continue;
            }

            string path = Path.Combine(root, name);
            try
            {
                switch (kind % 3)
                {
                    case 0:
                        File.WriteAllBytes(path, new byte[kind]);
                        expected[name] = 'f';
                        break;
                    case 1:
                        Directory.CreateDirectory(path);
                        if ((kind & 8) != 0)
                        {
                            File.WriteAllText(Path.Combine(path, "inner"), "x");
                        }

                        expected[name] = 'd';
                        break;
                    default:
                    {
                        string target = (kind & 4) != 0 ? "missing-" + name : expected.FirstOrDefault(e => e.Value == 'f').Key ?? "missing-target";
                        File.CreateSymbolicLink(path, target);
                        expected[name] = 'l';
                        links[name] = target;
                        break;
                    }
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException)
            {
                // Names the file system rejects (too long for NAME_MAX, ...): documented exceptions.
                Check.That(Encoding.UTF8.GetByteCount(name) > 255 || name.Contains('�') || e is IOException, $"{e.GetType().Name} for {Check.Show(name)}: {e.Message}");
                continue;
            }

            count++;
        }

        string what = $"{expected.Count} entries under {root}";
        // Every entry comes back exactly once with its kind, through three enumeration APIs.
        var seen = new Dictionary<string, char>(StringComparer.Ordinal);
        foreach (string entry in Directory.EnumerateFileSystemEntries(root))
        {
            string name = Path.GetFileName(entry);
            Check.That(!seen.ContainsKey(name), $"{what}: {Check.Show(name)} enumerated twice");
            seen[name] = File.GetAttributes(entry).HasFlag(FileAttributes.ReparsePoint) ? 'l' : Directory.Exists(entry) ? 'd' : 'f';
        }

        Compare(expected, seen, what, "EnumerateFileSystemEntries");
        seen.Clear();
        var info = new DirectoryInfo(root);
        foreach (FileSystemInfo entry in info.EnumerateFileSystemInfos("*", new EnumerationOptions { AttributesToSkip = 0, RecurseSubdirectories = false }))
        {
            Check.That(entry.Exists || entry.LinkTarget is not null, $"{what}: {Check.Show(entry.Name)} doesn't exist");
            seen[entry.Name] = entry.LinkTarget is not null ? 'l' : entry is DirectoryInfo ? 'd' : 'f';
            if (entry.LinkTarget is string target)
            {
                Check.That(links.TryGetValue(entry.Name, out string t) && (t == target || !t.Any(c => c == '�')), $"{what}: link {Check.Show(entry.Name)} target {Check.Show(target)} != {Check.Show(links.GetValueOrDefault(entry.Name))}");
                FileSystemInfo resolved = entry.ResolveLinkTarget(returnFinalTarget: false);
                Check.Equal(Path.Combine(root, target), resolved.FullName, $"{what}: ResolveLinkTarget of {Check.Show(entry.Name)}");
            }
        }

        Compare(expected, seen, what, "DirectoryInfo.EnumerateFileSystemInfos");
        seen.Clear();
        using (var enumerator = new Enumerator(root))
        {
            while (enumerator.MoveNext())
            {
                (string name, char kind, long length) = enumerator.Current;
                Check.That(!seen.ContainsKey(name), $"{what}: FileSystemEnumerator returned {Check.Show(name)} twice");
                seen[name] = kind;
                if (kind == 'f')
                {
                    Check.Equal(new FileInfo(Path.Combine(root, name)).Length, length, $"{what}: FileSystemEntry.Length of {Check.Show(name)}");
                }
            }
        }

        Compare(expected, seen, what, "FileSystemEnumerator");
        // Recursion into the subdirectories finds the inner files, and the links aren't followed.
        int inner = Directory.EnumerateFiles(root, "inner", SearchOption.AllDirectories).Count();
        int expectedInner = expected.Where(e => e.Value == 'd').Count(e => File.Exists(Path.Combine(root, e.Key, "inner")));
        Check.Equal(expectedInner, inner, $"{what}: recursive inner files");
        // Fuzzed match patterns: the simple-expression matcher agrees with the enumeration filter.
        if (pattern is { Length: > 0 } && !pattern.Contains('/') && pattern is not ("." or "*.*"))
        {
            var matched = new HashSet<string>(Directory.EnumerateFileSystemEntries(root, pattern, new EnumerationOptions { AttributesToSkip = 0, MatchType = MatchType.Simple, MatchCasing = MatchCasing.CaseSensitive }).Select(Path.GetFileName), StringComparer.Ordinal);
            foreach (string name in expected.Keys)
            {
                bool m = FileSystemName.MatchesSimpleExpression(pattern, name, ignoreCase: false);
                Check.Equal(m, matched.Contains(name), $"{what}: pattern {Check.Show(pattern)} on {Check.Show(name)}: MatchesSimpleExpression {m}, enumeration {matched.Contains(name)}");
            }

            var win32 = new HashSet<string>(Directory.EnumerateFileSystemEntries(root, pattern, new EnumerationOptions { AttributesToSkip = 0, MatchType = MatchType.Win32, MatchCasing = MatchCasing.CaseInsensitive }).Select(Path.GetFileName), StringComparer.Ordinal);
            foreach (string name in expected.Keys.Where(_ => s_reportKnownIssues || pattern.IndexOfAny(['<', '>', '"', '\\']) < 0))
            {
                bool m = FileSystemName.MatchesWin32Expression(FileSystemName.TranslateWin32Expression(pattern), name, ignoreCase: true);
                Check.Equal(m, win32.Contains(name), $"{what}: Win32 pattern {Check.Show(pattern)} on {Check.Show(name)}: MatchesWin32Expression {m}, enumeration {win32.Contains(name)}");
            }
        }

        // Attributes and modes on a file.
        foreach ((string name, char kind) in expected)
        {
            string path = Path.Combine(root, name);
            var fi = new FileInfo(path);
            if (kind == 'f')
            {
                Check.That(fi.Exists && !fi.Attributes.HasFlag(FileAttributes.Directory), $"{what}: FileInfo of {Check.Show(name)}");
                Check.Equal(name.StartsWith('.'), fi.Attributes.HasFlag(FileAttributes.Hidden), $"{what}: Hidden for {Check.Show(name)}");
                fi.IsReadOnly = true;
                Check.That(new FileInfo(path).IsReadOnly && !new FileInfo(path).UnixFileMode.HasFlag(UnixFileMode.UserWrite), $"{what}: IsReadOnly for {Check.Show(name)}");
                fi.IsReadOnly = false;
            }
            else if (kind == 'l')
            {
                Check.That(fi.LinkTarget is not null, $"{what}: LinkTarget of {Check.Show(name)} is null");
                Check.Equal(links[name], fi.LinkTarget, $"{what}: LinkTarget of {Check.Show(name)}");
                Check.Equal(links[name], File.ResolveLinkTarget(path, returnFinalTarget: false).Name, $"{what}: File.ResolveLinkTarget of {Check.Show(name)}");
            }
        }
    }

    private static void Compare(Dictionary<string, char> expected, Dictionary<string, char> seen, string what, string how)
    {
        Check.Equal(expected.Count, seen.Count, $"{what}: {how} count");
        foreach ((string name, char kind) in expected)
        {
            Check.That(seen.TryGetValue(name, out char k) && k == kind, $"{what}: {how} has {Check.Show(name)} as {(seen.TryGetValue(name, out char kk) ? kk : '-')}, expected {kind}");
        }
    }

    private sealed class Enumerator(string directory) : FileSystemEnumerator<(string Name, char Kind, long Length)>(directory, new EnumerationOptions { AttributesToSkip = 0 })
    {
        protected override (string Name, char Kind, long Length) TransformEntry(ref FileSystemEntry entry)
        {
            Check.Equal(directory, entry.Directory.ToString(), "FileSystemEntry.Directory");
            Check.Equal(Path.Combine(directory, entry.FileName.ToString()), entry.ToFullPath(), "FileSystemEntry.ToFullPath");
            Check.Equal(entry.FileName.ToString(), entry.ToSpecifiedFullPath()[(directory.Length + 1)..], "FileSystemEntry.ToSpecifiedFullPath");
            char kind = entry.Attributes.HasFlag(FileAttributes.ReparsePoint) ? 'l' : entry.IsDirectory ? 'd' : 'f';
            return (entry.FileName.ToString(), kind, entry.Length);
        }

        protected override bool ShouldRecurseIntoEntry(ref FileSystemEntry entry) => false;
    }
}
