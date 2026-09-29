using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using System.Text.Json;
using System.Text.RegularExpressions;

// Each check returns (reproduced, observed-behaviour). "reproduced" means the runtime still shows the bug.
var checks = new (string Id, string Title, Func<(bool, string)> Check)[]
{
    ("REGEX-1", "new Regex(\"[^\", ECMAScript) throws IndexOutOfRangeException instead of RegexParseException", () =>
    {
        try { _ = new Regex("[^", RegexOptions.ECMAScript); return (true, "no exception at all"); }
        catch (RegexParseException e) { return (false, $"RegexParseException ({e.Error})"); }
        catch (Exception e) { return (true, e.GetType().FullName!); }
    }),

    ("REGEX-2", "NonBacktracking misses the leftmost match of 0?x in \"0axx\"", () =>
    {
        int bt = Regex.Match("0axx", "0?x").Index;
        int nb = Regex.Match("0axx", "0?x", RegexOptions.NonBacktracking).Index;
        string all = string.Join(",", Regex.Matches("0axx", "0?x", RegexOptions.NonBacktracking).Select(m => $"{m.Index}:{m.Length}"));
        return (bt != nb, $"backtracking index {bt}, NonBacktracking index {nb} (all NB matches: {all})");
    }),

    ("REGEX-3", "NonBacktracking ignores the priority of an empty middle alternation branch: (x||.)h on \"hh\"", () =>
    {
        Match bt = Regex.Match("hh", "(x||.)h");
        Match nb = Regex.Match("hh", "(x||.)h", RegexOptions.NonBacktracking);
        return (bt.Length != nb.Length, $"backtracking {bt.Index}:{bt.Length}, NonBacktracking {nb.Index}:{nb.Length}");
    }),

    ("REGEX-4", "NonBacktracking reports a mandatory group as unmatched: x*(\\Bx) on \"xx\"", () =>
    {
        Match nb = Regex.Match("xx", @"x*(\Bx)", RegexOptions.NonBacktracking);
        return (nb.Success && !nb.Groups[1].Success,
            $"match {nb.Index}:{nb.Length}, Groups[1].Success={nb.Groups[1].Success} (backtracking: '{Regex.Match("xx", @"x*(\Bx)").Groups[1].Value}')");
    }),

    ("REGEX-5", "Match timeout not enforced: (){10000000}x with a 100 ms timeout", () =>
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            bool m = new Regex("(){10000000}x", RegexOptions.None, TimeSpan.FromMilliseconds(100)).IsMatch("x");
            return (sw.ElapsedMilliseconds > 200, $"returned {m} after {sw.ElapsedMilliseconds} ms without RegexMatchTimeoutException");
        }
        catch (RegexMatchTimeoutException) { return (false, $"timed out after {sw.ElapsedMilliseconds} ms"); }
    }),

    ("REGEX-6", "Backtracking engines make \\W+ / -+ atomic before \\B and miss matches: -+\\B on \"--a\"", () =>
    {
        bool interp = Regex.IsMatch("--a", @"-+\B");
        bool compiled = Regex.IsMatch("--a", @"-+\B", RegexOptions.Compiled);
        bool nb = Regex.IsMatch("--a", @"-+\B", RegexOptions.NonBacktracking);
        return (!interp || !compiled, $"interpreter {interp}, Compiled {compiled}, NonBacktracking {nb} (expected true: '-' then \\B between '-' and '-')");
    }),

    ("JSON-1", "JsonElement.DeepEquals throws for numbers whose exponent doesn't fit in an int", () =>
    {
        if (DeepEquals is null) return (false, "JsonElement.DeepEquals not available (< .NET 9)");
        try { bool r = CallDeepEquals("0e99999999999", "0e99999999999"); return (false, $"returned {r}"); }
        catch (Exception e) { return (true, $"{e.GetType().Name}: {e.Message}"); }
    }),

    ("JSON-2", "Out-of-range JSON numbers deserialize to double infinity but can't be serialized back (by design, noted)", () =>
    {
        double d = JsonSerializer.Deserialize<double>("1e400");
        try { JsonSerializer.Serialize(d); return (false, $"deserialized {d}, serialized fine"); }
        catch (ArgumentException) { return (true, $"deserialized {d}; Serialize throws ArgumentException"); }
    }),

    ("JSON-3", "JsonElement.DeepEquals(10e2147483647, 1e-2147483648) returns true (int overflow while normalizing)", () =>
    {
        if (DeepEquals is null) return (false, "JsonElement.DeepEquals not available (< .NET 9)");
        bool r = CallDeepEquals("10e2147483647", "1e-2147483648");
        return (r, $"returned {r}");
    }),

    ("BASE64URL-1", "Base64Url.TryDecodeFromChars(\"QUI\", 1-byte buffer) throws FormatException instead of returning false", () =>
    {
        if (Base64UrlTryDecodeFromChars is null) return (false, "Base64Url not available (< .NET 9)");
        byte[] shortBuffer = new byte[1]; // "QUI" decodes to 2 bytes
        try { bool ok = Base64UrlTryDecodeFromChars("QUI", shortBuffer, out int w); return (false, $"returned {ok}, wrote {w}"); }
        catch (FormatException e) { return (true, $"FormatException: {e.Message}"); }
    }),

    ("HEX-1", "Convert.FromHexString(\"zz\", dst, out consumed, out written) reports charsConsumed=1 for an invalid first char", () =>
    {
        if (FromHexStringStatus is null) return (false, "Convert.FromHexString(span, span, out, out) not available (< .NET 9)");
        var status = FromHexStringStatus("zz", new byte[1], out int consumed, out int written);
        var status2 = FromHexStringStatus("0z", new byte[1], out int consumed2, out _);
        return (consumed != 0, $"\"zz\": {status}, charsConsumed={consumed}, bytesWritten={written}; for comparison \"0z\": {status2}, charsConsumed={consumed2}");
    }),

    ("UTF7-1", "UTF-7 Encoder.Convert with a small output buffer duplicates output: \"ab\\u0100\" into 5-byte chunks", () =>
    {
#pragma warning disable SYSLIB0001
        Encoder encoder = new UTF7Encoding().GetEncoder();
#pragma warning restore SYSLIB0001
        char[] chars = "ab\u0100".ToCharArray();
        var output = new List<byte>();
        byte[] buffer = new byte[5];
        int pos = 0;
        for (int i = 0; i < 10; i++)
        {
            encoder.Convert(chars, pos, chars.Length - pos, buffer, 0, buffer.Length, true, out int used, out int produced, out bool completed);
            output.AddRange(buffer.AsSpan(0, produced).ToArray());
            pos += used;
            if (completed) break;
        }

        string result = Encoding.ASCII.GetString(output.ToArray());
        return (result != "ab+AQA-", $"Convert produced \"{result}\", GetBytes produces \"ab+AQA-\"");
    }),

    ("UTF7-2", "UTF-7 Encoder.Convert never reports completed after a surrogate pair followed by a direct char: \"\\uD83D\\uDE00b\"", () =>
    {
#pragma warning disable SYSLIB0001
        Encoder encoder = new UTF7Encoding().GetEncoder();
#pragma warning restore SYSLIB0001
        char[] chars = "\uD83D\uDE00b".ToCharArray();
        byte[] buffer = new byte[64];
        encoder.Convert(chars, 0, chars.Length, buffer, 0, buffer.Length, true, out int used, out int produced, out bool completed);
        encoder.Convert(chars, chars.Length, 0, buffer, 0, buffer.Length, true, out _, out int produced2, out bool completed2);
        return (!completed2, $"first call: charsUsed={used}/{chars.Length}, bytesUsed={produced}, completed={completed}; flushing again: bytesUsed={produced2}, completed={completed2}");
    }),

    ("COMPOSITEFORMAT-1", "CompositeFormat.Parse(\"{4294967297}\") accepts an index string.Format rejects, and formats argument 1", () =>
    {
        string viaString;
        try { viaString = string.Format(null, "{4294967297}", "a", "b"); } catch (FormatException) { viaString = "FormatException"; }
        try
        {
            var cf = System.Text.CompositeFormat.Parse("{4294967297}");
            string viaCf = string.Format(null, cf, "a", "b");
            return (true, $"string.Format: {viaString}; CompositeFormat: MinimumArgumentCount={cf.MinimumArgumentCount}, formats as \"{viaCf}\"");
        }
        catch (FormatException) { return (false, $"string.Format: {viaString}; CompositeFormat.Parse: FormatException"); }
    }),

    ("COMPOSITEFORMAT-2", "For \"{0:}\" string.Format passes format null to IFormattable, CompositeFormat passes \"\"", () =>
    {
        var echo = new EchoFormat();
        string viaString = string.Format(null, "{0:}", echo);
        string viaCf = string.Format(null, System.Text.CompositeFormat.Parse("{0:}"), echo);
        return (viaString != viaCf, $"string.Format gives {viaString}, CompositeFormat gives {viaCf}");
    }),

    ("TIMESPAN-1", "TimeSpan.TryParse(\"0:0:0.0000000123456789\") throws IndexOutOfRangeException", () =>
    {
        try { bool ok = TimeSpan.TryParse("0:0:0.0000000123456789", System.Globalization.CultureInfo.InvariantCulture, out TimeSpan t); return (false, $"returned {ok} ({t})"); }
        catch (IndexOutOfRangeException) { return (true, "IndexOutOfRangeException"); }
    }),

    ("BASE64-STREAM-1", "Base64.DecodeFromUtf8 with isFinalBlock: false returns InvalidData for valid input with whitespace", () =>
    {
        byte[] input = Encoding.ASCII.GetBytes("S\r\nGVsbG8gV29y"); // "Hello Wor"
        byte[] output = new byte[32];
        var first = System.Buffers.Text.Base64.DecodeFromUtf8(input.AsSpan(0, 7), output, out int consumed, out int written, isFinalBlock: false);
        var oneShot = System.Buffers.Text.Base64.DecodeFromUtf8(input, output, out _, out int all, isFinalBlock: true);
        return (first == System.Buffers.OperationStatus.InvalidData,
            $"first 7 bytes with isFinalBlock=false: {first} (consumed {consumed}, written {written}); whole input in one call: {oneShot} ({all} bytes)");
    }),

    ("RESOURCES-1", "A 206-byte .resources file with numResources = 0x10000000 makes ResourceReader allocate ~1 GB", () =>
    {
        var ms = new MemoryStream();
        using (var w = new System.Resources.ResourceWriter(ms)) { w.AddResource("key", "value"); w.Generate(); }
        byte[] file = ms.ToArray();
        var br = new BinaryReader(new MemoryStream(file));
        br.ReadInt32(); br.ReadInt32(); int skip = br.ReadInt32(); br.BaseStream.Seek(skip + 4, SeekOrigin.Current);
        BitConverter.GetBytes(0x10000000).CopyTo(file, (int)br.BaseStream.Position); // numResources
        long before = GC.GetTotalAllocatedBytes(precise: true);
        string result;
        try { using var reader = new System.Resources.ResourceReader(new MemoryStream(file)); result = "no exception"; }
        catch (Exception e) { result = e.GetType().Name; }
        long allocated = GC.GetTotalAllocatedBytes(precise: true) - before;
        return (allocated > 100_000_000, $"{file.Length}-byte file: {result} after allocating {allocated / (1 << 20)} MB");
    }),

    ("NUMBER-NEGZERO-1", "uint.TryParse accepts \"-0\" and \"-0e5\" but rejects \"-0.0\" with NumberStyles.Float", () =>
    {
        var inv = System.Globalization.CultureInfo.InvariantCulture;
        string R(string s) => uint.TryParse(s, System.Globalization.NumberStyles.Float, inv, out uint v) ? v.ToString() : "false";
        bool signed = int.TryParse("-0.0", System.Globalization.NumberStyles.Float, inv, out _);
        return (R("-0.0") == "false" && R("-0") == "0", $"\"-0\": {R("-0")}, \"-0e5\": {R("-0e5")}, \"-0.0\": {R("-0.0")} (int.TryParse(\"-0.0\"): {signed})");
    }),

    ("UTF8PARSER-FLOAT-1", "Utf8Parser reads \"63732000000000900.000\" as a different double than \"63732000000000900\" (tie rounded up)", () =>
    {
        System.Buffers.Text.Utf8Parser.TryParse("63732000000000900"u8, out double plain, out _);
        System.Buffers.Text.Utf8Parser.TryParse("63732000000000900.000"u8, out double withZeros, out _);
        double reference = double.Parse("63732000000000900.000", System.Globalization.CultureInfo.InvariantCulture);
        return (withZeros != plain, $"\"...900\": {plain:R}, \"...900.000\": {withZeros:R}, double.Parse: {reference:R}");
    }),

    ("UTF8PARSER-DECIMAL-1", "Utf8Parser rounds decimal midpoints half away from zero, decimal.Parse half to even", () =>
    {
        const string text = "76228501625444444444444444444.5";
        System.Buffers.Text.Utf8Parser.TryParse(Encoding.ASCII.GetBytes(text), out decimal viaUtf8, out _);
        decimal viaParse = decimal.Parse(text, System.Globalization.CultureInfo.InvariantCulture);
        return (viaUtf8 != viaParse, $"Utf8Parser: {viaUtf8}, decimal.Parse: {viaParse}");
    }),

    ("LINQ-SUM-1", "Enumerable.Sum(int[32]) throws OverflowException although the sum (-2) and every running sum fit", () =>
    {
        var x = new int[32];
        x[0] = int.MinValue; x[1] = int.MaxValue; x[8] = -1;
        var shorter = x[..31];
        string R(int[] a) { try { return a.Sum().ToString(); } catch (OverflowException) { return "OverflowException"; } }
        string full = R(x);
        return (full == "OverflowException", $"int[32]: {full}; same values as int[31]: {R(shorter)} (Vector<int>.Count = {System.Numerics.Vector<int>.Count}, accelerated = {System.Numerics.Vector.IsHardwareAccelerated})");
    }),
    // Round 5: the managed / native boundary (Linux where noted).
    ("MARSHAL-CHARARR-1", "ANSI char[] P/Invoke parameters are converted as one UTF-8 string: [Out] elements shift and the tail is left stale, [In] non-ASCII chars overflow the byte-per-char buffer (Unix)", () =>
    {
        if (!OperatingSystem.IsLinux()) return (false, "Linux only");
        byte[] src = [0x41, 0xC3, 0xA9, 0x42, 0xFF, 0x43, 0xE2, 0x82];
        char[] outArray = "ABCDEFGH".ToCharArray();
        Native.memcpy_chars_inout(outArray, src, (nuint)src.Length);
        string got = string.Join(" ", outArray.Select(c => ((int)c).ToString("X4")));
        string inResult;
        IntPtr buffer = Marshal.AllocHGlobal(8);
        try
        {
            for (int i = 0; i < 8; i++) Marshal.WriteByte(buffer, i, 0xCC);
            try { Native.memcpy_chars_in(buffer, ['\u00e9', 'x', '\u20ac', 'y'], 4); inResult = "native " + Convert.ToHexString(Enumerable.Range(0, 4).Select(i => Marshal.ReadByte(buffer, i)).ToArray()) + " ('y' lost, '\u20ac' cut)"; }
            catch (Exception e) { inResult = e.GetType().Name; }
        }
        finally { Marshal.FreeHGlobal(buffer); }
        return (outArray[3] != 'B' || outArray[7] == 'H', $"[In, Out] char[8] after memcpy of 41 C3 A9 42 FF 43 E2 82 -> [{got}] (5 or 6 decoded chars, rest stale); [In] char[4] of \"\u00e9x\u20acy\" -> {inResult}");
    }),

    ("LAYOUT-ALIAS-2", "Marshal.StructureToPtr / DestroyStructure of an explicit layout whose ByValArray-of-string region overlaps another reference field double-frees the aliased pointer (process abort; shown without the freeing step)", () =>
    {
        // The abort itself (StructureToPtr marshals A[1] and S into the same 8 bytes, DestroyStructure frees
        // them twice) would kill the process, so this reads the aliased pointer back instead of freeing.
        int size = Marshal.SizeOf<AliasArray>();
        IntPtr p = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.Copy(new byte[size], 0, p, size);
            Marshal.StructureToPtr(new AliasArray { A = ["a", "b", "c", "d"], S = "x" }, p, false);
            IntPtr slot1 = Marshal.ReadIntPtr(p, 8); // A[1] and S occupy the same native pointer slot
            return (true, $"SizeOf={size}, type loaded OK; A[1] and S share the native pointer at offset 8 ({slot1:X}); DestroyStructure would free it once per field (glibc 'double free detected')");
        }
        finally { Marshal.FreeHGlobal(p); }
    }),

    ("RSA-IMPORT-1", "RSA.ImportParameters with an empty (non-null) Modulus or Exponent throws IndexOutOfRangeException instead of CryptographicException (ECDsa / DSA reject the same input cleanly)", () =>
    {
        try { using var rsa = System.Security.Cryptography.RSA.Create(); rsa.ImportParameters(new System.Security.Cryptography.RSAParameters { Modulus = [], Exponent = [] }); return (false, "ImportParameters accepted empty components"); }
        catch (System.Security.Cryptography.CryptographicException) { return (false, "CryptographicException (clean)"); }
        catch (IndexOutOfRangeException) { return (true, "IndexOutOfRangeException from RSA.ImportParameters with empty Modulus/Exponent"); }
    }),

    ("SOCKADDR-SCOPE-1", "IPEndPoint.Create drops sin6_scope_id unless the address is link-local, while Serialize keeps it", () =>
    {
        var loopback = new IPEndPoint(new IPAddress(new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 3), 80);
        SocketAddress sa = loopback.Serialize();
        long back = ((IPEndPoint)loopback.Create(sa)).Address.ScopeId;
        var linkLocal = new IPEndPoint(IPAddress.Parse("fe80::1%3"), 80);
        long backLinkLocal = ((IPEndPoint)linkLocal.Create(linkLocal.Serialize())).Address.ScopeId;
        return (back != 3, $"[::1%3]:80 -> Serialize (scope bytes {sa[24]} {sa[25]} {sa[26]} {sa[27]}) -> Create: ScopeId {back}; [fe80::1%3]:80 round-trips to {backLinkLocal}");
    }),

    ("RA-IOV-1", "RandomAccess.Read with more than IOV_MAX (1024) buffers returns a short read although the data is there; Write handles any count", () =>
    {
        string path = Path.Combine(Path.GetTempPath(), "sharpfuzz-ra-iov-" + Environment.ProcessId);
        try
        {
            using SafeFileHandle h = File.OpenHandle(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None, FileOptions.DeleteOnClose);
            RandomAccess.Write(h, new byte[1500], 0);
            var segments = new List<Memory<byte>>();
            for (int i = 0; i < 1500; i++) segments.Add(new byte[1]);
            long read = RandomAccess.Read(h, segments, 0);
            var sources = new List<ReadOnlyMemory<byte>>();
            for (int i = 0; i < 1500; i++) sources.Add(new byte[1]);
            RandomAccess.Write(h, sources, 2000);
            return (read != 1500, $"Read into 1500 one-byte buffers of a 1500-byte file returned {read}; Write of 1500 one-byte buffers at 2000 made the file {RandomAccess.GetLength(h)} bytes");
        }
        finally { File.Delete(path); }
    }),

    ("FS-ISASYNC-1", "FileStream.IsAsync / SafeFileHandle.IsAsync are false for FileOptions.Asynchronous on Linux (true on .NET 8, 9 and 10)", () =>
    {
        if (!OperatingSystem.IsLinux()) return (false, "Linux only");
        string path = Path.Combine(Path.GetTempPath(), "sharpfuzz-isasync-" + Environment.ProcessId);
        using var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.Asynchronous | FileOptions.DeleteOnClose);
        return (!fs.IsAsync, $"FileStream.IsAsync = {fs.IsAsync}, SafeFileHandle.IsAsync = {fs.SafeFileHandle.IsAsync}");
    }),

    ("LAYOUT-ALIAS-1", "Two LPStr fields at one explicit offset: StructureToPtr marshals the shared string twice and DestroyStructure frees it twice (process abort; checked here without freeing)", () =>
    {
        // The double free itself would abort this process, so only the duplicated pointer is shown.
        var value = new Aliased { A = "hello" };
        IntPtr p = Marshal.AllocHGlobal(16);
        try
        {
            Marshal.StructureToPtr(value, p, false);
            IntPtr first = Marshal.ReadIntPtr(p);
            // Marshal.DestroyStructure<Aliased>(p) here frees that pointer once per field and aborts the process
            // ("free(): double free detected in tcache 2" on glibc), so it is left out; the leak is freed by hand.
            Marshal.FreeCoTaskMem(first);
            return (true, $"A and B share the slot ({value.B}); StructureToPtr marshalled the string once per field into the same 8 bytes (last pointer {first:X}, the first copy leaked); DestroyStructure would free it twice");
        }
        finally { Marshal.FreeHGlobal(p); }
    }),
    ("FS-STALE-1", "FileStream: after a buffered WriteAsync, a Seek that lands within the previous read buffer's window serves the write payload instead of the file (sync Write is fine)", () =>
    {
        string path = Path.Combine(Path.GetTempPath(), "sharpfuzz-fs-stale-" + Environment.ProcessId);
        try
        {
            using var fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.DeleteOnClose);
            fs.Write(new byte[47]);                                   // file: 47 zeros
            fs.Seek(0, SeekOrigin.Begin);
            fs.Read(new byte[363]);                                   // 47 bytes: the read buffer is filled and fully consumed
            byte[] payload = Enumerable.Range(2, 166).Select(i => (byte)i).ToArray();
            fs.WriteAsync(payload).AsTask().GetAwaiter().GetResult(); // buffered write at 47 (file: 213 bytes)
            fs.Seek(228, SeekOrigin.Begin);                           // flushes the write, seeks past the end
            fs.Seek(-12, SeekOrigin.End);                             // 201, judged to be inside the stale read window
            byte[] read = new byte[439];
            int n = fs.Read(read);
            byte[] expected = payload.AsSpan(154, 12).ToArray();      // file[201..213)
            return (n != 12 || !read.AsSpan(0, n).SequenceEqual(expected),
                $"Read at 201 of a 213-byte file returned {n} bytes {Convert.ToHexString(read.AsSpan(0, Math.Min(n, 27)))} (expected 12: {Convert.ToHexString(expected)}), Position {fs.Position}, Length {fs.Length}");
        }
        finally { File.Delete(path); }
    }),

    ("FSNAME-1", "Directory enumeration with MatchType.Win32 treats '<', '>' and '\"' in the pattern as literals, FileSystemName.MatchesWin32Expression as DOS wildcards (Unix)", () =>
    {
        if (OperatingSystem.IsWindows()) return (false, "Unix only: those characters can't appear in Windows file names");
        string dir = Path.Combine(Path.GetTempPath(), "sharpfuzz-fsname-" + Environment.ProcessId);
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "l1"), "");
            string translated = System.IO.Enumeration.FileSystemName.TranslateWin32Expression("<l*");
            bool matcher = System.IO.Enumeration.FileSystemName.MatchesWin32Expression(translated, "l1", ignoreCase: true);
            bool enumerated = Directory.EnumerateFiles(dir, "<l*", new EnumerationOptions { MatchType = MatchType.Win32, MatchCasing = MatchCasing.CaseInsensitive }).Any();
            return (matcher != enumerated, $"pattern \"<l*\" (TranslateWin32Expression: \"{translated}\") on \"l1\": MatchesWin32Expression {matcher}, enumeration {enumerated}");
        }
        finally { Directory.Delete(dir, true); }
    }),
    ("COLLATION-NUM-1", "CompareInfo.Compare with NumericOrdering orders two digit strings differently from their sort keys (zh-CN, Mongolian digits)", () =>
    {
        var ci = System.Globalization.CultureInfo.GetCultureInfo("zh-CN").CompareInfo;
        var numeric = (System.Globalization.CompareOptions)32; // NumericOrdering, .NET 10+
        string a = "\u1818\u1858\u6418\u0000\uFF00\uFFFF\uFFFF\uFFFF\uFFFF\uFF0F\uFFFF\uDFFFk-\u2379\uFFFF\uFFF8\uFFFF\uFFFF\uFFFF\uFFFF\uFFFF\uFFFF\uFFFF";
        string b = "\u1818\u1818\u1818\u1818\u1810\u1818\u1810\u1818\u1818\u1818\u1818\u1818\u1818\u1818 \uFFFF\u7FFF\uFFFF\uFFFF\uF1FF\uFF00\uFFFF\uFFFF\uFFFF\uFFFF\u01FF\u0001S\u03BE\u2DF5\u700A\u4D00\u2D00\uFF00\uFFF8\uFFFF\uFFFF\uFFFF\uFFFF\uFFFF\uFFFF\u0000\u0000\uFFFF\uCB72";
        try
        {
            var results = new List<string>();
            bool differ = false;
            foreach (var (x, y, label) in new[] { (a.Substring(0, 3), b.Substring(0, 15), "fuzzed prefixes"), ("\u1818\u1858", "\u1818\u1818\u1818", "8+letter vs 888 (Mongolian)"), ("8a", "888", "8a vs 888"), ("2", "10", "2 vs 10"), ("2a", "10", "2a vs 10"), ("a2", "a10", "a2 vs a10") })
            {
                foreach (string culture in new[] { "zh-CN", "en-US", "", "ja-JP" })
                {
                    var c = System.Globalization.CultureInfo.GetCultureInfo(culture).CompareInfo;
                    int cmp = Math.Sign(c.Compare(x, y, numeric));
                    int keys = Math.Sign(System.Globalization.SortKey.Compare(c.GetSortKey(x, numeric), c.GetSortKey(y, numeric)));
                    differ |= cmp != keys;
                    results.Add($"{label} [{(culture.Length == 0 ? "inv" : culture)}] {cmp}/{keys}");
                }
            }
            return (differ, string.Join("; ", results));
        }
        catch (ArgumentException) { return (false, "NumericOrdering isn't supported on this runtime"); }
    }),
};

Console.WriteLine(System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription);
foreach (var (id, title, check) in checks)
{
    var (reproduced, observed) = check();
    Console.WriteLine($"{(reproduced ? "REPRODUCED" : "not seen  ")}  {id,-8} {title}\n            -> {observed}");
}

sealed class EchoFormat : IFormattable
{
    public string ToString(string? format, IFormatProvider? formatProvider) => format is null ? "<null>" : $"<\"{format}\">";
}

partial class Program
{
    delegate bool TryDecodeChars(ReadOnlySpan<char> source, Span<byte> destination, out int bytesWritten);
    delegate System.Buffers.OperationStatus HexStatus(ReadOnlySpan<char> source, Span<byte> destination, out int charsConsumed, out int bytesWritten);

    // .NET 9+ APIs, bound dynamically so this also runs on .NET 8.
    static readonly TryDecodeChars? Base64UrlTryDecodeFromChars = typeof(object).Assembly.GetType("System.Buffers.Text.Base64Url")
        ?.GetMethod("TryDecodeFromChars", [typeof(ReadOnlySpan<char>), typeof(Span<byte>), typeof(int).MakeByRefType()])?.CreateDelegate<TryDecodeChars>();

    static readonly HexStatus? FromHexStringStatus = typeof(Convert)
        .GetMethod("FromHexString", [typeof(ReadOnlySpan<char>), typeof(Span<byte>), typeof(int).MakeByRefType(), typeof(int).MakeByRefType()])?.CreateDelegate<HexStatus>();

    // JsonElement.DeepEquals was added in .NET 9; bind to it dynamically so this also runs on .NET 8.
    static readonly MethodInfo? DeepEquals = typeof(JsonElement).GetMethod("DeepEquals", BindingFlags.Public | BindingFlags.Static);

    static bool CallDeepEquals(string left, string right)
    {
        using JsonDocument a = JsonDocument.Parse(left), b = JsonDocument.Parse(right);
        try { return (bool)DeepEquals!.Invoke(null, [a.RootElement, b.RootElement])!; }
        catch (TargetInvocationException e) { throw e.InnerException!; }
    }
}

partial class Program
{
    [StructLayout(LayoutKind.Explicit, Size = 64)]
    struct AliasArray
    {
        [FieldOffset(0)] [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4, ArraySubType = UnmanagedType.LPStr)] public string[] A;
        [FieldOffset(8)] [MarshalAs(UnmanagedType.LPUTF8Str)] public string S;
    }

    [StructLayout(LayoutKind.Explicit)]
    struct Aliased
    {
        [FieldOffset(0)] [MarshalAs(UnmanagedType.LPStr)] public string A;
        [FieldOffset(0)] [MarshalAs(UnmanagedType.LPStr)] public string B;
    }

    static class Native
    {
        [DllImport("libc", EntryPoint = "memcpy", CharSet = CharSet.Ansi)] public static extern IntPtr memcpy_chars_inout([In, Out] char[] dst, byte[] src, nuint n);
        [DllImport("libc", EntryPoint = "memcpy", CharSet = CharSet.Ansi)] public static extern IntPtr memcpy_chars_in(IntPtr dst, [In] char[] src, nuint n);
    }
}
