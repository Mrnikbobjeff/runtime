using SharpFuzz;

namespace SharpFuzzHarness;

public static class Program
{
    private static readonly Dictionary<string, ReadOnlySpanAction> s_targets = new()
    {
        ["regex"] = RegexTarget.Run,
        ["json"] = JsonTarget.Run,
        // System.Private.CoreLib
        ["number"] = NumberTarget.Run,
        ["datetime"] = DateTimeTarget.Run,
        ["guid"] = GuidTarget.Run,
        ["version"] = VersionTarget.Run,
        ["enum"] = EnumTarget.Run,
        ["base64"] = Base64Target.Run,
        ["encoding"] = EncodingTarget.Run,
        ["searchvalues"] = SearchValuesTarget.Run,
        ["compositeformat"] = CompositeFormatTarget.Run,
        ["resources"] = ResourcesTarget.Run,
        // System.Numerics.Tensors (NuGet package, instrumented by setup.sh)
        ["tensorprimitives"] = TensorPrimitivesTarget.Run,
        // Vectorized span / array helpers over primitive element types (CoreLib, System.Collections, System.Linq)
        ["spanops"] = SpanOpsTarget.Run,
        ["utf8parser"] = Utf8ParserTarget.Run,
        // System.Collections.Immutable (Frozen, Immutable*) and OrderedDictionary
        ["collections"] = CollectionsTarget.Run,
        ["uri"] = UriTarget.Run,
        ["biginteger"] = BigIntegerTarget.Run,
        ["asn1"] = Asn1Target.Run,
        ["metadata"] = MetadataTarget.Run,
        // Round 3: header / stream parsers outside CoreLib
        ["sse"] = SseTarget.Run,
        ["data"] = DataTarget.Run,
        ["diag"] = DiagTarget.Run,
        ["mail"] = MailTarget.Run,
        ["codepages"] = CodePagesTarget.Run,
        ["tensor"] = TensorTarget.Run,
        ["sequence"] = SequenceTarget.Run,
        ["timezone"] = TimeZoneTarget.Run,
        ["cookie"] = CookieTarget.Run,
        ["httputil"] = HttpUtilityTarget.Run,
        ["calendar"] = CalendarTarget.Run,
        ["asyncenum"] = AsyncEnumTarget.Run,
        ["hashing"] = HashingTarget.Run,
        ["cbor"] = CborTarget.Run,
        ["binxml"] = BinaryXmlTarget.Run,
        ["xsd"] = XsdTarget.Run,
        ["pkcs"] = PkcsTarget.Run,
        ["cose"] = CoseTarget.Run,
        ["sortedcoll"] = SortedCollectionsTarget.Run,
        ["channels"] = ChannelsTarget.Run,
        // Guard-page memory safety (SHARPFUZZ_GUARD=1 also puts tensorprimitives / metadata buffers against guard pages)
        ["unsafetext"] = UnsafeTextTarget.Run,
        ["unsafefmt"] = UnsafeFormatTarget.Run,
        ["unsafemem"] = UnsafeMemoryTarget.Run,
        ["unsafeenc"] = UnsafeEncodingTarget.Run,
        ["unsaferegex"] = UnsafeRegexTarget.Run,
    };

    public static int Main(string[] args)
    {
        // Instrumented framework code that runs before SharpFuzz attaches AFL's shared memory (e.g.
        // System.Diagnostics.DiagnosticSource, which the process machinery touches) would write
        // coverage through a null map. Give it a scratch map until SharpFuzz sets the real one.
        unsafe
        {
            if (SharpFuzz.Common.Trace.SharedMem == null)
            {
                SharpFuzz.Common.Trace.SharedMem = (byte*)System.Runtime.InteropServices.NativeMemory.AllocZeroed(1 << 16);
            }
        }

        if (args.Length < 1)
        {
            Console.Error.WriteLine($"usage: SharpFuzzHarness <{string.Join('|', s_targets.Keys)}> [--repro <file>...]");
            return 2;
        }

        if (!s_targets.TryGetValue(args[0], out ReadOnlySpanAction? target))
        {
            throw new ArgumentException($"Unknown target '{args[0]}'.");
        }

        if (args.Length == 3 && args[1] == "--write-seeds")
        {
            IEnumerable<byte[]> seeds = Seeds.For(args[0]) ?? throw new ArgumentException($"No generated seeds for '{args[0]}'.");
            Directory.CreateDirectory(args[2]);
            int n = 0;
            foreach (byte[] seed in seeds)
            {
                File.WriteAllBytes(Path.Combine(args[2], $"seed-{n++:D3}"), seed);
            }

            Console.WriteLine($"Wrote {n} seeds to {args[2]}");
            return 0;
        }

        if (args.Length > 1 && args[1] == "--repro")
        {
            // Replay inputs directly (no AFL) and print full exception details. The instrumented
            // framework assemblies write coverage into Trace.SharedMem, so give them a scratch buffer.
            unsafe
            {
                SharpFuzz.Common.Trace.SharedMem = (byte*)System.Runtime.InteropServices.NativeMemory.AllocZeroed(1 << 16);
            }

            // SHARPFUZZ_SHOW_COVERAGE=1 prints the number of map entries each input touches
            // (afl-showmap can't drive the out-of-process fork server).
            bool showCoverage = Environment.GetEnvironmentVariable("SHARPFUZZ_SHOW_COVERAGE") is not null;
            if (showCoverage)
            {
                Console.WriteLine($"Instrumented CoreLib: {CoreLibTrace.IsInstrumented}");
            }

            // SHARPFUZZ_REPEAT=n runs each input n times in this process and reports how many map
            // entries (in AFL's hit-count buckets) differ between runs: a stability check that
            // doesn't involve AFL.
            if (int.TryParse(Environment.GetEnvironmentVariable("SHARPFUZZ_REPEAT"), out int repeat) && repeat > 1)
            {
                foreach (string file in args.Skip(2))
                {
                    byte[] data = File.ReadAllBytes(file);
                    byte[]? previous = null;
                    var diffs = new List<string>();
                    var unstable = new HashSet<int>();
                    for (int run = 0; run < repeat; run++)
                    {
                        byte[] map = RunOnce(target, data);
                        if (previous is not null)
                        {
                            int differing = 0;
                            for (int i = 0; i < map.Length; i++)
                            {
                                if (Bucket(map[i]) != Bucket(previous[i]))
                                {
                                    differing++;
                                    if (run >= 2)
                                    {
                                        unstable.Add(i);
                                    }
                                }
                            }

                            diffs.Add(differing.ToString());
                        }

                        previous = map;
                    }

                    int covered = previous!.Count(b => b != 0);
                    Console.WriteLine($"{file}: {covered} entries; differing from previous run: {string.Join(" ", diffs)}; unstable after warm-up: {unstable.Count} ({100.0 * (covered - unstable.Count) / Math.Max(1, covered):F1}% stable)");
                }

                return 0;
            }

            int failures = 0;
            foreach (string file in args.Skip(2))
            {
                byte[] data = File.ReadAllBytes(file);
                unsafe
                {
                    new Span<byte>(SharpFuzz.Common.Trace.SharedMem, 1 << 16).Clear();
                }

                CoreLibTrace.Enter();
                try
                {
                    target(data);
                    Console.WriteLine($"OK    {file}{(showCoverage ? $" ({CoveredEntries()} map entries)" : "")}");
                }
                catch (Exception e)
                {
                    failures++;
                    Console.WriteLine($"CRASH {file}");
                    Console.WriteLine(e);
                }
                finally
                {
                    CoreLibTrace.Leave();
                }
            }
            return failures == 0 ? 0 : 1;
        }

        Fuzzer.OutOfProcess.Run(stream =>
        {
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            byte[] data = ms.ToArray();
            SelfTest(data);
            if (s_warmup)
            {
                CoreLibTrace.RunWithWarmup(target, data);
            }
            else
            {
                CoreLibTrace.Run(target, data);
            }
        });
        return 0;
    }

    private static unsafe byte[] RunOnce(ReadOnlySpanAction target, byte[] data)
    {
        var map = new Span<byte>(SharpFuzz.Common.Trace.SharedMem, 1 << 16);
        map.Clear();
        try
        {
            if (s_warmup)
            {
                CoreLibTrace.RunWithWarmup(target, data);
            }
            else
            {
                CoreLibTrace.Run(target, data);
            }
        }
        catch (Exception)
        {
        }

        return map.ToArray();
    }

    // AFL's hit-count classes: 0, 1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+.
    private static int Bucket(byte count) => count switch
    {
        0 => 0, 1 => 1, 2 => 2, 3 => 3, < 8 => 4, < 16 => 5, < 32 => 6, < 128 => 7, _ => 8,
    };

    private static unsafe int CoveredEntries()
    {
        var map = new ReadOnlySpan<byte>(SharpFuzz.Common.Trace.SharedMem, 1 << 16);
        return map.Length - map.Count((byte)0);
    }

    // SHARPFUZZ_WARMUP=1: run every input twice and record only the second run (see
    // CoreLibTrace.RunWithWarmup). Worth ~5 points of AFL stability on the CoreLib targets but
    // costs ~40% of the exec rate, so it's off by default.
    private static readonly bool s_warmup = Environment.GetEnvironmentVariable("SHARPFUZZ_WARMUP") == "1";

    // With SHARPFUZZ_HARNESS_SELFTEST set, inputs starting with "CRASHME" throw,
    // which proves the crash reporting path works end to end.
    private static readonly bool s_selfTest = Environment.GetEnvironmentVariable("SHARPFUZZ_HARNESS_SELFTEST") is not null;

    private static void SelfTest(byte[] data)
    {
        if (s_selfTest && data.AsSpan().StartsWith("CRASHME"u8))
        {
            throw new InvalidOperationException("Harness self-test crash.");
        }

        // "GUARDME": read one byte past a guarded buffer, which must kill the process (checks that
        // Guarded's fault reaches AFL as a crash).
        if (s_selfTest && data.AsSpan().StartsWith("GUARDME"u8))
        {
            ReadOnlySpan<byte> guarded = Guarded.Copy<byte>(data, atStart: false);
            byte past = System.Runtime.CompilerServices.Unsafe.Add(ref System.Runtime.InteropServices.MemoryMarshal.GetReference(guarded), guarded.Length);
            Console.WriteLine($"Guard page not hit (read {past})");
        }
    }
}

/// <summary>Thrown when two code paths that must agree produce different results.</summary>
public sealed class ConsistencyException(string message) : Exception(message);
