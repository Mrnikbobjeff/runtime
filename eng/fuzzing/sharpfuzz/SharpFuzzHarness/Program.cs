using SharpFuzz;

namespace SharpFuzzHarness;

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("usage: SharpFuzzHarness <regex|json> [--repro <file>...]");
            return 2;
        }

        ReadOnlySpanAction target = args[0] switch
        {
            "regex" => RegexTarget.Run,
            "json" => JsonTarget.Run,
            _ => throw new ArgumentException($"Unknown target '{args[0]}'."),
        };

        if (args.Length > 1 && args[1] == "--repro")
        {
            // Replay inputs directly (no AFL) and print full exception details. The instrumented
            // framework assemblies write coverage into Trace.SharedMem, so give them a scratch buffer.
            unsafe
            {
                SharpFuzz.Common.Trace.SharedMem = (byte*)System.Runtime.InteropServices.NativeMemory.AllocZeroed(1 << 16);
            }

            int failures = 0;
            foreach (string file in args.Skip(2))
            {
                try
                {
                    target(File.ReadAllBytes(file));
                    Console.WriteLine($"OK    {file}");
                }
                catch (Exception e)
                {
                    failures++;
                    Console.WriteLine($"CRASH {file}");
                    Console.WriteLine(e);
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
            target(data);
        });
        return 0;
    }

    // With SHARPFUZZ_HARNESS_SELFTEST set, inputs starting with "CRASHME" throw,
    // which proves the crash reporting path works end to end.
    private static readonly bool s_selfTest = Environment.GetEnvironmentVariable("SHARPFUZZ_HARNESS_SELFTEST") is not null;

    private static void SelfTest(byte[] data)
    {
        if (s_selfTest && data.AsSpan().StartsWith("CRASHME"u8))
        {
            throw new InvalidOperationException("Harness self-test crash.");
        }
    }
}

/// <summary>Thrown when two code paths that must agree produce different results.</summary>
public sealed class ConsistencyException(string message) : Exception(message);
