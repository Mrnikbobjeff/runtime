#nullable disable warnings
using System.Collections;
using System.Reflection;
using System.Resources;

namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Resources.ResourceReader and RuntimeResourceSet on raw .resources files.</summary>
/// <remarks>
/// Input: the bytes of a .resources file (seeds are generated with ResourceWriter).
/// Corrupt files may only fail with the exceptions ResourceReader documents for bad data
/// (BadImageFormatException, EndOfStreamException, ArgumentException for a stream that isn't a
/// resource file, NotSupportedException for types that need a deserializer, FormatException).
/// Checks: enumeration, GetResourceData, RuntimeResourceSet (the hash-based lookup that
/// ResourceManager uses) and ResourceSet agree on every key and value.
/// </remarks>
public static class ResourcesTarget
{
    private static readonly ConstructorInfo? s_runtimeResourceSet = typeof(ResourceReader).Assembly
        .GetType("System.Resources.RuntimeResourceSet")?
        .GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance)
        .FirstOrDefault(c => c.GetParameters() is [{ ParameterType: var p }, ..] && p == typeof(Stream));

    private static bool IsBadData(Exception e) =>
        e is BadImageFormatException or EndOfStreamException or FormatException or NotSupportedException ||
        e.GetType() == typeof(ArgumentException);

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length > 1 << 16)
        {
            return;
        }

        byte[] bytes = data.ToArray();
        var entries = new List<(string Key, object? Value)>();
        try
        {
            using var reader = new ResourceReader(new MemoryStream(bytes, writable: false));
            IDictionaryEnumerator e = reader.GetEnumerator();
            while (e.MoveNext())
            {
                string key = (string)e.Key;
                object? value = e.Value;
                Check.That(e.Entry.Key.Equals(key), $"ResourceReader enumerator Entry.Key != Key for {Check.Show(key)}");
                reader.GetResourceData(key, out string type, out byte[] resourceData);
                _ = type.Length + resourceData.Length;
                entries.Add((key, value));
            }
        }
        catch (Exception e) when (Unwrap(e) is var inner && IsBadData(inner))
        {
            return;
        }

        if (entries.Count == 0 || entries.Select(x => x.Key).Distinct().Count() != entries.Count)
        {
            return; // Lookups are only well-defined for unique keys.
        }

        // The same file through RuntimeResourceSet (ResourceManager's lazy, hash-ordered lookup)
        // and ResourceSet (which reads everything into a Hashtable up front).
        try
        {
            using var runtimeSet = (ResourceSet)s_runtimeResourceSet!.Invoke([new MemoryStream(bytes, writable: false), .. Enumerable.Repeat<object?>(false, s_runtimeResourceSet.GetParameters().Length - 1)]);
            using var resourceSet = new ResourceSet(new MemoryStream(bytes, writable: false));
            foreach (var (key, value) in entries)
            {
                object? fromRuntime = runtimeSet.GetObject(key);
                object? fromRuntimeIgnoreCase = runtimeSet.GetObject(key, ignoreCase: true);
                object? fromSet = resourceSet.GetObject(key);
                string what = $"key {Check.Show(key)} (value {Check.Show(value)})";
                Check.That(Same(value, fromRuntime), $"RuntimeResourceSet.GetObject gave {Check.Show(fromRuntime)} for {what}");
                Check.That(Same(value, fromSet), $"ResourceSet.GetObject gave {Check.Show(fromSet)} for {what}");
                Check.That(fromRuntimeIgnoreCase is not null || value is null, $"RuntimeResourceSet.GetObject(ignoreCase) found nothing for {what}");
                if (value is string s)
                {
                    Check.Equal(s, runtimeSet.GetString(key), $"RuntimeResourceSet.GetString for {what}");
                }
            }

            var enumerated = new List<string>();
            IDictionaryEnumerator runtimeEnum = runtimeSet.GetEnumerator();
            while (runtimeEnum.MoveNext())
            {
                enumerated.Add((string)runtimeEnum.Key);
            }

            Check.That(enumerated.Order(StringComparer.Ordinal).SequenceEqual(entries.Select(x => x.Key).Order(StringComparer.Ordinal)), "RuntimeResourceSet enumeration keys differ from ResourceReader's");
        }
        catch (Exception e) when (IsBadData(Unwrap(e)))
        {
            // Values are read lazily, so corruption that enumeration skipped over (e.g. in the
            // name hash table) may only show up here.
        }
    }

    private static Exception Unwrap(Exception e) => e is TargetInvocationException { InnerException: { } inner } ? inner : e;

    private static bool Same(object? a, object? b) => a switch
    {
        null => b is null,
        byte[] x => b is byte[] y && x.AsSpan().SequenceEqual(y),
        MemoryStream x => b is MemoryStream y && x.ToArray().AsSpan().SequenceEqual(y.ToArray()),
        UnmanagedMemoryStream x => b is UnmanagedMemoryStream y && x.Length == y.Length,
        _ => a.Equals(b),
    };
}
