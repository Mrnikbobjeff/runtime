#nullable disable warnings
using System.Collections.Frozen;
using System.Collections.Immutable;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// Fuzzes System.Collections.Frozen (whose constructors pick a specialized implementation from an
/// analysis of the keys), System.Collections.Immutable and OrderedDictionary against
/// Dictionary / HashSet / SortedDictionary / List references.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     mode (see <see cref="Run"/>)
///   byte 1     number of keys
///   rest       keys, then probes: '\0'-separated UTF-8 strings (string modes), little-endian
///              integers (integer modes), or operations (sequence modes)
/// Frozen: Count, every key's value, ContainsKey/TryGetValue/GetValueRefOrNullRef for keys and
/// probes (including case-flipped keys, prefixes and suffixes), Keys/Values/enumeration, and the
/// FrozenSet set predicates must match the references. Sequences: every operation's result and
/// the final contents must match.
/// </remarks>
public static class CollectionsTarget
{
    private const int MaxInput = 8192;

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length > MaxInput)
        {
            return;
        }

        var input = new FuzzInput(data);
        byte mode = input.Byte();
        int count = input.Byte();
        switch (mode % 7)
        {
            case 0: FrozenStrings(ref input, count, StringComparer.Ordinal); break;
            case 1: FrozenStrings(ref input, count, StringComparer.OrdinalIgnoreCase); break;
            case 2: FrozenIntegers<int>(ref input, count, sizeof(int)); break;
            case 3: FrozenIntegers<long>(ref input, count, sizeof(long)); break;
            case 4: ImmutableDictionaries(ref input); break;
            case 5: OrderedDictionaries(ref input); break;
            default: ImmutableLists(ref input); break;
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Frozen collections

    private static void FrozenStrings(ref FuzzInput input, int count, StringComparer comparer)
    {
        var keys = new List<string>();
        for (int i = 0; i < count && input.Remaining > 0; i++)
        {
            keys.Add(input.Segment());
        }

        var probes = new List<string>();
        while (input.Remaining > 0)
        {
            probes.Add(input.Segment());
        }

        // Derived probes: the frozen implementations hash substrings, compare lengths and special-case
        // ASCII, so near misses of real keys are the interesting ones.
        foreach (string k in keys)
        {
            probes.Add(FlipAsciiCase(k));
            probes.Add(k.ToUpperInvariant());
            if (k.Length > 0)
            {
                probes.Add(k[1..]);
                probes.Add(k[..^1]);
                probes.Add(k[..^1] + (char)(k[^1] + 1));
                probes.Add((char)(k[0] ^ 0x20) + k[1..]);
            }

            probes.Add(k + "x");
        }

        CheckFrozen(keys, probes, comparer, s => Check.Show(s));
    }

    private static string FlipAsciiCase(string s) =>
        string.Create(s.Length, s, (dst, src) =>
        {
            for (int i = 0; i < src.Length; i++)
            {
                dst[i] = char.IsAsciiLetter(src[i]) ? (char)(src[i] ^ 0x20) : src[i];
            }
        });

    private static void FrozenIntegers<T>(ref FuzzInput input, int count, int size)
        where T : struct, System.Numerics.IBinaryInteger<T>
    {
        var keys = new List<T>();
        for (int i = 0; i < count && input.Remaining >= 1; i++)
        {
            // Mostly small values (dense ranges trigger special implementations), sometimes full-width.
            byte tag = input.Byte();
            keys.Add((tag & 0x80) != 0 ? T.ReadLittleEndian(input.Bytes(size), isUnsigned: false) : T.CreateTruncating((sbyte)tag));
        }

        var probes = new List<T>();
        while (input.Remaining > 0)
        {
            byte tag = input.Byte();
            probes.Add((tag & 0x80) != 0 ? T.ReadLittleEndian(input.Bytes(size), isUnsigned: false) : T.CreateTruncating((sbyte)tag));
        }

        foreach (T k in keys.ToArray())
        {
            probes.Add(k + T.One);
            probes.Add(k - T.One);
            probes.Add(-k);
        }

        CheckFrozen(keys, probes, EqualityComparer<T>.Default, v => v.ToString());
    }

    private static void CheckFrozen<T>(List<T> keys, List<T> probes, IEqualityComparer<T> comparer, Func<T, string> show)
    {
        // Reference: first occurrence of each key (by the comparer) wins, value = its index.
        var reference = new Dictionary<T, int>(comparer);
        for (int i = 0; i < keys.Count; i++)
        {
            reference.TryAdd(keys[i], i);
        }

        string what = $"{typeof(T).Name} keys [{string.Join(", ", keys.Take(20).Select(show))}{(keys.Count > 20 ? $", ... ({keys.Count})" : "")}] ({comparer.GetType().Name})";
        FrozenDictionary<T, int> frozen = reference.ToFrozenDictionary(comparer);
        FrozenSet<T> set = reference.Keys.ToFrozenSet(comparer);
        string impl = $"{frozen.GetType().Name}/{set.GetType().Name}";
        what += $" as {impl}";

        Check.Equal(reference.Count, frozen.Count, $"FrozenDictionary.Count for {what}");
        Check.Equal(reference.Count, set.Count, $"FrozenSet.Count for {what}");
        foreach (var (key, value) in reference)
        {
            Check.That(frozen.TryGetValue(key, out int v) && v == value, $"FrozenDictionary.TryGetValue({show(key)}) misses a key for {what}");
            Check.That(set.Contains(key), $"FrozenSet.Contains({show(key)}) misses a key for {what}");
            Check.That(set.TryGetValue(key, out T actual) && comparer.Equals(actual, key), $"FrozenSet.TryGetValue({show(key)}) for {what}");
        }

        foreach (T probe in probes)
        {
            bool expected = reference.TryGetValue(probe, out int expectedValue);
            bool found = frozen.TryGetValue(probe, out int value);
            Check.That(found == expected && (!found || value == expectedValue), $"FrozenDictionary.TryGetValue({show(probe)}) = {found}/{value}, reference {expected}/{expectedValue}, for {what}");
            Check.Equal(expected, frozen.ContainsKey(probe), $"FrozenDictionary.ContainsKey({show(probe)}) for {what}");
            Check.Equal(expected, !System.Runtime.CompilerServices.Unsafe.IsNullRef(in frozen.GetValueRefOrNullRef(probe)), $"FrozenDictionary.GetValueRefOrNullRef({show(probe)}) for {what}");
            Check.Equal(expected, set.Contains(probe), $"FrozenSet.Contains({show(probe)}) for {what}");
        }

        // Enumeration: Keys, Values and pairs are consistent and cover the reference exactly.
        var enumerated = frozen.ToList();
        Check.That(enumerated.Count == reference.Count && enumerated.All(p => reference.TryGetValue(p.Key, out int v) && v == p.Value), $"FrozenDictionary enumeration differs for {what}");
        Check.That(frozen.Keys.Length == reference.Count && frozen.Values.Length == reference.Count &&
                   frozen.Keys.AsEnumerable().Zip(frozen.Values.AsEnumerable()).All(p => reference[p.First] == p.Second), $"FrozenDictionary Keys/Values out of step for {what}");
        Check.That(set.Items.Length == reference.Count && set.Items.All(reference.ContainsKey), $"FrozenSet.Items differs for {what}");

        // Set predicates against HashSet.
        var other = new HashSet<T>(probes.Take(8).Concat(reference.Keys.Take(reference.Count / 2)), comparer);
        var hs = new HashSet<T>(reference.Keys, comparer);
        Check.Equal(hs.SetEquals(other), set.SetEquals(other), $"FrozenSet.SetEquals for {what}");
        Check.Equal(hs.Overlaps(other), set.Overlaps(other), $"FrozenSet.Overlaps for {what}");
        Check.Equal(hs.IsSubsetOf(other), set.IsSubsetOf(other), $"FrozenSet.IsSubsetOf for {what}");
        Check.Equal(hs.IsSupersetOf(other), set.IsSupersetOf(other), $"FrozenSet.IsSupersetOf for {what}");
        Check.Equal(hs.IsProperSubsetOf(other), set.IsProperSubsetOf(other), $"FrozenSet.IsProperSubsetOf for {what}");
        Check.Equal(hs.IsProperSupersetOf(other), set.IsProperSupersetOf(other), $"FrozenSet.IsProperSupersetOf for {what}");
    }

    // ---------------------------------------------------------------------------------------------
    // Operation sequences

    private static void ImmutableDictionaries(ref FuzzInput input)
    {
        var reference = new SortedDictionary<int, int>();
        ImmutableDictionary<int, int> hashed = ImmutableDictionary<int, int>.Empty;
        ImmutableSortedDictionary<int, int> sorted = ImmutableSortedDictionary<int, int>.Empty;
        ImmutableDictionary<int, int>.Builder builder = ImmutableDictionary.CreateBuilder<int, int>();
        var log = new StringBuilder();
        while (input.Remaining > 0)
        {
            byte op = input.Byte();
            int key = (sbyte)input.Byte();
            int value = input.Byte();
            log.Append($"{op % 5}:{key}:{value} ");
            switch (op % 5)
            {
                case 0:
                    reference[key] = value;
                    hashed = hashed.SetItem(key, value);
                    sorted = sorted.SetItem(key, value);
                    builder[key] = value;
                    break;
                case 1:
                    bool removed = reference.Remove(key);
                    Check.Equal(removed, hashed.ContainsKey(key), $"ImmutableDictionary.ContainsKey before Remove after {log}");
                    hashed = hashed.Remove(key);
                    sorted = sorted.Remove(key);
                    Check.Equal(removed, builder.Remove(key), $"ImmutableDictionary.Builder.Remove after {log}");
                    break;
                case 2:
                    // Bulk: SetItems / RemoveRange with keys derived from this one.
                    var items = Enumerable.Range(0, value % 9).Select(i => new KeyValuePair<int, int>(key + i * 3, value + i)).ToArray();
                    foreach (var kv in items)
                    {
                        reference[kv.Key] = kv.Value;
                        builder[kv.Key] = kv.Value;
                    }

                    hashed = hashed.SetItems(items);
                    sorted = sorted.SetItems(items);
                    break;
                case 3:
                    int[] remove = Enumerable.Range(0, value % 7).Select(i => key - i * 2).ToArray();
                    foreach (int k in remove)
                    {
                        reference.Remove(k);
                        builder.Remove(k);
                    }

                    hashed = hashed.RemoveRange(remove);
                    sorted = sorted.RemoveRange(remove);
                    break;
                default:
                    ImmutableDictionary<int, int> built = builder.ToImmutable();
                    Check.That(built.Count == reference.Count && built.All(kv => reference.TryGetValue(kv.Key, out int v) && v == kv.Value), $"Builder.ToImmutable differs after {log}");
                    break;
            }

            Check.Equal(reference.Count, hashed.Count, $"ImmutableDictionary.Count after {log}");
            Check.Equal(reference.Count, sorted.Count, $"ImmutableSortedDictionary.Count after {log}");
            Check.Equal(reference.Count, builder.Count, $"ImmutableDictionary.Builder.Count after {log}");
            Check.That(hashed.TryGetValue(key, out int hv) == reference.TryGetValue(key, out int rv) && hv == rv, $"ImmutableDictionary.TryGetValue({key}) after {log}");
        }

        Check.That(sorted.Keys.SequenceEqual(reference.Keys) && sorted.Values.SequenceEqual(reference.Values), $"ImmutableSortedDictionary contents/order differ after {log}");
        Check.That(hashed.OrderBy(kv => kv.Key).SequenceEqual(reference), $"ImmutableDictionary contents differ after {log}");
    }

    private static void OrderedDictionaries(ref FuzzInput input)
    {
        var reference = new List<KeyValuePair<int, int>>();
        var dict = new OrderedDictionary<int, int>();
        var log = new StringBuilder();
        while (input.Remaining > 0)
        {
            byte op = input.Byte();
            int key = (sbyte)input.Byte();
            int value = input.Byte();
            int index = reference.Count == 0 ? 0 : value % (reference.Count + 1);
            int existing = reference.FindIndex(kv => kv.Key == key);
            log.Append($"{op % 7}:{key}:{value} ");
            switch (op % 7)
            {
                case 0:
                    Check.Equal(existing < 0, dict.TryAdd(key, value), $"OrderedDictionary.TryAdd after {log}");
                    if (existing < 0)
                    {
                        reference.Add(new(key, value));
                    }

                    break;
                case 1:
                    if (existing < 0)
                    {
                        dict.Insert(index, key, value);
                        reference.Insert(index, new(key, value));
                    }
                    else
                    {
                        Check.That(Throws(() => dict.Insert(index, key, value)), $"OrderedDictionary.Insert of an existing key didn't throw after {log}");
                    }

                    break;
                case 2:
                    Check.Equal(existing >= 0, dict.Remove(key), $"OrderedDictionary.Remove after {log}");
                    if (existing >= 0)
                    {
                        reference.RemoveAt(existing);
                    }

                    break;
                case 3:
                    if (reference.Count > 0)
                    {
                        int at = value % reference.Count;
                        dict.RemoveAt(at);
                        reference.RemoveAt(at);
                    }

                    break;
                case 4:
                    dict[key] = value;
                    if (existing >= 0)
                    {
                        reference[existing] = new(key, value);
                    }
                    else
                    {
                        reference.Add(new(key, value));
                    }

                    break;
                case 5:
                    if (reference.Count > 0)
                    {
                        int at = value % reference.Count;
                        dict.SetAt(at, value + 1);
                        reference[at] = new(reference[at].Key, value + 1);
                    }

                    break;
                default:
                    Check.Equal(existing, dict.IndexOf(key), $"OrderedDictionary.IndexOf({key}) after {log}");
                    break;
            }

            Check.That(dict.Count == reference.Count && dict.SequenceEqual(reference), $"OrderedDictionary contents differ after {log}");
            Check.That(dict.TryGetValue(key, out int v) == (reference.FindIndex(kv => kv.Key == key) is var i && i >= 0) && (i < 0 || v == reference[i].Value),
                $"OrderedDictionary.TryGetValue({key}) after {log}");
        }
    }

    private static void ImmutableLists(ref FuzzInput input)
    {
        var reference = new List<int>();
        ImmutableList<int> list = ImmutableList<int>.Empty;
        ImmutableArray<int> array = ImmutableArray<int>.Empty;
        var log = new StringBuilder();
        while (input.Remaining > 0)
        {
            byte op = input.Byte();
            int value = (sbyte)input.Byte();
            int index = reference.Count == 0 ? 0 : (value & 0x7F) % (reference.Count + 1);
            log.Append($"{op % 8}:{value} ");
            switch (op % 8)
            {
                case 0: reference.Add(value); list = list.Add(value); array = array.Add(value); break;
                case 1: reference.Insert(index, value); list = list.Insert(index, value); array = array.Insert(index, value); break;
                case 2:
                    if (reference.Count > 0)
                    {
                        int at = index % reference.Count;
                        reference.RemoveAt(at); list = list.RemoveAt(at); array = array.RemoveAt(at);
                    }

                    break;
                case 3:
                {
                    int n = Math.Min(value & 7, reference.Count - index);
                    reference.RemoveRange(index, n); list = list.RemoveRange(index, n); array = array.RemoveRange(index, n);
                    break;
                }

                case 4:
                {
                    int[] items = Enumerable.Range(value, value & 7).ToArray();
                    reference.InsertRange(index, items); list = list.InsertRange(index, items); array = array.InsertRange(index, items);
                    break;
                }

                case 5: reference.Sort(); list = list.Sort(); array = array.Sort(); break;
                case 6:
                    reference.Reverse(); list = list.Reverse(); array = ImmutableArray.CreateRange(array.Reverse());
                    break;
                default:
                    Check.Equal(reference.IndexOf(value), list.IndexOf(value), $"ImmutableList.IndexOf({value}) after {log}");
                    Check.Equal(reference.LastIndexOf(value), list.LastIndexOf(value), $"ImmutableList.LastIndexOf({value}) after {log}");
                    Check.Equal(reference.IndexOf(value), array.IndexOf(value), $"ImmutableArray.IndexOf({value}) after {log}");
                    if (IsSorted(reference))
                    {
                        int r = reference.BinarySearch(value), l = list.BinarySearch(value);
                        Check.That(r >= 0 ? l >= 0 && reference[l] == value : l == r, $"ImmutableList.BinarySearch({value}) = {l}, List {r}, after {log}");
                    }

                    break;
            }

            Check.That(list.SequenceEqual(reference), $"ImmutableList contents differ after {log}");
            Check.That(array.SequenceEqual(reference), $"ImmutableArray contents differ after {log}");
        }
    }

    private static bool IsSorted(List<int> values)
    {
        for (int i = 1; i < values.Count; i++)
        {
            if (values[i - 1] > values[i])
            {
                return false;
            }
        }

        return true;
    }

    private static bool Throws(Action action)
    {
        try
        {
            action();
            return false;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }
}
