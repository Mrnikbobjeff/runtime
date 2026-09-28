#nullable disable warnings
namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Linq.AsyncEnumerable (new in .NET 10) against System.Linq on the same operator chain.</summary>
/// <remarks>
/// Input layout:
///   byte 0     source length; then that many source bytes
///   rest       operators: an opcode byte and a parameter byte each; the last pair picks a terminal operator
/// Checks: every chain of operators gives the same elements (or throws the same exception type)
/// through IAsyncEnumerable as through IEnumerable, and so do the terminal operators; selectors are
/// alternately synchronous and ValueTask-returning.
/// </remarks>
public static class AsyncEnumTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        int[] source = input.Bytes(input.Byte() % 48).ToArray().Select(b => (int)(sbyte)b).ToArray();
        int[] other = source.Reverse().Where(x => x % 3 != 0).Take(9).ToArray();
        IEnumerable<int> sync = source;
        IAsyncEnumerable<int> async = source.ToAsyncEnumerable();
        var log = new List<string>();
        while (input.Remaining > 2 && log.Count < 8)
        {
            byte op = input.Byte();
            int p = input.Byte();
            log.Add($"{op % 34}:{p}");
            (sync, async) = Apply(op, p, sync, async, other);
        }

        string what = $"source [{string.Join(",", source)}] ops [{string.Join(" ", log)}]";
        var expected = Outcome<int[]>.Of(() => sync.ToArray(), Allowed);
        var actual = Outcome<int[]>.Of(() => Wait(async.ToArrayAsync()), Allowed);
        Check.That(expected.SameAs(actual, new Check.By<int[]>((a, b) => a.SequenceEqual(b))),
            $"IEnumerable {Show(expected)} vs IAsyncEnumerable {Show(actual)} for {what}");

        byte terminal = input.Byte();
        int q = input.Byte();
        var t1 = Outcome<long>.Of(() => Terminal(terminal, q, sync, other), Allowed);
        var t2 = Outcome<long>.Of(() => Terminal(terminal, q, async, other), Allowed);
        Check.That(t1.SameAs(t2), $"terminal {terminal % 16}({q}): IEnumerable {t1} vs IAsyncEnumerable {t2} for {what}");
    }

    private static bool Allowed(Exception e) => e is InvalidOperationException or ArgumentOutOfRangeException or ArgumentException or OverflowException or DivideByZeroException;

    private static string Show(Outcome<int[]> o) => o.Ok ? "[" + string.Join(",", o.Value) + "]" : o.ErrorType.Name;

    private static T Wait<T>(ValueTask<T> task) => task.AsTask().GetAwaiter().GetResult();

    private static ValueTask<T> V<T>(T value) => new(value);

    private static (IEnumerable<int>, IAsyncEnumerable<int>) Apply(byte op, int p, IEnumerable<int> s, IAsyncEnumerable<int> a, int[] other)
    {
        int k = 1 + p % 5;
        bool asyncSelector = (op & 0x80) != 0;
        IAsyncEnumerable<int> o = other.ToAsyncEnumerable();
        switch (op % 34)
        {
            case 0: return (s.Select(x => x * k - p), asyncSelector ? a.Select((int x, CancellationToken _) => V(x * k - p)) : a.Select(x => x * k - p));
            case 1: return (s.Select((x, i) => x + i * k), asyncSelector ? a.Select((int x, int i, CancellationToken _) => V(x + i * k)) : a.Select((int x, int i) => x + i * k));
            case 2: return (s.Where(x => x % k == 0), asyncSelector ? a.Where((int x, CancellationToken _) => V(x % k == 0)) : a.Where(x => x % k == 0));
            case 3: return (s.Where((x, i) => (x + i) % k != 0), a.Where((int x, int i) => (x + i) % k != 0));
            case 4: return (s.Take(p % 20 - 3), a.Take(p % 20 - 3));
            case 5: return (s.Skip(p % 20 - 3), a.Skip(p % 20 - 3));
            case 6: return (s.TakeLast(p % 20 - 3), a.TakeLast(p % 20 - 3));
            case 7: return (s.SkipLast(p % 20 - 3), a.SkipLast(p % 20 - 3));
            case 8: return (s.TakeWhile(x => x % k != 0), asyncSelector ? a.TakeWhile((int x, CancellationToken _) => V(x % k != 0)) : a.TakeWhile(x => x % k != 0));
            case 9: return (s.SkipWhile((x, i) => x % k != 0 && i < p), a.SkipWhile((int x, int i) => x % k != 0 && i < p));
            case 10: return (s.Distinct(), a.Distinct());
            case 11: return (s.DistinctBy(x => x % k), asyncSelector ? a.DistinctBy(x => x % k) : a.DistinctBy(x => x % k));
            case 12: return (s.OrderBy(x => x % k).ThenByDescending(x => x), a.OrderBy(x => x % k).ThenByDescending(x => x));
            case 13: return (s.OrderByDescending(x => x / k).ThenBy(x => x), asyncSelector ? a.OrderByDescending((int x, CancellationToken _) => V(x / k)).ThenBy(x => x) : a.OrderByDescending(x => x / k).ThenBy(x => x));
            case 14: return (s.Reverse(), a.Reverse());
            case 15: return (s.Concat(other), a.Concat(o));
            case 16: return (s.Zip(other, (x, y) => x * 31 + y), a.Zip(o, (x, y) => x * 31 + y));
            case 17: return (s.Chunk(k).Select(c => c.Sum() * 7 + c.Length), a.Chunk(k).Select(c => c.Sum() * 7 + c.Length));
            case 18: return (s.GroupBy(x => x % k).Select(g => g.Key * 1000 + g.Sum()), a.GroupBy(x => x % k).Select(g => g.Key * 1000 + g.Sum()));
            case 19: return (s.Join(other, x => x % k, y => y % k, (x, y) => x * 31 + y), a.Join(o, x => x % k, y => y % k, (x, y) => x * 31 + y));
            case 20: return (s.GroupJoin(other, x => x % k, y => y % k, (x, ys) => x * 31 + ys.Count()), a.GroupJoin(o, x => x % k, y => y % k, (x, ys) => x * 31 + ys.Count()));
            case 21: return (s.Union(other), a.Union(o));
            case 22: return (s.Intersect(other), a.Intersect(o));
            case 23: return (s.Except(other), a.Except(o));
            case 24: return (s.Append(p), a.Append(p));
            case 25: return (s.Prepend(-p), a.Prepend(-p));
            case 26: return (s.DefaultIfEmpty(p), a.DefaultIfEmpty(p));
            case 27: return (s.Index().Select(t => t.Index * 100 + t.Item), a.Index().Select(t => t.Index * 100 + t.Item));
            case 28: return (s.CountBy(x => x % k).Select(kv => kv.Key * 100 + kv.Value), a.CountBy(x => x % k).Select(kv => kv.Key * 100 + kv.Value));
            case 29: return (s.SelectMany(x => Enumerable.Range(0, Math.Abs(x) % k)), a.SelectMany(x => Enumerable.Range(0, Math.Abs(x) % k)));
            case 30: return (s.AggregateBy(x => x % k, 1, (acc, x) => acc * 3 + x).Select(kv => kv.Key * 1000 + kv.Value), a.AggregateBy(x => x % k, 1, (acc, x) => acc * 3 + x).Select(kv => kv.Key * 1000 + kv.Value));
            case 31: return (s.Take(new Range(new Index(p % 7, (p & 8) != 0), new Index(p / 16 % 9, (p & 128) != 0))), a.Take(new Range(new Index(p % 7, (p & 8) != 0), new Index(p / 16 % 9, (p & 128) != 0))));
            case 32: return (s.LeftJoin(other, x => x % k, y => y % k, (x, y) => x * 31 + y), a.LeftJoin(o, x => x % k, y => y % k, (x, y) => x * 31 + y));
            default: return (s.UnionBy(other, x => x % k), a.UnionBy(o, x => x % k));
        }
    }

    private static long Terminal(byte op, int q, IEnumerable<int> s, int[] other) => (op % 16) switch
    {
        0 => s.Count(),
        1 => s.Sum(x => (long)x),
        2 => s.Min(),
        3 => s.Max(),
        4 => s.Aggregate((x, y) => x * 3 + y),
        5 => s.First(x => x % 3 == 0),
        6 => s.Last(),
        7 => s.ElementAt(q % 20 - 2),
        8 => s.Single(x => x == q % 7),
        9 => s.Any(x => x > q % 50) ? 1 : 0,
        10 => s.All(x => x < q % 50) ? 1 : 0,
        11 => s.Contains(q % 50) ? 1 : 0,
        12 => s.SequenceEqual(other) ? 1 : 0,
        13 => s.MaxBy(x => x % 7),
        14 => s.ElementAtOrDefault(q % 20 - 2),
        _ => s.LastOrDefault(x => x % 5 == 0, -1),
    };

    private static long Terminal(byte op, int q, IAsyncEnumerable<int> a, int[] other) => (op % 16) switch
    {
        0 => Wait(a.CountAsync()),
        1 => Wait(a.Select(x => (long)x).SumAsync()),
        2 => Wait(a.MinAsync()),
        3 => Wait(a.MaxAsync()),
        4 => Wait(a.AggregateAsync((x, y) => x * 3 + y)),
        5 => Wait(a.FirstAsync((int x, CancellationToken _) => V(x % 3 == 0))),
        6 => Wait(a.LastAsync()),
        7 => Wait(a.ElementAtAsync(q % 20 - 2)),
        8 => Wait(a.SingleAsync(x => x == q % 7)),
        9 => Wait(a.AnyAsync(x => x > q % 50)) ? 1 : 0,
        10 => Wait(a.AllAsync(x => x < q % 50)) ? 1 : 0,
        11 => Wait(a.ContainsAsync(q % 50)) ? 1 : 0,
        12 => Wait(a.SequenceEqualAsync(other.ToAsyncEnumerable())) ? 1 : 0,
        13 => Wait(a.MaxByAsync(x => x % 7)),
        14 => Wait(a.ElementAtOrDefaultAsync(q % 20 - 2)),
        _ => Wait(a.LastOrDefaultAsync(x => x % 5 == 0, -1)),
    };
}
