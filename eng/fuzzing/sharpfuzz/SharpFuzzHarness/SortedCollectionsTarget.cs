#nullable disable warnings
namespace SharpFuzzHarness;

/// <summary>
/// Fuzzes System.Collections SortedSet&lt;T&gt; (including views from GetViewBetween, which are
/// live windows onto the set) and PriorityQueue&lt;TElement, TPriority&gt; against simple models.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     0x01: PriorityQueue, otherwise SortedSet
///   rest       operations: an opcode byte and two operand bytes each
/// Checks (SortedSet): after every operation, on the set or on a view, the set holds the model's
/// elements in order; every view holds exactly the elements in its range, with the right Count,
/// Min and Max; adding outside a view's range throws ArgumentOutOfRangeException; the set
/// operations (UnionWith, IntersectWith, ExceptWith, SymmetricExceptWith through a view only touch
/// its range) and predicates (IsSubsetOf, Overlaps, SetEquals, ...) agree with the model.
/// (PriorityQueue): dequeued priorities come out in order, the element is one enqueued with that
/// priority, Remove / EnqueueDequeue / DequeueEnqueue / EnqueueRange match the model, and
/// UnorderedItems holds exactly the queued pairs.
/// </remarks>
public static class SortedCollectionsTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        if ((input.Byte() & 1) != 0)
        {
            Queue(ref input);
        }
        else
        {
            Set(ref input);
        }
    }

    private static void Set(ref FuzzInput input)
    {
        var set = new SortedSet<int>();
        var model = new SortedModel();
        var views = new List<(SortedSet<int> View, int Lo, int Hi)>();
        var log = new List<string>();
        for (int step = 0; input.Remaining > 0 && step < 48; step++)
        {
            byte op = input.Byte();
            int a = (sbyte)input.Byte() % 40, b = (sbyte)input.Byte() % 40;
            int which = views.Count == 0 ? -1 : (op >> 5) % (views.Count + 1) - 1; // -1: the set itself
            SortedSet<int> target = which < 0 ? set : views[which].View;
            int lo = which < 0 ? int.MinValue : views[which].Lo, hi = which < 0 ? int.MaxValue : views[which].Hi;
            bool inRange = lo <= a && a <= hi;
            int[] other = Enumerable.Range(Math.Min(a, b), Math.Abs(a - b) + 1).Where(x => (x ^ op) % 3 != 0).ToArray();
            log.Add($"{op % 16}{(which < 0 ? "" : $"v{which}")}({a},{b})");
            string what = $"ops [{string.Join(" ", log)}], set [{string.Join(",", set)}]";
            switch (op % 16)
            {
                case 0 or 1:
                {
                    var added = Outcome<bool>.Of(() => target.Add(a), e => e is ArgumentOutOfRangeException);
                    Check.That(added.Ok == inRange, $"Add({a}) to a view of [{lo},{hi}] gave {added}: {what}");
                    if (added.Ok)
                    {
                        Check.Equal(!model.Contains(a), added.Value, $"Add({a}) result: {what}");
                        model.Add(a);
                    }

                    break;
                }

                case 2:
                    Check.Equal(inRange && model.Contains(a), target.Remove(a), $"Remove({a}): {what}");
                    if (inRange)
                    {
                        model.Remove(a);
                    }

                    break;
                case 3:
                    Check.Equal(inRange && model.Contains(a), target.Contains(a), $"Contains({a}): {what}");
                    break;
                case 4:
                {
                    int vlo = Math.Min(a, b), vhi = Math.Max(a, b);
                    var view = Outcome<SortedSet<int>>.Of(() => target.GetViewBetween(vlo, vhi), e => e is ArgumentOutOfRangeException or ArgumentException);
                    bool valid = lo <= vlo && vhi <= hi;
                    Check.That(view.Ok == valid, $"GetViewBetween({vlo},{vhi}) of [{lo},{hi}] gave {view}: {what}");
                    if (view.Ok && views.Count < 4)
                    {
                        views.Add((view.Value, vlo, vhi));
                    }

                    break;
                }

                case 5:
                {
                    // Through a view, elements outside its range throw ArgumentOutOfRangeException (as Add does).
                    bool outside = other.Any(x => x < lo || x > hi);
                    var union = Outcome<bool>.Of(() => { target.UnionWith(other); return true; }, e => e is ArgumentOutOfRangeException);
                    Check.That(union.Ok != outside, $"UnionWith through a view of [{lo},{hi}] gave {union}: {what}");
                    if (!union.Ok)
                    {
                        model = new SortedModel(set); // may be partially applied
                        break;
                    }

                    foreach (int x in other)
                    {
                        model.Add(x);
                    }

                    break;
                }
                case 6:
                    target.IntersectWith(other);
                    foreach (int x in model.Where(x => lo <= x && x <= hi && !other.Contains(x)).ToArray())
                    {
                        model.Remove(x);
                    }

                    break;
                case 7:
                    target.ExceptWith(other);
                    foreach (int x in other)
                    {
                        if (lo <= x && x <= hi)
                        {
                            model.Remove(x);
                        }
                    }

                    break;
                case 8:
                {
                    var sym = Outcome<bool>.Of(() => { target.SymmetricExceptWith(other); return true; }, e => e is ArgumentOutOfRangeException);
                    if (!sym.Ok)
                    {
                        // Elements of other outside a view's range can't be added; the documented behavior
                        // is an exception, and the set may be partially updated: resync the model.
                        model = new SortedModel(set);
                        break;
                    }

                    foreach (int x in other.Distinct())
                    {
                        if (lo <= x && x <= hi && !model.Remove(x))
                        {
                            model.Add(x);
                        }
                    }

                    break;
                }

                case 9:
                {
                    int[] mine = model.Where(x => lo <= x && x <= hi).ToArray();
                    var otherSet = new HashSet<int>(other);
                    Check.Equal(mine.All(otherSet.Contains), target.IsSubsetOf(other), $"IsSubsetOf: {what}");
                    Check.Equal(other.All(mine.Contains), target.IsSupersetOf(other), $"IsSupersetOf: {what}");
                    Check.Equal(mine.Any(otherSet.Contains), target.Overlaps(other), $"Overlaps: {what}");
                    Check.Equal(mine.Length == otherSet.Count && mine.All(otherSet.Contains), target.SetEquals(other), $"SetEquals: {what}");
                    Check.Equal(mine.All(otherSet.Contains) && mine.Length < otherSet.Count, target.IsProperSubsetOf(other), $"IsProperSubsetOf: {what}");
                    Check.Equal(other.All(mine.Contains) && otherSet.Count < mine.Length, target.IsProperSupersetOf(other), $"IsProperSupersetOf: {what}");
                    break;
                }

                case 10:
                {
                    int k = Math.Abs(a) % 5 + 1;
                    int removed = target.RemoveWhere(x => x % k == 0);
                    int expected = model.Count(x => lo <= x && x <= hi && x % k == 0);
                    Check.Equal(expected, removed, $"RemoveWhere(x % {k} == 0): {what}");
                    model.RemoveWhere(x => lo <= x && x <= hi && x % k == 0);
                    break;
                }

                case 11:
                    target.Clear();
                    model.RemoveWhere(x => lo <= x && x <= hi);
                    break;
                case 12:
                {
                    int[] copy = new int[target.Count + 2];
                    target.CopyTo(copy, 1);
                    Check.That(copy.AsSpan(1, target.Count).SequenceEqual(model.Where(x => lo <= x && x <= hi).ToArray()), $"CopyTo: {what}");
                    break;
                }

                default:
                    Check.That(target.Reverse().SequenceEqual(model.Where(x => lo <= x && x <= hi).Reverse()), $"Reverse(): {what}");
                    break;
            }

            what = $"after ops [{string.Join(" ", log)}]";
            Check.That(set.SequenceEqual(model), $"set [{string.Join(",", set)}] vs model [{string.Join(",", model)}] {what}");
            Check.Equal(model.Count, set.Count, $"Count {what}");
            foreach ((SortedSet<int> view, int vlo, int vhi) in views)
            {
                int[] expected = model.Where(x => vlo <= x && x <= vhi).ToArray();
                Check.That(view.SequenceEqual(expected), $"view [{vlo},{vhi}] = [{string.Join(",", view)}], expected [{string.Join(",", expected)}] {what}");
                Check.Equal(expected.Length, view.Count, $"view [{vlo},{vhi}] Count {what}");
                Check.Equal(expected.Length == 0 ? 0 : expected[0], view.Min, $"view [{vlo},{vhi}] Min {what}");
                Check.Equal(expected.Length == 0 ? 0 : expected[^1], view.Max, $"view [{vlo},{vhi}] Max {what}");
            }
        }
    }

    /// <summary>A sorted list of distinct ints (the reference for SortedSet).</summary>
    private sealed class SortedModel : IEnumerable<int>
    {
        private readonly List<int> _items = new();

        public SortedModel()
        {
        }

        public SortedModel(IEnumerable<int> items) => _items.AddRange(items.Distinct().Order());

        public int Count => _items.Count;

        public bool Contains(int x) => _items.BinarySearch(x) >= 0;

        public bool Add(int x)
        {
            int i = _items.BinarySearch(x);
            if (i >= 0)
            {
                return false;
            }

            _items.Insert(~i, x);
            return true;
        }

        public bool Remove(int x)
        {
            int i = _items.BinarySearch(x);
            if (i < 0)
            {
                return false;
            }

            _items.RemoveAt(i);
            return true;
        }

        public int RemoveWhere(Predicate<int> match) => _items.RemoveAll(match);

        public IEnumerator<int> GetEnumerator() => _items.GetEnumerator();

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private static void Queue(ref FuzzInput input)
    {
        var queue = new PriorityQueue<int, int>();
        var model = new List<(int Element, int Priority)>();
        var log = new List<string>();
        int next = 0;
        for (int step = 0; input.Remaining > 0 && step < 64; step++)
        {
            byte op = input.Byte();
            int p = (sbyte)input.Byte() % 16, q = (sbyte)input.Byte() % 16;
            log.Add($"{op % 10}({p},{q})");
            string what = $"ops [{string.Join(" ", log)}]";
            int minPriority = model.Count == 0 ? 0 : model.Min(m => m.Priority);
            switch (op % 10)
            {
                case 0 or 1:
                    queue.Enqueue(next, p);
                    model.Add((next++, p));
                    break;
                case 2:
                {
                    bool ok = queue.TryDequeue(out int element, out int priority);
                    Check.Equal(model.Count > 0, ok, $"TryDequeue: {what}");
                    if (ok)
                    {
                        Check.Equal(minPriority, priority, $"TryDequeue priority: {what}");
                        Check.That(model.Remove((element, priority)), $"TryDequeue returned ({element}, {priority}), which isn't queued: {what}");
                    }

                    break;
                }

                case 3:
                {
                    bool ok = queue.TryPeek(out int element, out int priority);
                    Check.Equal(model.Count > 0, ok, $"TryPeek: {what}");
                    Check.That(!ok || priority == minPriority && model.Contains((element, priority)), $"TryPeek ({element}, {priority}): {what}");
                    break;
                }

                case 4:
                {
                    // Enqueue then dequeue: the new pair comes straight back unless something queued has a lower priority.
                    int element = queue.EnqueueDequeue(next, p);
                    model.Add((next++, p));
                    int min = model.Min(m => m.Priority);
                    var match = model.FirstOrDefault(m => m.Element == element);
                    Check.That(model.Contains(match) && match.Priority == min, $"EnqueueDequeue({next - 1}, {p}) returned {element}: {what}");
                    model.Remove(match);
                    break;
                }

                case 5:
                {
                    var result = Outcome<int>.Of(() => queue.DequeueEnqueue(next, p), e => e is InvalidOperationException);
                    Check.Equal(model.Count > 0, result.Ok, $"DequeueEnqueue: {what}");
                    if (result.Ok)
                    {
                        var match = model.FirstOrDefault(m => m.Element == result.Value);
                        Check.That(model.Contains(match) && match.Priority == minPriority, $"DequeueEnqueue returned {result.Value}: {what}");
                        model.Remove(match);
                        model.Add((next++, p));
                    }

                    break;
                }

                case 6:
                {
                    int target = model.Count == 0 ? -1 : model[Math.Abs(q) % model.Count].Element;
                    bool removed = queue.Remove(target, out int element, out int priority);
                    var match = model.FirstOrDefault(m => m.Element == target);
                    Check.Equal(model.Contains(match), removed, $"Remove({target}): {what}");
                    if (removed)
                    {
                        Check.That(element == target && priority == match.Priority, $"Remove({target}) gave ({element}, {priority}): {what}");
                        model.Remove(match);
                    }

                    break;
                }

                case 7:
                {
                    int count = Math.Abs(q) % 6;
                    var items = Enumerable.Range(0, count).Select(i => (next + i, (p + i * q) % 16)).ToArray();
                    queue.EnqueueRange(items);
                    model.AddRange(items);
                    next += count;
                    break;
                }

                case 8:
                    if ((q & 1) != 0)
                    {
                        queue.Clear();
                        model.Clear();
                    }
                    else
                    {
                        queue.TrimExcess();
                    }

                    break;
                default:
                {
                    var range = Enumerable.Range(0, Math.Abs(q) % 4).Select(i => next + i).ToArray();
                    queue.EnqueueRange(range, p);
                    model.AddRange(range.Select(e => (e, p)));
                    next += range.Length;
                    break;
                }
            }

            Check.Equal(model.Count, queue.Count, $"Count after {what}");
            var unordered = queue.UnorderedItems.Select(t => (t.Element, t.Priority)).OrderBy(t => t.Element).ToArray();
            Check.That(unordered.SequenceEqual(model.OrderBy(t => t.Element)), $"UnorderedItems after {what}");
        }
    }
}
