#nullable disable warnings
using System.Threading.Channels;

namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Threading.Channels (bounded in every full mode, unbounded, prioritized) against a queue model, single-threaded.</summary>
/// <remarks>
/// Input layout:
///   byte 0     channel kind: 0-3 bounded with FullMode Wait / DropNewest / DropOldest / DropWrite, 4 unbounded,
///              5 unbounded prioritized; byte 1 capacity
///   rest       operations: an opcode byte and an operand byte each
/// Checks: TryWrite / TryRead / TryPeek / Count and the itemDropped callback follow the model of each
/// full mode; a pending ReadAsync is completed by the next write with that item; a pending WriteAsync
/// (Wait mode) completes when a read makes room and its item is then queued; after TryComplete the
/// channel drains and Completion completes.
/// </remarks>
public static class ChannelsTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        int kind = input.Byte() % 6;
        int capacity = 1 + input.Byte() % 5;
        var dropped = new List<int>();
        Channel<int> channel = kind switch
        {
            < 4 => Channel.CreateBounded<int>(new BoundedChannelOptions(capacity) { FullMode = (BoundedChannelFullMode)kind, SingleReader = (capacity & 1) != 0 }, dropped.Add),
            4 => Channel.CreateUnbounded<int>(new UnboundedChannelOptions { SingleReader = (capacity & 1) != 0 }),
            _ => Channel.CreateUnboundedPrioritized<int>(),
        };
        bool bounded = kind < 4;
        var model = new List<int>();
        var expectedDropped = new List<int>();
        ValueTask<int>? pendingRead = null;
        ValueTask? pendingWrite = null;
        int pendingItem = 0;
        bool completed = false;
        var log = new List<string>();
        for (int step = 0; input.Remaining > 0 && step < 64; step++)
        {
            byte op = input.Byte();
            int x = (sbyte)input.Byte();
            log.Add($"{op % 8}({x})");
            string what = $"{(kind < 4 ? $"bounded({capacity}, {(BoundedChannelFullMode)kind})" : kind == 4 ? "unbounded" : "prioritized")} ops [{string.Join(" ", log)}]";
            switch (op % 8)
            {
                case 0 or 1:
                {
                    if (pendingRead is { } read)
                    {
                        // A waiting reader takes the item directly.
                        bool ok = channel.Writer.TryWrite(x);
                        Check.Equal(!completed, ok, $"TryWrite({x}) with a pending read: {what}");
                        if (ok)
                        {
                            Check.That(read.IsCompleted && read.Result == x, $"pending ReadAsync not completed with {x}: {what}");
                            pendingRead = null;
                        }

                        break;
                    }

                    bool full = bounded && model.Count >= capacity;
                    bool expected = !completed && (!full || kind != (int)BoundedChannelFullMode.Wait) && pendingWrite is null;
                    bool wrote = channel.Writer.TryWrite(x);
                    if (pendingWrite is not null && !completed && full)
                    {
                        expected = kind != (int)BoundedChannelFullMode.Wait;
                    }

                    Check.Equal(expected, wrote, $"TryWrite({x}): {what}");
                    if (wrote)
                    {
                        Add(x);
                    }

                    break;
                }

                case 2:
                {
                    bool ok = channel.Reader.TryRead(out int item);
                    Check.Equal(model.Count > 0, ok, $"TryRead: {what}");
                    if (ok)
                    {
                        int expected = kind == 5 ? model.Min() : model[0];
                        Check.Equal(expected, item, $"TryRead item: {what}");
                        model.Remove(expected);
                        CompletePendingWrite(what);
                    }

                    break;
                }

                case 3:
                {
                    bool ok = channel.Reader.TryPeek(out int item);
                    Check.Equal(model.Count > 0, ok, $"TryPeek: {what}");
                    Check.That(!ok || item == (kind == 5 ? model.Min() : model[0]), $"TryPeek item {item}: {what}");
                    break;
                }

                case 4:
                    if (pendingRead is null && pendingWrite is null && !completed && model.Count == 0)
                    {
                        ValueTask<int> read = channel.Reader.ReadAsync();
                        Check.That(!read.IsCompleted, $"ReadAsync on an empty channel completed: {what}");
                        pendingRead = read;
                    }
                    else if (pendingRead is null && model.Count > 0)
                    {
                        ValueTask<int> read = channel.Reader.ReadAsync();
                        int expected = kind == 5 ? model.Min() : model[0];
                        Check.That(read.IsCompleted && read.Result == expected, $"ReadAsync with items queued: {what}");
                        model.Remove(expected);
                        CompletePendingWrite(what);
                    }

                    break;
                case 5:
                    if (pendingWrite is null && pendingRead is null && !completed)
                    {
                        ValueTask write = channel.Writer.WriteAsync(x);
                        bool blocks = bounded && kind == (int)BoundedChannelFullMode.Wait && model.Count >= capacity;
                        Check.Equal(!blocks, write.IsCompleted, $"WriteAsync({x}) completed: {what}");
                        if (blocks)
                        {
                            pendingWrite = write;
                            pendingItem = x;
                        }
                        else
                        {
                            Add(x);
                        }
                    }

                    break;
                case 6:
                    if (channel.Reader.CanCount)
                    {
                        Check.Equal(model.Count, channel.Reader.Count, $"Count: {what}");
                    }

                    break;
                default:
                {
                    bool first = !completed;
                    Check.Equal(first, channel.Writer.TryComplete(), $"TryComplete: {what}");
                    completed = true;
                    if (pendingRead is { } read)
                    {
                        Check.That(read.IsCompleted && read.IsFaulted, $"pending ReadAsync not failed by TryComplete: {what}");
                        _ = read.AsTask().Exception;
                        pendingRead = null;
                    }

                    if (pendingWrite is { } write)
                    {
                        Check.That(write.IsCompleted && write.IsFaulted, $"pending WriteAsync not failed by TryComplete: {what}");
                        _ = write.AsTask().Exception;
                        pendingWrite = null;
                    }

                    break;
                }
            }

            Check.That(dropped.SequenceEqual(expectedDropped), $"itemDropped [{string.Join(",", dropped)}], expected [{string.Join(",", expectedDropped)}]: {what}");
            Check.Equal(completed && model.Count == 0, channel.Reader.Completion.IsCompleted, $"Completion.IsCompleted: {what}");
        }

        void Add(int item)
        {
            if (bounded && model.Count >= capacity)
            {
                switch ((BoundedChannelFullMode)kind)
                {
                    case BoundedChannelFullMode.DropNewest:
                        expectedDropped.Add(model[^1]);
                        model.RemoveAt(model.Count - 1);
                        break;
                    case BoundedChannelFullMode.DropOldest:
                        expectedDropped.Add(model[0]);
                        model.RemoveAt(0);
                        break;
                    case BoundedChannelFullMode.DropWrite:
                        expectedDropped.Add(item);
                        return;
                }
            }

            model.Add(item);
        }

        void CompletePendingWrite(string what)
        {
            if (pendingWrite is { } write)
            {
                Check.That(write.IsCompleted, $"pending WriteAsync not completed after a read made room: {what}");
                pendingWrite = null;
                model.Add(pendingItem);
            }
        }
    }
}
