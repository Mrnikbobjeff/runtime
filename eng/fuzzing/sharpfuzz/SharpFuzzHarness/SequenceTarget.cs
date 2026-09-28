#nullable disable warnings
using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Memory's ReadOnlySequence&lt;byte&gt; and SequenceReader&lt;byte&gt; over multi-segment data.</summary>
/// <remarks>
/// Input layout:
///   byte 0     data length; byte 1 segmentation pattern (segments of 0-7 bytes, or large ones)
///   data       the sequence contents
///   rest       operations: an opcode byte followed by its operands
/// Checks: every SequenceReader operation gives the same result on the segmented sequence as on a
/// single-segment one and as a plain array model, and leaves the reader at the same position;
/// ReadOnlySequence Slice / GetPosition / GetOffset / PositionOf / ToArray agree with the model.
/// </remarks>
public static class SequenceTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        int length = input.Byte();
        byte pattern = input.Byte();
        byte[] bytes = input.Bytes(length).ToArray();
        byte[] ops = input.Rest().ToArray();

        ReadOnlySequence<byte> segmented = Segment(bytes, pattern);
        var single = new ReadOnlySequence<byte>(new ReadOnlyMemory<byte>([0xEE, .. bytes, 0xEE], 1, bytes.Length));
        string what = $"data 0x{Convert.ToHexString(bytes)} segments 0x{pattern:X2} ops 0x{Convert.ToHexString(ops)}";
        Check.Equal((long)bytes.Length, segmented.Length, $"Length for {what}");
        Check.That(segmented.ToArray().AsSpan().SequenceEqual(bytes), $"ToArray for {what}");

        Sequence(segmented, bytes, ops, what);

        var a = new SequenceReader<byte>(segmented);
        var b = new SequenceReader<byte>(single);
        var model = new Model(bytes);
        var log = new StringBuilder();
        var opInput = new FuzzInput(ops);
        for (int step = 0; opInput.Remaining > 0 && step < 64; step++)
        {
            byte op = opInput.Byte();
            byte p1 = opInput.Byte(), p2 = opInput.Byte(), p3 = opInput.Byte();
            string ra = Step(ref a, op, p1, p2, p3);
            string rb = Step(ref b, op, p1, p2, p3);
            string rm = model.Step(op, p1, p2, p3);
            log.Append($"[{op % 24}:{ra}]");
            Check.That(ra == rb, $"step {step} op {op % 24}: segmented {ra}, single segment {rb}; log {log} for {what}");
            if (ra == "AOORE")
            {
                break; // Advance past the end leaves the reader somewhere unspecified
            }

            if (rm == "SKIP")
            {
                break; // the model doesn't cover this case
            }

            if (rm is not null)
            {
                Check.That(ra == rm, $"step {step} op {op % 24}: reader {ra}, model {rm}; log {log} for {what}");
            }

            Check.That(a.Consumed == model.Position && b.Consumed == model.Position && a.Remaining == bytes.Length - model.Position,
                $"after step {step}: Consumed {a.Consumed}/{b.Consumed}, model {model.Position}; log {log} for {what}");
            Check.That(a.End == (model.Position == bytes.Length), $"End after step {step}; log {log} for {what}");
            Check.That(a.UnreadSequence.ToArray().AsSpan().SequenceEqual(bytes.AsSpan(model.Position)), $"UnreadSequence after step {step}; log {log} for {what}");
            Check.That(bytes.AsSpan(model.Position).StartsWith(a.UnreadSpan), $"UnreadSpan after step {step}; log {log} for {what}");
            Check.Equal((long)model.Position, segmented.Slice(0, a.Position).Length, $"Position after step {step}; log {log} for {what}");
        }
    }

    private sealed class Segment_ : ReadOnlySequenceSegment<byte>
    {
        public Segment_(ReadOnlyMemory<byte> memory, long runningIndex)
        {
            Memory = memory;
            RunningIndex = runningIndex;
        }

        public Segment_ Append(ReadOnlyMemory<byte> memory)
        {
            var next = new Segment_(memory, RunningIndex + Memory.Length);
            Next = next;
            return next;
        }
    }

    private static ReadOnlySequence<byte> Segment(byte[] bytes, byte pattern)
    {
        // Each segment's memory sits in a larger array, so offsets inside segments aren't 0.
        static ReadOnlyMemory<byte> Piece(byte[] bytes, int start, int count) =>
            new ReadOnlyMemory<byte>([0xEE, 0xEE, .. bytes.AsSpan(start, count), 0xEE], 2, count);

        int position = 0, k = 0, previous = 1;
        Segment_ first = null, last = null;
        do
        {
            int size = Math.Min(bytes.Length - position, (pattern >> (k++ % 4 * 2) & 3) switch { 0 => previous == 0 ? 1 : 0, 1 => 1, 2 => 1 + k % 7, _ => 16 + pattern % 32 });
            previous = size;
            ReadOnlyMemory<byte> memory = Piece(bytes, position, size);
            last = last is null ? first = new Segment_(memory, 0) : last.Append(memory);
            position += size;
        }
        while (position < bytes.Length || k % 3 != 0 && k < 8);

        return new ReadOnlySequence<byte>(first, 0, last, last.Memory.Length);
    }

    private static string Bytes(ReadOnlySequence<byte> s) => Convert.ToHexString(s.ToArray());

    private static string Step(ref SequenceReader<byte> r, byte op, byte p1, byte p2, byte p3)
    {
        byte d = (byte)(p1 % 8);
        ReadOnlySpan<byte> set = [d, (byte)(p2 % 8), (byte)(p3 % 8), (byte)(p1 / 32)];
        ReadOnlySpan<byte> values = set.Slice(0, 1 + p2 / 64);
        bool past = (p3 & 0x80) != 0;
        try
        {
            switch (op % 24)
            {
                case 0: return r.TryRead(out byte v) ? $"{v}" : "F";
                case 1: return r.TryPeek(out byte v1) ? $"{v1}" : "F";
                case 2: return r.TryPeek(p1 % 40, out byte v2) ? $"{v2}" : "F";
                case 3: r.Advance(p1 % 40); return "ok";
                case 4: r.Rewind(p1 % 40); return "ok";
                case 5: return r.TryReadTo(out ReadOnlySequence<byte> s, d, past) ? Bytes(s) : "F";
                case 6: return r.TryReadTo(out ReadOnlySpan<byte> sp, d, past) ? Convert.ToHexString(sp) : "F";
                case 7: return r.TryReadTo(out ReadOnlySequence<byte> s7, d, (byte)(p2 % 8), past) ? Bytes(s7) : "F";
                case 8: return r.TryReadTo(out ReadOnlySequence<byte> s8, values, past) ? Bytes(s8) : "F";
                case 9: return r.TryReadTo(out ReadOnlySpan<byte> s9, values, past) ? Convert.ToHexString(s9) : "F";
                case 10: return r.TryReadToAny(out ReadOnlySequence<byte> s10, values, past) ? Bytes(s10) : "F";
                case 11: return r.TryAdvanceTo(d, past) ? "T" : "F";
                case 12: return r.TryAdvanceToAny(values, past) ? "T" : "F";
                case 13: return r.AdvancePast(d).ToString();
                case 14: return r.AdvancePastAny(values).ToString();
                case 15: return (values.Length switch { 1 => r.AdvancePastAny(d, d), 2 => r.AdvancePastAny(values[0], values[1]), 3 => r.AdvancePastAny(values[0], values[1], values[2]), _ => r.AdvancePastAny(values[0], values[1], values[2], values[3]) }).ToString();
                case 16: return r.IsNext(d, past) ? "T" : "F";
                case 17: return r.IsNext(values, past) ? "T" : "F";
                case 18:
                    return (p1 % 6) switch
                    {
                        0 => r.TryReadBigEndian(out short a) ? $"{a}" : "F",
                        1 => r.TryReadLittleEndian(out short b) ? $"{b}" : "F",
                        2 => r.TryReadBigEndian(out int c) ? $"{c}" : "F",
                        3 => r.TryReadLittleEndian(out int e) ? $"{e}" : "F",
                        4 => r.TryReadBigEndian(out long f) ? $"{f}" : "F",
                        _ => r.TryReadLittleEndian(out long g) ? $"{g}" : "F",
                    };
                case 19:
                {
                    byte[] dest = new byte[p1 % 40];
                    return r.TryCopyTo(dest) ? Convert.ToHexString(dest) : "F";
                }

                case 20: return r.TryReadExact(p1 % 40, out ReadOnlySequence<byte> s20) ? Bytes(s20) : "F";
                case 21: r.AdvanceToEnd(); return "ok";
                case 22: return r.TryReadTo(out ReadOnlySpan<byte> s22, d, (byte)(p2 % 8), past) ? Convert.ToHexString(s22) : "F";
                default: return r.TryAdvanceToAny(values, advancePastDelimiter: false) ? $"T{r.Consumed}" : "F";
            }
        }
        catch (ArgumentOutOfRangeException)
        {
            return "AOORE";
        }
    }

    /// <summary>The same operations on a plain array (null where the model doesn't cover an operation).</summary>
    private sealed class Model(byte[] data)
    {
        public int Position;

        private int Remaining => data.Length - Position;

        private string Take(int count)
        {
            string s = Convert.ToHexString(data, Position, count);
            Position += count;
            return s;
        }

        private int IndexOf(ReadOnlySpan<byte> values, bool any) =>
            any ? data.AsSpan(Position).IndexOfAny(values) : data.AsSpan(Position).IndexOf(values);

        public string Step(byte op, byte p1, byte p2, byte p3)
        {
            byte d = (byte)(p1 % 8);
            ReadOnlySpan<byte> set = [d, (byte)(p2 % 8), (byte)(p3 % 8), (byte)(p1 / 32)];
            ReadOnlySpan<byte> values = set.Slice(0, 1 + p2 / 64);
            bool past = (p3 & 0x80) != 0;
            switch (op % 24)
            {
                case 0: return Remaining > 0 ? $"{data[Position++]}" : "F";
                case 1: return Remaining > 0 ? $"{data[Position]}" : "F";
                case 2: return p1 % 40 < Remaining ? $"{data[Position + p1 % 40]}" : "F";
                case 3:
                    if (p1 % 40 > Remaining)
                    {
                        return null; // Advance past the end throws and leaves the reader in an unspecified state
                    }

                    Position += p1 % 40;
                    return "ok";
                case 4:
                    if (p1 % 40 > Position)
                    {
                        return null;
                    }

                    Position -= p1 % 40;
                    return "ok";
                case 5 or 6 or 8 or 9 or 10:
                {
                    ReadOnlySpan<byte> delimiter = op % 24 is 5 or 6 ? [d] : values;
                    int i = IndexOf(delimiter, op % 24 == 10);
                    if (i < 0)
                    {
                        return "F";
                    }

                    string s = Take(i);
                    Position += past ? (op % 24 == 10 ? 1 : delimiter.Length) : 0;
                    return s;
                }

                case 11 or 12:
                {
                    int i = IndexOf(op % 24 == 11 ? [d] : values, any: true);
                    if (i < 0)
                    {
                        return "F";
                    }

                    Position += i + (past ? 1 : 0);
                    return "T";
                }

                case 13 or 14 or 15:
                {
                    ReadOnlySpan<byte> skip = op % 24 == 13 ? [d] : op % 24 == 15 && values.Length == 1 ? [d] : values;
                    int i = data.AsSpan(Position).IndexOfAnyExcept(skip);
                    int n = i < 0 ? Remaining : i;
                    Position += n;
                    return n.ToString();
                }

                case 16 or 17:
                {
                    ReadOnlySpan<byte> next = op % 24 == 16 ? [d] : values;
                    bool match = data.AsSpan(Position).StartsWith(next);
                    Position += match && past ? next.Length : 0;
                    return match ? "T" : "F";
                }

                case 18:
                {
                    int size = (p1 % 6 / 2) switch { 0 => 2, 1 => 4, _ => 8 };
                    if (Remaining < size)
                    {
                        return "F";
                    }

                    ReadOnlySpan<byte> v = data.AsSpan(Position, size);
                    Position += size;
                    return (p1 % 6) switch
                    {
                        0 => $"{BinaryPrimitives.ReadInt16BigEndian(v)}",
                        1 => $"{BinaryPrimitives.ReadInt16LittleEndian(v)}",
                        2 => $"{BinaryPrimitives.ReadInt32BigEndian(v)}",
                        3 => $"{BinaryPrimitives.ReadInt32LittleEndian(v)}",
                        4 => $"{BinaryPrimitives.ReadInt64BigEndian(v)}",
                        _ => $"{BinaryPrimitives.ReadInt64LittleEndian(v)}",
                    };
                }

                case 19: return p1 % 40 <= Remaining ? Convert.ToHexString(data, Position, p1 % 40) : "F";
                case 20: return p1 % 40 <= Remaining ? Take(p1 % 40) : "F";
                case 21:
                    Position = data.Length;
                    return "ok";
                case 23:
                {
                    int i = IndexOf(values, any: true);
                    if (i < 0)
                    {
                        return "F";
                    }

                    Position += i;
                    return $"T{Position}";
                }

                default: // 7 and 22: read to a delimiter that isn't preceded by an odd number of escapes
                {
                    byte escape = (byte)(p2 % 8);
                    if (escape == d)
                    {
                        return "SKIP";
                    }

                    for (int i = Position; i < data.Length; i++)
                    {
                        int escapes = 0;
                        while (i - escapes - 1 >= Position && data[i - escapes - 1] == escape)
                        {
                            escapes++;
                        }

                        if (data[i] == d && escapes % 2 == 0)
                        {
                            string s = Take(i - Position);
                            Position += past ? 1 : 0;
                            return s;
                        }
                    }

                    return "F";
                }
            }
        }
    }

    private static void Sequence(ReadOnlySequence<byte> seq, byte[] bytes, byte[] ops, string what)
    {
        var input = new FuzzInput(ops);
        for (int i = 0; i < 4 && input.Remaining > 0; i++)
        {
            int start = input.Byte() % (bytes.Length + 1);
            int count = input.Byte() % (bytes.Length - start + 1);
            ReadOnlySequence<byte> slice = seq.Slice(start, count);
            Check.That(slice.ToArray().AsSpan().SequenceEqual(bytes.AsSpan(start, count)), $"Slice({start}, {count}) for {what}");
            Check.Equal((long)start, seq.GetOffset(slice.Start), $"GetOffset(Slice({start}, {count}).Start) for {what}");
            Check.Equal((long)(start + count), seq.GetOffset(slice.End), $"GetOffset(Slice({start}, {count}).End) for {what}");
            SequencePosition p = seq.GetPosition(start);
            Check.Equal((long)start, seq.GetOffset(p), $"GetOffset(GetPosition({start})) for {what}");
            Check.That(seq.Slice(p).ToArray().AsSpan().SequenceEqual(bytes.AsSpan(start)), $"Slice(GetPosition({start})) for {what}");
            Check.That(slice.Slice(0, count).ToArray().AsSpan().SequenceEqual(bytes.AsSpan(start, count)), $"Slice of slice for {what}");

            byte value = (byte)(input.Byte() % 8);
            SequencePosition? found = slice.PositionOf(value);
            int expected = bytes.AsSpan(start, count).IndexOf(value);
            Check.Equal(expected < 0 ? -1L : start + expected, found is { } f ? seq.GetOffset(f) : -1L, $"PositionOf({value}) in Slice({start}, {count}) for {what}");

            byte[] copy = new byte[count];
            slice.CopyTo(copy);
            Check.That(copy.AsSpan().SequenceEqual(bytes.AsSpan(start, count)), $"CopyTo of Slice({start}, {count}) for {what}");
            Check.That(slice.FirstSpan.SequenceEqual(bytes.AsSpan(start, Math.Min(count, slice.FirstSpan.Length))), $"FirstSpan of Slice({start}, {count}) for {what}");
            Check.Equal(count == 0, slice.IsEmpty, $"IsEmpty of Slice({start}, {count}) for {what}");
        }
    }
}
