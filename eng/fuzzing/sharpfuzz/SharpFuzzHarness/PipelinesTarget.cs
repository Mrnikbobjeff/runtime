#nullable disable warnings
using System.Buffers;
using System.IO.Pipelines;
using System.Runtime.InteropServices;

namespace SharpFuzzHarness;

/// <summary>
/// System.IO.Pipelines driven by a fuzzed sequence of writer and reader operations on one thread (inline
/// schedulers, no back pressure), against a byte-queue model: writes through GetSpan / GetMemory with
/// size hints and Advance, flushes, reads with AdvanceTo(consumed, examined) at fuzzed positions, TryRead,
/// and completion. Everything the reader consumes must be exactly what was written, in order. Also
/// PipeReader.Create over a stream returning a few bytes per read, with small buffer / minimum read sizes.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     mode / options; byte 1 minimum segment size
///   rest       operations: an opcode byte followed by an argument byte
/// </remarks>
public static class PipelinesTarget
{
    private sealed class ChunkStream(byte[] data, byte pattern) : Stream
    {
        private int _position, _reads;

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            int n = Math.Min(buffer.Length, Math.Min(data.Length - _position, 1 + (pattern >> (_reads++ % 4 * 2) & 3) * 7));
            data.AsSpan(_position, n).CopyTo(buffer);
            _position += n;
            return n;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => new(Read(buffer.Span));
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => _position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        int segment = 1 + input.Byte() % 64 * 8;
        byte[] ops = input.Rest().ToArray();
        if (ops.Length > 4096)
        {
            return;
        }

        string what = $"mode {mode:X2} segment {segment}, ops 0x{Convert.ToHexString(ops.AsSpan(0, Math.Min(ops.Length, 64)))}";
        if ((mode & 1) == 0)
        {
            PipeOps(ops, segment, what);
        }
        else
        {
            StreamReader(ops, mode, segment, what);
        }
    }

    private static void PipeOps(byte[] ops, int segment, string what)
    {
        var pipe = new Pipe(new PipeOptions(pool: MemoryPool<byte>.Shared, readerScheduler: PipeScheduler.Inline, writerScheduler: PipeScheduler.Inline,
            pauseWriterThreshold: 0, resumeWriterThreshold: 0, minimumSegmentSize: segment, useSynchronizationContext: false));
        var written = new List<byte>();
        var consumed = new List<byte>();
        byte next = 0;
        bool writerDone = false;
        for (int i = 0; i + 1 < ops.Length; i += 2)
        {
            byte op = ops[i], arg = ops[i + 1];
            switch (op % 6)
            {
                case 0 or 1 when !writerDone:
                {
                    // Write arg bytes through a span or memory with a size hint.
                    int hint = op / 6 % 4 == 0 ? 0 : arg;
                    Span<byte> span = op % 6 == 0 ? pipe.Writer.GetSpan(hint) : pipe.Writer.GetMemory(hint).Span;
                    Check.That(span.Length >= Math.Max(1, hint), $"GetSpan({hint}) gave {span.Length} bytes: {what}");
                    int n = Math.Min(span.Length, arg);
                    for (int k = 0; k < n; k++)
                    {
                        span[k] = next;
                        written.Add(next++);
                    }

                    pipe.Writer.Advance(n);
                    break;
                }

                case 2 when !writerDone:
                    pipe.Writer.FlushAsync().AsTask().GetAwaiter().GetResult();
                    break;
                case 3:
                {
                    // Read what's there (TryRead, so nothing blocks), consume and examine at fuzzed positions.
                    if (!pipe.Reader.TryRead(out ReadResult result))
                    {
                        break;
                    }

                    ReadOnlySequence<byte> buffer = result.Buffer;
                    long take = buffer.Length == 0 ? 0 : arg % (buffer.Length + 1);
                    consumed.AddRange(buffer.Slice(0, take).ToArray());
                    SequencePosition end = buffer.GetPosition(take);
                    SequencePosition examined = (op & 0x80) != 0 ? buffer.End : end;
                    pipe.Reader.AdvanceTo(end, examined);
                    break;
                }

                case 4 when !writerDone:
                    pipe.Writer.FlushAsync().AsTask().GetAwaiter().GetResult();
                    pipe.Writer.Complete();
                    writerDone = true;
                    break;
                default:
                    pipe.Reader.CancelPendingRead();
                    break;
            }

            Check.That(consumed.Count <= written.Count && CollectionsMarshal.AsSpan(consumed).SequenceEqual(CollectionsMarshal.AsSpan(written)[..consumed.Count]), $"consumed bytes don't match the written ones at op {i / 2}: {what}");
        }

        // Finish: flush and complete the writer, then read everything that's left.
        if (!writerDone)
        {
            pipe.Writer.FlushAsync().AsTask().GetAwaiter().GetResult();
            pipe.Writer.Complete();
        }

        for (int guard = 0; guard < 1000; guard++)
        {
            ReadResult result = pipe.Reader.ReadAsync().AsTask().GetAwaiter().GetResult();
            consumed.AddRange(result.Buffer.ToArray());
            pipe.Reader.AdvanceTo(result.Buffer.End);
            if (result.IsCompleted)
            {
                break;
            }
        }

        pipe.Reader.Complete();
        Check.That(CollectionsMarshal.AsSpan(consumed).SequenceEqual(CollectionsMarshal.AsSpan(written)), $"read {consumed.Count} bytes, wrote {written.Count}: {what}");
    }

    private static void StreamReader(byte[] data, byte mode, int segment, string what)
    {
        var reader = PipeReader.Create(new ChunkStream(data, mode), new StreamPipeReaderOptions(bufferSize: segment, minimumReadSize: Math.Max(1, segment / 4 * (mode >> 6)), leaveOpen: true));
        var consumed = new List<byte>();
        int k = 0;
        for (int guard = 0; guard < 100000; guard++)
        {
            ReadResult result = (mode & 2) != 0 && k % 3 == 0
                ? reader.ReadAtLeastAsync(1 + (mode >> 2 & 15)).AsTask().GetAwaiter().GetResult()
                : reader.ReadAsync().AsTask().GetAwaiter().GetResult();
            ReadOnlySequence<byte> buffer = result.Buffer;
            // Consume part (or all) of it; examine everything so the next read waits for more.
            long take = result.IsCompleted ? buffer.Length : Math.Min(buffer.Length, 1 + (data.Length == 0 ? 0 : data[k++ % data.Length]) % 17);
            consumed.AddRange(buffer.Slice(0, take).ToArray());
            reader.AdvanceTo(buffer.GetPosition(take), buffer.End);
            if (result.IsCompleted && take == buffer.Length)
            {
                break;
            }
        }

        reader.Complete();
        Check.That(CollectionsMarshal.AsSpan(consumed).SequenceEqual(data), $"PipeReader over a stream read {consumed.Count} of {data.Length} bytes (or different ones): {what}");
    }
}
