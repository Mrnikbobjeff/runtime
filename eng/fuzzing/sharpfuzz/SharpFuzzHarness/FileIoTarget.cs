#nullable disable warnings
using System.Buffers;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SharpFuzzHarness;

/// <summary>
/// File I/O through the System.Native shim against a byte-array model: RandomAccess reads and writes
/// (scalar and vectored, with the destination memory against guard pages so preadv can't write past
/// what it was given, including more segments than IOV_MAX), GetLength / SetLength / FlushToDisk;
/// FileStream in every strategy (buffer sizes 0, 1, small and default; synchronous and
/// FileOptions.Asynchronous; sync and async APIs; Seek / Position / SetLength / ReadExactly /
/// ReadAtLeast / CopyTo); FileStream over a pipe (non-seekable); File.ReadAllBytes / WriteAllBytes /
/// AppendAllBytes / Copy / Move; and Unix file mode / timestamp round trips. Files live in /dev/shm
/// and are deleted on close.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     operation; byte 1 flags
///   rest       operations (opcode + operands) or data
/// </remarks>
public static unsafe class FileIoTarget
{
    private static int s_files;
    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte op = input.Byte();
        byte flags = input.Byte();
        switch (op % 4)
        {
            case 0: Random(ref input, flags); break;
            case 1: Stream(ref input, flags); break;
            case 2: Pipe(ref input, flags); break;
            default: Files(ref input, flags); break;
        }
    }

    private static string NewPath() => $"/dev/shm/sharpfuzz-fileio-{Environment.ProcessId}-{s_files++}";

    // ------------------------------------------------------------ RandomAccess

    private static void Random(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        var model = new SparseModel();
        bool big = input.Byte() % 3 == 0; // offsets past 2^31 and 2^32 (sparse file)
        using SafeFileHandle handle = File.OpenHandle(NewPath(), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, FileOptions.DeleteOnClose | ((flags & 2) != 0 ? FileOptions.Asynchronous : 0), preallocationSize: flags >> 2);
        var log = new List<string>();
        for (int step = 0; step < 24 && input.Remaining > 0; step++)
        {
            int kind = input.Byte() % 8;
            long offset = big ? (long)input.UInt16() << 16 : input.UInt16() % 4200;
            int length = input.UInt16() % 2100;
            log.Add($"{kind}@{offset}x{length}");
            string what = $"RandomAccess over {model.Count} bytes: {string.Join(" ", log)}";
            switch (kind)
            {
                case 0:
                {
                    // Write a span at an offset (extending with zeros).
                    byte[] payload = Payload(ref input, length);
                    RandomAccess.Write(handle, payload, offset);
                    Apply(model, offset, payload);
                    break;
                }
                case 1:
                {
                    // Read into a guarded span of exactly the requested length.
                    Span<byte> dest = new(Guarded.Allocate(length, atStart), length);
                    dest.Fill(0xCC);
                    int read = RandomAccess.Read(handle, dest, offset);
                    Check.Equal(Expected(model, offset, length).Length, read, $"{what}: Read length");
                    Check.That(dest.Slice(0, read).SequenceEqual(Expected(model, offset, length)), $"{what}: Read contents");
                    break;
                }
                case 2:
                {
                    // Vectored write from several segments (some empty), then vectored read into guarded segments.
                    int segments = input.Byte() % 5 + 1;
                    var buffers = new List<ReadOnlyMemory<byte>>();
                    var all = new List<byte>();
                    for (int i = 0; i < segments; i++)
                    {
                        byte[] piece = Payload(ref input, input.Byte() % Math.Max(1, length / segments + 1));
                        buffers.Add(piece);
                        all.AddRange(piece);
                    }

                    RandomAccess.Write(handle, buffers, offset);
                    Apply(model, offset, all.ToArray());
                    var dests = new List<Memory<byte>>();
                    int total = 0;
                    for (int i = 0; i < segments; i++)
                    {
                        int n = input.Byte() % Math.Max(1, length / segments + 1);
                        dests.Add(Guarded.CopyMemory<byte>(new byte[n], (i & 1) == 0));
                        total += n;
                    }

                    long read = RandomAccess.Read(handle, dests, offset);
                    byte[] expected = Expected(model, offset, total);
                    Check.Equal(expected.Length, read, $"{what}: vectored Read length");
                    var got = new List<byte>();
                    foreach (Memory<byte> d in dests)
                    {
                        got.AddRange(d.Span.ToArray());
                    }

                    Check.That(got.Take((int)read).SequenceEqual(expected), $"{what}: vectored Read contents");
                    break;
                }
                case 3:
                {
                    // More segments than IOV_MAX (1024), one byte each.
                    int segments = 1024 + input.Byte();
                    byte* block = Guarded.Allocate(segments, atStart);
                    var dests = new List<Memory<byte>>(segments);
                    for (int i = 0; i < segments; i++)
                    {
                        dests.Add(new Manager(block + i, 1).Memory);
                    }

                    long read = RandomAccess.Read(handle, dests, offset);
                    byte[] expected = Expected(model, offset, segments);
                    // Known (RA-IOV-1): a single preadv is issued with at most IOV_MAX segments, so the read is short.
                    Check.That(read == expected.Length || !s_reportKnownIssues && read == Math.Min(expected.Length, 1024), $"{what}: Read into {segments} segments length: expected {expected.Length}, got {read}");
                    Check.That(new ReadOnlySpan<byte>(block, (int)read).SequenceEqual(expected.AsSpan(0, (int)read)), $"{what}: Read into {segments} segments contents");
                    var sources = new List<ReadOnlyMemory<byte>>(segments);
                    byte[] payload = Payload(ref input, segments);
                    for (int i = 0; i < segments; i++)
                    {
                        sources.Add(payload.AsMemory(i, 1));
                    }

                    RandomAccess.Write(handle, sources, offset);
                    Apply(model, offset, payload);
                    break;
                }
                case 4:
                    RandomAccess.SetLength(handle, offset);
                    Resize(model, offset);
                    break;
                case 5:
                    RandomAccess.FlushToDisk(handle);
                    break;
                case 6:
                {
                    // Async read into guarded memory.
                    Memory<byte> dest = Guarded.CopyMemory<byte>(new byte[length], atStart);
                    int read = RandomAccess.ReadAsync(handle, dest, offset).AsTask().GetAwaiter().GetResult();
                    Check.Equal(Expected(model, offset, length).Length, read, $"{what}: ReadAsync length");
                    Check.That(dest.Span.Slice(0, read).SequenceEqual(Expected(model, offset, length)), $"{what}: ReadAsync contents");
                    break;
                }
                default:
                {
                    byte[] payload = Payload(ref input, length);
                    RandomAccess.WriteAsync(handle, payload, offset).AsTask().GetAwaiter().GetResult();
                    Apply(model, offset, payload);
                    break;
                }
            }

            Check.Equal((long)model.Count, RandomAccess.GetLength(handle), $"{what}: GetLength");
        }

        // Everything at once (small files only).
        if (model.Count <= 1 << 20)
        {
            byte[] whole = new byte[(int)model.Count];
            Check.Equal((int)model.Count, RandomAccess.Read(handle, whole, 0), "final Read length");
            Check.That(whole.AsSpan().SequenceEqual(model.ToArray()), "final Read contents");
        }
        try
        {
            RandomAccess.Read(handle, new byte[16], -1);
            Check.That(false, "Read at a negative offset succeeded");
        }
        catch (ArgumentOutOfRangeException)
        {
        }
    }

    private static byte[] Payload(ref FuzzInput input, int length)
    {
        byte[] payload = new byte[length];
        ReadOnlySpan<byte> bytes = input.Bytes(Math.Min(length, 32));
        for (int i = 0; i < length; i++)
        {
            payload[i] = bytes.Length == 0 ? (byte)i : bytes[i % bytes.Length];
        }

        return payload;
    }

    /// <summary>The file's contents as written bytes over an implicit sea of zeros, so positions past 4 GB cost nothing.</summary>
    private sealed class SparseModel
    {
        private readonly SortedDictionary<long, byte> _bytes = new();

        public long Count { get; private set; }

        public byte this[long index] => _bytes.TryGetValue(index, out byte b) ? b : (byte)0;

        public void Apply(long offset, byte[] payload)
        {
            for (int i = 0; i < payload.Length; i++)
            {
                _bytes[offset + i] = payload[i];
            }

            if (payload.Length > 0)
            {
                Count = Math.Max(Count, offset + payload.Length);
            }
        }

        public void Resize(long length)
        {
            if (length < Count)
            {
                foreach (long key in _bytes.Keys.Where(k => k >= length).ToList())
                {
                    _bytes.Remove(key);
                }
            }

            Count = length;
        }

        public byte[] Expected(long offset, int length)
        {
            if (offset >= Count)
            {
                return [];
            }

            byte[] result = new byte[(int)Math.Min(length, Count - offset)];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = this[offset + i];
            }

            return result;
        }

        public byte[] ToArray() => Expected(0, (int)Math.Min(Count, int.MaxValue));
    }

    private static void Apply(SparseModel model, long offset, byte[] payload) => model.Apply(offset, payload);

    private static void Resize(SparseModel model, long length) => model.Resize(length);

    private static byte[] Expected(SparseModel model, long offset, int length) => model.Expected(offset, length);

    private sealed class Manager(byte* pointer, int length) : MemoryManager<byte>
    {
        public override Span<byte> GetSpan() => new(pointer, length);
        public override MemoryHandle Pin(int elementIndex = 0) => new(pointer + elementIndex);
        public override void Unpin() { }
        protected override void Dispose(bool disposing) { }
    }

    // ------------------------------------------------------------ FileStream

    private static void Stream(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        bool async = (flags & 2) != 0;
        int bufferSize = (flags >> 2) switch { 0 => 0, 1 => 1, 2 => 7, 3 => 64, 4 => 4096, _ => 1 + (flags >> 2) * 37 };
        var model = new SparseModel();
        bool big = input.Byte() % 3 == 0; // positions past 2^31 and 2^32 (sparse file)
        long position = 0;
        using var fs = new FileStream(NewPath(), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, bufferSize, FileOptions.DeleteOnClose | (async ? FileOptions.Asynchronous : 0));
        var log = new List<string>();
        bool asyncWrite = false, tainted = false; // FS-STALE-1: a seek after a buffered WriteAsync can leave a stale read window
        for (int step = 0; step < 32 && input.Remaining > 0; step++)
        {
            int kind = input.Byte() % 12;
            int arg = input.UInt16() % 3000;
            long pos = big ? (long)arg << 21 : arg;
            log.Add($"{kind}({arg})");
            if (asyncWrite && kind is 4 or 5 or 6)
            {
                tainted = !s_reportKnownIssues;
            }

            bool trust = !tainted;
            string what = $"FileStream(buffer {bufferSize}, async {async}) over {model.Count} bytes at {position}: {string.Join(" ", log)}";
            switch (kind)
            {
                case 0:
                {
                    byte[] payload = Payload(ref input, arg % 600);
                    fs.Write(payload);
                    Apply(model, position, payload);
                    position += payload.Length;
                    break;
                }
                case 1:
                {
                    Span<byte> dest = new(Guarded.Allocate(arg % 600, atStart), arg % 600);
                    int read = fs.Read(dest);
                    byte[] expected = Expected(model, position, dest.Length);
                    Check.That(!trust || expected.Length == read, $"{what}: Read length: expected {expected.Length}, got {read}");
                    Check.That(!trust || dest.Slice(0, read).SequenceEqual(expected), $"{what}: Read contents");
                    position += read;
                    break;
                }
                case 2:
                {
                    int value = fs.ReadByte();
                    Check.That(!trust || value == (position < model.Count ? model[position] : -1), $"{what}: ReadByte");
                    if (value >= 0)
                    {
                        position++;
                    }

                    break;
                }
                case 3:
                    fs.WriteByte((byte)arg);
                    Apply(model, position, [(byte)arg]);
                    position++;
                    break;
                case 4:
                {
                    SeekOrigin origin = (SeekOrigin)(arg % 3);
                    long target = origin switch { SeekOrigin.Begin => pos, SeekOrigin.Current => position + arg % 100 - 50, _ => model.Count + arg % 100 - 50 };
                    if (target < 0)
                    {
                        try
                        {
                            fs.Seek(origin == SeekOrigin.Begin ? pos : arg % 100 - 50, origin);
                            Check.That(false, $"{what}: Seek before the start succeeded");
                        }
                        catch (IOException)
                        {
                        }
                    }
                    else
                    {
                        Check.Equal(target, fs.Seek(origin == SeekOrigin.Begin ? pos : arg % 100 - 50, origin), $"{what}: Seek");
                        position = target;
                    }

                    break;
                }
                case 5:
                    fs.Position = pos;
                    position = pos;
                    break;
                case 6:
                    fs.SetLength(pos);
                    Resize(model, pos);
                    if (position > pos)
                    {
                        position = pos; // documented: the position is moved back to the new end
                    }

                    break;
                case 7:
                    fs.Flush((arg & 1) != 0);
                    break;
                case 8:
                {
                    byte[] dest = new byte[arg % 600];
                    int available = Expected(model, position, dest.Length).Length;
                    if (available < dest.Length)
                    {
                        try
                        {
                            fs.ReadExactly(dest);
                            Check.That(false, $"{what}: ReadExactly succeeded with {available} of {dest.Length} bytes");
                        }
                        catch (EndOfStreamException)
                        {
                            // The position after a failed ReadExactly is unspecified; resynchronize.
                            position = fs.Position;
                        }
                    }
                    else
                    {
                        fs.ReadExactly(dest);
                        Check.That(!trust || dest.SequenceEqual(Expected(model, position, dest.Length)), $"{what}: ReadExactly contents");
                        position += dest.Length;
                    }

                    break;
                }
                case 9:
                {
                    Memory<byte> dest = Guarded.CopyMemory<byte>(new byte[arg % 600], atStart);
                    int minimum = dest.Length == 0 ? 0 : arg % dest.Length;
                    int available = Expected(model, position, dest.Length).Length;
                    int read = fs.ReadAtLeast(dest.Span, minimum, throwOnEndOfStream: false);
                    Check.That(!trust || read >= Math.Min(minimum, available) && read <= dest.Length && read <= available, $"{what}: ReadAtLeast({minimum}) returned {read} with {available} available");
                    Check.That(!trust || dest.Span.Slice(0, read).SequenceEqual(Expected(model, position, read)), $"{what}: ReadAtLeast contents");
                    position += read;
                    break;
                }
                case 10:
                {
                    Memory<byte> dest = Guarded.CopyMemory<byte>(new byte[arg % 600], atStart);
                    int read = fs.ReadAsync(dest).AsTask().GetAwaiter().GetResult();
                    byte[] expected = Expected(model, position, dest.Length);
                    Check.That(!trust || expected.Length == read, $"{what}: ReadAsync length: expected {expected.Length}, got {read}");
                    Check.That(!trust || dest.Span.Slice(0, read).SequenceEqual(expected), $"{what}: ReadAsync contents");
                    position += read;
                    break;
                }
                default:
                {
                    byte[] payload = Payload(ref input, arg % 600);
                    fs.WriteAsync(payload).AsTask().GetAwaiter().GetResult();
                    Apply(model, position, payload);
                    position += payload.Length;
                    asyncWrite = true;
                    break;
                }
            }

            if (kind == 7)
            {
                asyncWrite = false; // a flush before any seek avoids the stale window
            }

            Check.That(!trust || position == fs.Position, $"{what}: Position: expected {position}, got {fs.Position}");
            Check.Equal((long)model.Count, fs.Length, $"{what}: Length");
            if (tainted)
            {
                position = fs.Position; // follow the stream so the model stays usable for the writes
            }
        }

        // CopyTo from the current position into a MemoryStream, then the whole file through the handle (small files only).
        if (model.Count <= 1 << 20)
        {
            var ms = new MemoryStream();
            fs.CopyTo(ms, Math.Max(1, bufferSize));
            Check.That(tainted || ms.ToArray().AsSpan().SequenceEqual(Expected(model, position, (int)model.Count)), "CopyTo contents");
            fs.Flush();
            byte[] whole = new byte[(int)model.Count];
            Check.Equal((int)model.Count, RandomAccess.Read(fs.SafeFileHandle, whole, 0), "handle Read length");
            Check.That(whole.AsSpan().SequenceEqual(model.ToArray()), "handle Read contents");
        }
    }

    // ------------------------------------------------------------ pipes

    [DllImport("libc", SetLastError = true)] private static extern int pipe(int* fds);

    private static void Pipe(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        int* fds = stackalloc int[2];
        Check.Equal(0, pipe(fds), "pipe()");
        using var reader = new FileStream(new SafeFileHandle((IntPtr)fds[0], ownsHandle: true), FileAccess.Read, ((flags >> 2) % 3) switch { 0 => 0, 1 => 1, _ => 4096 });
        using var writer = new FileStream(new SafeFileHandle((IntPtr)fds[1], ownsHandle: true), FileAccess.Write, ((flags >> 4) % 3) switch { 0 => 0, 1 => 1, _ => 4096 });
        Check.That(!reader.CanSeek && !writer.CanSeek && reader.CanRead && !reader.CanWrite && writer.CanWrite && !writer.CanRead, "pipe stream capabilities");
        try
        {
            _ = reader.Length;
            Check.That(false, "Length of a pipe succeeded");
        }
        catch (NotSupportedException)
        {
        }

        var pending = new Queue<byte>();
        for (int step = 0; step < 16 && input.Remaining > 0; step++)
        {
            int kind = input.Byte() % 4;
            int length = input.UInt16() % 3000;
            string what = $"pipe step {step} kind {kind} length {length} pending {pending.Count}";
            switch (kind)
            {
                case 0:
                {
                    byte[] payload = Payload(ref input, length);
                    writer.Write(payload);
                    writer.Flush();
                    foreach (byte b in payload)
                    {
                        pending.Enqueue(b);
                    }

                    break;
                }
                case 1 when pending.Count > 0:
                {
                    int n = Math.Min(Math.Max(1, length), pending.Count);
                    Span<byte> dest = new(Guarded.Allocate(n, atStart), n);
                    int read = reader.Read(dest);
                    Check.That(read > 0 && read <= n, $"{what}: Read returned {read}");
                    for (int i = 0; i < read; i++)
                    {
                        Check.Equal(pending.Dequeue(), dest[i], $"{what}: byte {i}");
                    }

                    break;
                }
                case 2 when pending.Count > 0:
                {
                    int n = Math.Min(Math.Max(1, length), pending.Count);
                    byte[] dest = new byte[n];
                    reader.ReadExactly(dest);
                    for (int i = 0; i < n; i++)
                    {
                        Check.Equal(pending.Dequeue(), dest[i], $"{what}: ReadExactly byte {i}");
                    }

                    break;
                }
                case 3 when pending.Count > 0:
                {
                    int value = reader.ReadByte();
                    Check.Equal(pending.Dequeue(), (byte)value, $"{what}: ReadByte");
                    break;
                }
            }
        }

        // Drain what's left, then EOF after the writer closes.
        byte[] rest = new byte[pending.Count];
        reader.ReadExactly(rest);
        Check.That(rest.SequenceEqual(pending), "drained pipe contents");
        writer.Dispose();
        Check.Equal(0, reader.Read(new byte[16]), "pipe EOF");
    }

    // ------------------------------------------------------------ File helpers, modes, times

    private static void Files(ref FuzzInput input, byte flags)
    {
        string path = NewPath();
        string other = path + "-b";
        byte[] payload = input.Bytes(Math.Min(input.Remaining, 300)).ToArray();
        byte[] extra = input.Bytes(Math.Min(input.Remaining, 100)).ToArray();
        try
        {
            File.WriteAllBytes(path, payload);
            Check.That(File.ReadAllBytes(path).SequenceEqual(payload), "WriteAllBytes / ReadAllBytes");
            File.AppendAllBytes(path, extra);
            Check.That(File.ReadAllBytes(path).SequenceEqual(payload.Concat(extra)), "AppendAllBytes");
            Check.Equal((long)(payload.Length + extra.Length), new FileInfo(path).Length, "FileInfo.Length");
            File.Copy(path, other, overwrite: true);
            Check.That(File.ReadAllBytes(other).SequenceEqual(payload.Concat(extra)), "Copy");
            // Unix mode round trip (the caller sets it explicitly, so umask doesn't apply).
            var mode = (UnixFileMode)(input.UInt16() & 0x1FF);
            File.SetUnixFileMode(path, mode | UnixFileMode.UserRead | UnixFileMode.UserWrite);
            Check.Equal(mode | UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path), $"SetUnixFileMode({mode})");
            var info = new FileInfo(path);
            Check.Equal(mode | UnixFileMode.UserRead | UnixFileMode.UserWrite, info.UnixFileMode, $"FileInfo.UnixFileMode({mode})");
            // Timestamps: tmpfs keeps nanoseconds, so 100 ns ticks round-trip exactly.
            long ticks = DateTime.UnixEpoch.Ticks + ((long)input.Int32() << 20) % (TimeSpan.TicksPerDay * 365 * 200) + (input.UInt16() & 0x7FFF);
            var when = new DateTime(Math.Max(ticks, new DateTime(1902, 1, 1).Ticks), DateTimeKind.Utc);
            File.SetLastWriteTimeUtc(path, when);
            Check.Equal(when, File.GetLastWriteTimeUtc(path), $"SetLastWriteTimeUtc({when:O})");
            File.SetLastAccessTimeUtc(path, when.AddTicks(1));
            Check.Equal(when.AddTicks(1), File.GetLastAccessTimeUtc(path), $"SetLastAccessTimeUtc({when:O})");
            Check.Equal(when, File.GetLastWriteTimeUtc(path), "last write time after setting the access time");
            info.Refresh();
            Check.Equal(when, info.LastWriteTimeUtc, "FileInfo.LastWriteTimeUtc");
            // Move over an existing file, then the original is gone.
            File.Move(other, path, overwrite: true);
            Check.That(!File.Exists(other) && File.ReadAllBytes(path).SequenceEqual(payload.Concat(extra)), "Move");
            // Symbolic links: the target is stored verbatim.
            string target = "t-" + Convert.ToHexString(extra.AsSpan(0, Math.Min(extra.Length, 20)));
            File.CreateSymbolicLink(other, target);
            Check.Equal(target, new FileInfo(other).LinkTarget, "LinkTarget");
            Check.Equal(Path.Combine("/dev/shm", target), File.ResolveLinkTarget(other, returnFinalTarget: false).FullName, "ResolveLinkTarget");
        }
        finally
        {
            File.Delete(path);
            File.Delete(other);
        }
    }
}
