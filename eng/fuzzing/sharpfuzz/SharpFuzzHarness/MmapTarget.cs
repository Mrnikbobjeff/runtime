#nullable disable warnings
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;

namespace SharpFuzzHarness;

/// <summary>
/// Memory-mapped files (mmap through the System.Native shim) against a byte-array model: anonymous
/// and file-backed maps with fuzzed capacities, views at fuzzed (unaligned) offsets and sizes,
/// accessor reads and writes of every width at fuzzed positions (in range must match the model,
/// out of range must throw, never touch memory), ReadArray / WriteArray, view streams, two views over
/// the same bytes seeing each other's writes, Flush, SafeMemoryMappedViewHandle pointer arithmetic
/// (PointerOffset), and capacity growth of the backing file.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     flags; bytes 1-2 capacity; bytes 3-4 view offset; bytes 5-6 view size
///   rest       operations (opcode + operands)
/// </remarks>
public static unsafe class MmapTarget
{
    private static int s_files;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte flags = input.Byte();
        long capacity = input.UInt16() % 20000 + 1;
        long offset = input.UInt16() % 9000;
        long size = input.UInt16() % 9000;
        bool fileBacked = (flags & 1) != 0;
        string what = $"MemoryMappedFile capacity {capacity} {(fileBacked ? "file" : "anonymous")}, view offset {offset} size {size}";
        byte[] model = new byte[capacity];

        string path = fileBacked ? $"/dev/shm/sharpfuzz-mmap-{Environment.ProcessId}-{s_files++}" : null;
        FileStream file = null;
        try
        {
            MemoryMappedFile mmf;
            if (fileBacked)
            {
                // The file starts smaller than the capacity: CreateFromFile grows it.
                long initial = (flags & 2) != 0 ? 0 : Math.Min(capacity, input.Byte());
                file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 4096, FileOptions.DeleteOnClose);
                file.SetLength(initial);
                mmf = MemoryMappedFile.CreateFromFile(file, null, capacity, MemoryMappedFileAccess.ReadWrite, HandleInheritability.None, leaveOpen: true);
                Check.Equal(capacity, file.Length, $"{what}: file grown to the capacity");
            }
            else
            {
                mmf = MemoryMappedFile.CreateNew(null, capacity);
            }

            using (mmf)
            {
                MemoryMappedViewAccessor view;
                try
                {
                    view = mmf.CreateViewAccessor(offset, size, MemoryMappedFileAccess.ReadWrite);
                }
                catch (ArgumentOutOfRangeException)
                {
                    Check.That(offset + size > capacity || offset >= capacity && size == 0, $"{what}: CreateViewAccessor rejected a valid view");
                    return;
                }
                catch (UnauthorizedAccessException)
                {
                    Check.That(offset + size > capacity, $"{what}: CreateViewAccessor threw UnauthorizedAccessException for a valid view");
                    return;
                }

                Check.That(offset + size <= capacity, $"{what}: CreateViewAccessor accepted a view past the capacity");
                using (view)
                {
                    long viewSize = size == 0 ? capacity - offset : size;
                    Check.Equal(viewSize, view.Capacity, $"{what}: view Capacity");
                    if (viewSize > 0)
                    {
                        Check.Equal(offset % Environment.SystemPageSize, view.PointerOffset, $"{what}: PointerOffset");
                    }
                    Check.That(view.CanRead && view.CanWrite, $"{what}: CanRead / CanWrite");
                    Operations(view, model, offset, viewSize, ref input, what);

                    // A second view over the whole file sees every write, and a stream over the same range too.
                    using MemoryMappedViewAccessor whole = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);
                    byte[] all = new byte[capacity];
                    Check.Equal((int)capacity, whole.ReadArray(0, all, 0, (int)capacity), $"{what}: whole-view ReadArray count");
                    Check.That(all.SequenceEqual(model), $"{what}: whole view differs from the model");
                    using MemoryMappedViewStream stream = mmf.CreateViewStream(offset, size, MemoryMappedFileAccess.Read);
                    Check.Equal(viewSize, stream.Length, $"{what}: view stream Length");
                    byte[] streamed = new byte[viewSize];
                    stream.ReadExactly(streamed);
                    Check.That(streamed.AsSpan().SequenceEqual(model.AsSpan((int)offset, (int)viewSize)), $"{what}: view stream contents");
                    Check.Equal(0, stream.Read(new byte[1]), $"{what}: view stream EOF");
                    // Pointer access through the SafeBuffer.
                    byte* pointer = null;
                    view.SafeMemoryMappedViewHandle.AcquirePointer(ref pointer);
                    try
                    {
                        Check.That(new ReadOnlySpan<byte>(pointer + view.PointerOffset, (int)viewSize).SequenceEqual(model.AsSpan((int)offset, (int)viewSize)), $"{what}: pointer view differs from the model");
                        Check.That(view.SafeMemoryMappedViewHandle.ByteLength >= (ulong)(viewSize + view.PointerOffset), $"{what}: ByteLength {view.SafeMemoryMappedViewHandle.ByteLength}");
                    }
                    finally
                    {
                        view.SafeMemoryMappedViewHandle.ReleasePointer();
                    }

                    view.Flush();
                }
            }

            if (fileBacked)
            {
                // The file holds the model once the maps are gone.
                file.Position = 0;
                byte[] contents = new byte[capacity];
                file.ReadExactly(contents);
                Check.That(contents.SequenceEqual(model), $"{what}: file contents after unmapping");
            }
        }
        finally
        {
            file?.Dispose();
        }
    }

    private static void Operations(MemoryMappedViewAccessor view, byte[] model, long offset, long viewSize, ref FuzzInput input, string what)
    {
        var log = new List<string>();
        for (int step = 0; step < 40 && input.Remaining > 0; step++)
        {
            int kind = input.Byte() % 12;
            long position = input.UInt16() % (viewSize + 16) - 8;
            long value = (long)input.Int32() << 32 | (uint)input.Int32();
            int width = kind switch { 0 or 6 => 1, 1 or 7 => 2, 2 or 8 => 4, 3 or 9 => 8, 4 or 10 => 16, _ => 1 + (int)(value & 31) };
            bool inRange = position >= 0 && position + width <= viewSize;
            log.Add($"{kind}@{position}");
            string where = $"{what}: ops {string.Join(" ", log)}";
            try
            {
                switch (kind)
                {
                    case 0: { byte v = view.ReadByte(position); Check.That(inRange, $"{where}: ReadByte outside the view"); Check.Equal(model[offset + position], v, $"{where}: ReadByte"); break; }
                    case 1: { short v = view.ReadInt16(position); Check.That(inRange, $"{where}: ReadInt16 outside the view"); Check.Equal(BitConverter.ToInt16(model, (int)(offset + position)), v, $"{where}: ReadInt16"); break; }
                    case 2: { int v = view.ReadInt32(position); Check.That(inRange, $"{where}: ReadInt32 outside the view"); Check.Equal(BitConverter.ToInt32(model, (int)(offset + position)), v, $"{where}: ReadInt32"); break; }
                    case 3: { long v = view.ReadInt64(position); Check.That(inRange, $"{where}: ReadInt64 outside the view"); Check.Equal(BitConverter.ToInt64(model, (int)(offset + position)), v, $"{where}: ReadInt64"); break; }
                    case 4:
                        view.Read(position, out decimal d);
                        Check.That(inRange, $"{where}: Read<decimal> outside the view");
                        Check.That(MemoryMarshal.AsBytes(new ReadOnlySpan<decimal>(in d)).SequenceEqual(model.AsSpan((int)(offset + position), 16)), $"{where}: Read<decimal>");
                        break;
                    case 6: view.Write(position, (byte)value); Check.That(inRange, $"{where}: Write(byte) outside the view"); model[offset + position] = (byte)value; break;
                    case 7: view.Write(position, (short)value); Check.That(inRange, $"{where}: Write(short) outside the view"); BitConverter.TryWriteBytes(model.AsSpan((int)(offset + position)), (short)value); break;
                    case 8: view.Write(position, (int)value); Check.That(inRange, $"{where}: Write(int) outside the view"); BitConverter.TryWriteBytes(model.AsSpan((int)(offset + position)), (int)value); break;
                    case 9: view.Write(position, value); Check.That(inRange, $"{where}: Write(long) outside the view"); BitConverter.TryWriteBytes(model.AsSpan((int)(offset + position)), value); break;
                    case 10:
                    {
                        var guid = new Guid((int)value, (short)(value >> 32), (short)(value >> 48), 1, 2, 3, 4, 5, 6, 7, 8);
                        view.Write(position, ref guid);
                        Check.That(inRange, $"{where}: Write(Guid) outside the view");
                        guid.TryWriteBytes(model.AsSpan((int)(offset + position), 16));
                        break;
                    }
                    case 5:
                    {
                        // ReadArray: count clipped to the view is documented; the array must have room.
                        int count = width;
                        byte[] array = new byte[count + 2];
                        int read = view.ReadArray(position, array, 1, count);
                        int expected = (int)Math.Max(0, Math.Min(count, viewSize - position));
                        Check.Equal(expected, read, $"{where}: ReadArray count");
                        Check.That(array.AsSpan(1, read).SequenceEqual(model.AsSpan((int)(offset + position), read)) && array[0] == 0 && array[count + 1] == 0, $"{where}: ReadArray contents");
                        inRange = position >= 0 && position <= viewSize; // ReadArray clips instead of throwing
                        break;
                    }
                    default:
                    {
                        int count = width;
                        byte[] array = new byte[count];
                        for (int i = 0; i < count; i++)
                        {
                            array[i] = (byte)(value + i);
                        }

                        view.WriteArray(position, array, 0, count);
                        Check.That(inRange, $"{where}: WriteArray outside the view");
                        array.CopyTo(model.AsSpan((int)(offset + position)));
                        break;
                    }
                }

                Check.That(inRange, $"{where}: access at {position} width {width} outside the {viewSize}-byte view didn't throw");
            }
            catch (Exception e) when (e is ArgumentOutOfRangeException or ArgumentException or NotSupportedException)
            {
                Check.That(!inRange, $"{where}: in-range access at {position} width {width} threw {e.GetType().Name}: {e.Message}");
            }
        }
    }
}
