#nullable disable warnings
using System.Buffers.Binary;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;

namespace SharpFuzzHarness;

/// <summary>
/// Memory safety of the readers over raw memory: System.Reflection.Metadata's BlobReader (pointer +
/// length, read through Unsafe) and UnmanagedMemoryAccessor / UnmanagedMemoryStream / SafeBuffer
/// (bounds arithmetic on positions and counts). The memory sits against a guard page (see
/// <see cref="Guarded"/>), so any access outside it faults; values are compared with a byte-array model.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     0-1 BlobReader, 2 UnmanagedMemoryAccessor, 3 UnmanagedMemoryStream; bit 7 memory at the start of a slot
///   byte 1     length of the memory (a few bytes to 255)
///   rest       the memory's contents, then operations (opcode byte + operand bytes)
/// Checks: reads within the memory return what the model says; reads that would go past it throw the
/// documented exception (BadImageFormatException for BlobReader, ArgumentException / ArgumentOutOfRangeException /
/// NotSupportedException for the unmanaged accessors) instead of touching the guard page.
/// </remarks>
public static unsafe class UnsafeMemoryTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        int length = input.Byte();
        byte[] contents = input.Bytes(length).ToArray();
        length = contents.Length;
        byte* p = Guarded.Allocate(length, atStart: (mode & 0x80) != 0);
        contents.CopyTo(new Span<byte>(p, length));
        switch (mode & 3)
        {
            case 0 or 1:
                Blob(p, contents, ref input);
                break;
            case 2:
                Accessor(p, contents, ref input);
                break;
            default:
                Stream(p, contents, ref input);
                break;
        }
    }

    private static void Blob(byte* p, byte[] model, ref FuzzInput input)
    {
        var reader = new BlobReader(p, model.Length);
        var log = new List<string>();
        for (int step = 0; input.Remaining > 0 && step < 64; step++)
        {
            byte op = input.Byte();
            int arg = input.Byte();
            int offset = reader.Offset;
            log.Add($"{op % 24}({arg})@{offset}");
            string what = $"BlobReader over {model.Length} bytes 0x{Convert.ToHexString(model.AsSpan(0, Math.Min(model.Length, 32)))}, ops [{string.Join(" ", log)}]";
            int size = (op % 24) switch { 0 => 1, 1 => 2, 2 => 4, 3 => 8, 4 => 4, 5 => 8, 6 => 16, 7 => 16, 8 => 8, 9 => 2, _ => -1 };
            if (size > 0)
            {
                bool fits = offset + size <= model.Length;
                var value = Outcome<string>.Of(() => (op % 24) switch
                {
                    0 => reader.ReadByte().ToString(),
                    1 => reader.ReadInt16().ToString(),
                    2 => reader.ReadInt32().ToString(),
                    3 => reader.ReadInt64().ToString(),
                    4 => BitConverter.SingleToInt32Bits(reader.ReadSingle()).ToString(),
                    5 => BitConverter.DoubleToInt64Bits(reader.ReadDouble()).ToString(),
                    6 => reader.ReadGuid().ToString(),
                    7 => reader.ReadDecimal().ToString(System.Globalization.CultureInfo.InvariantCulture),
                    8 => reader.ReadDateTime().Ticks.ToString(),
                    _ => ((int)reader.ReadChar()).ToString(),
                    // Known (BLOB-DT-1): ReadDateTime lets the DateTime constructor's ArgumentOutOfRangeException
                    // through for invalid ticks instead of BadImageFormatException.
                }, e => e is BadImageFormatException || !s_reportKnownIssues && (op % 24) == 8 && e is ArgumentOutOfRangeException);
                Check.That(value.Ok == fits || (op % 24) is 7 or 8 && !value.Ok, $"read of {size} bytes at {offset} gave {value}: {what}");
                if (value.Ok && (op % 24) is >= 0 and <= 3)
                {
                    string expected = (op % 24) switch
                    {
                        0 => model[offset].ToString(),
                        1 => BinaryPrimitives.ReadInt16LittleEndian(model.AsSpan(offset)).ToString(),
                        2 => BinaryPrimitives.ReadInt32LittleEndian(model.AsSpan(offset)).ToString(),
                        _ => BinaryPrimitives.ReadInt64LittleEndian(model.AsSpan(offset)).ToString(),
                    };
                    Check.Equal(expected, value.Value, $"value at {offset}: {what}");
                }

                // A read past the end must not move the offset (ReadDecimal / ReadDateTime validate after reading).
                if (!value.Ok && !fits)
                {
                    Check.Equal(offset, reader.Offset, $"a failed read moved the offset: {what}");
                }

                continue;
            }

            _ = Outcome<object>.Of(() => (op % 24) switch
            {
                10 => reader.ReadCompressedInteger(),
                11 => reader.ReadCompressedSignedInteger(),
                12 => reader.TryReadCompressedInteger(out int v) ? v : -1,
                13 => reader.ReadBytes(arg % 40).Length,
                14 => reader.ReadUTF8(arg % 40),
                15 => reader.ReadUTF16(arg % 40),
                16 => reader.ReadSerializedString(),
                17 => reader.ReadSignatureHeader().RawValue,
                18 => reader.ReadTypeHandle().IsNil,
                19 => reader.ReadBlobHandle().IsNil,
                20 => reader.ReadConstant((ConstantTypeCode)(arg % 20)),
                21 => SetOffset(ref reader, arg),
                22 => Align(ref reader, arg),
                _ => reader.IndexOf((byte)arg),
            }, e => e is BadImageFormatException or ArgumentOutOfRangeException or ArgumentException);
            Check.That(reader.Offset >= 0 && reader.Offset <= model.Length, $"Offset {reader.Offset} outside 0..{model.Length}: {what}");
            Check.Equal(model.Length - reader.Offset, reader.RemainingBytes, $"RemainingBytes: {what}");
        }
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    private static object SetOffset(ref BlobReader reader, int offset)
    {
        reader.Offset = offset % 300;
        return reader.Offset;
    }

    private static object Align(ref BlobReader reader, int alignment)
    {
        reader.Align((byte)(1 << (alignment % 4)));
        return reader.Offset;
    }

    private sealed class Buffer : SafeBuffer
    {
        public Buffer(byte* p, int length)
            : base(ownsHandle: false)
        {
            SetHandle((nint)p);
            Initialize((ulong)length);
        }

        protected override bool ReleaseHandle() => true;
    }

    private static void Accessor(byte* p, byte[] model, ref FuzzInput input)
    {
        using var buffer = new Buffer(p, model.Length);
        long offset = model.Length == 0 ? 0 : input.Byte() % (model.Length + 1);
        long capacity = model.Length - offset - (input.Byte() % 3 == 0 ? 0 : input.Byte() % (model.Length - offset + 1));
        capacity = Math.Max(0, capacity);
        using var accessor = new UnmanagedMemoryAccessor(buffer, offset, capacity, FileAccess.ReadWrite);
        var log = new List<string>();
        for (int step = 0; input.Remaining > 0 && step < 48; step++)
        {
            byte op = input.Byte();
            long position = (sbyte)input.Byte() + (op & 0x80) * 2;
            int count = input.Byte() % 12;
            log.Add($"{op % 12}@{position}x{count}");
            string what = $"accessor over [{offset}, +{capacity}) of {model.Length} bytes, ops [{string.Join(" ", log)}]";
            int size = (op % 12) switch { 0 => 1, 1 => 2, 2 => 4, 3 => 8, 4 => 16, 5 => 8, 6 => 4, 7 => 16, _ => 0 };
            bool fits = position >= 0 && position + size <= capacity;
            if (size > 0)
            {
                var value = Outcome<string>.Of(() => (op % 12) switch
                {
                    0 => accessor.ReadByte(position).ToString(),
                    1 => accessor.ReadInt16(position).ToString(),
                    2 => accessor.ReadInt32(position).ToString(),
                    3 => accessor.ReadInt64(position).ToString(),
                    4 => accessor.ReadDecimal(position).ToString(System.Globalization.CultureInfo.InvariantCulture),
                    5 => BitConverter.DoubleToInt64Bits(accessor.ReadDouble(position)).ToString(),
                    6 => Write(accessor, position, model, offset),
                    _ => Struct(accessor, position),
                }, e => e is ArgumentException or InvalidOperationException);
                Check.That(value.Ok == fits || (op % 12) == 4 && fits && !value.Ok, $"access of {size} bytes at {position} gave {value}: {what}");
                if (value.Ok && (op % 12) is >= 0 and <= 3)
                {
                    long at = offset + position;
                    string expected = (op % 12) switch
                    {
                        0 => model[at].ToString(),
                        1 => BinaryPrimitives.ReadInt16LittleEndian(model.AsSpan((int)at)).ToString(),
                        2 => BinaryPrimitives.ReadInt32LittleEndian(model.AsSpan((int)at)).ToString(),
                        _ => BinaryPrimitives.ReadInt64LittleEndian(model.AsSpan((int)at)).ToString(),
                    };
                    Check.Equal(expected, value.Value, $"value at {position}: {what}");
                }
            }
            else
            {
                // Arrays: ReadArray / WriteArray of count Int32s at position, into / from an array at an offset.
                int[] array = new int[16];
                int arrayOffset = (op >> 4) % 8;
                var n = Outcome<int>.Of(() => (op % 12) switch
                {
                    8 => accessor.ReadArray(position, array, arrayOffset, count),
                    9 => Fill(accessor, position, array, arrayOffset, count, model, offset),
                    10 => ReadSpan(buffer, position, count),
                    _ => WriteSpan(buffer, position, count, model),
                }, e => e is ArgumentException or InvalidOperationException);
                if ((op % 12) is 8 && n.Ok)
                {
                    long available = Math.Max(0, (capacity - position) / 4);
                    Check.That(position >= 0 && position <= capacity && n.Value == Math.Min(count, available), $"ReadArray read {n.Value}: {what}");
                }

                if ((op % 12) is 10 or 11 && n.Ok)
                {
                    Check.That(Math.Max(0, position) + count * 2 <= model.Length, $"SafeBuffer span access of {count * 2} bytes at {position} succeeded: {what}");
                }
            }
        }

        // Anything written through the accessor must be what the model holds.
        Check.That(new ReadOnlySpan<byte>(p, model.Length).SequenceEqual(model), $"memory differs from the model after ops [{string.Join(" ", log)}]");
    }

    private static string Write(UnmanagedMemoryAccessor accessor, long position, byte[] model, long offset)
    {
        int value = (int)(position * 2654435761u);
        accessor.Write(position, value);
        BinaryPrimitives.WriteInt32LittleEndian(model.AsSpan((int)(offset + position)), value);
        return value.ToString();
    }

    private static int Fill(UnmanagedMemoryAccessor accessor, long position, int[] array, int arrayOffset, int count, byte[] model, long offset)
    {
        for (int i = 0; i < array.Length; i++)
        {
            array[i] = (int)(0x9E3779B9u * (uint)(i + 1));
        }

        accessor.WriteArray(position, array, arrayOffset, count);
        int n = Math.Min(count, array.Length - arrayOffset);
        MemoryMarshal.AsBytes(array.AsSpan(arrayOffset, n)).CopyTo(model.AsSpan((int)(offset + position)));
        return count;
    }

    private static int ReadSpan(SafeBuffer buffer, long position, int count)
    {
        buffer.ReadSpan<short>((ulong)Math.Max(0, position), new short[count]);
        return count;
    }

    private static int WriteSpan(SafeBuffer buffer, long position, int count, byte[] model)
    {
        short[] values = Enumerable.Range(1, count).Select(i => (short)(i * 7919)).ToArray();
        buffer.WriteSpan<short>((ulong)Math.Max(0, position), values);
        MemoryMarshal.AsBytes(values.AsSpan()).CopyTo(model.AsSpan((int)Math.Max(0, position)));
        return count;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct Sixteen
    {
        public long A;
        public int B;
        public short C;
        public byte D;
        public byte E;
    }

    private static string Struct(UnmanagedMemoryAccessor accessor, long position)
    {
        accessor.Read(position, out Sixteen s);
        return $"{s.A}/{s.B}/{s.C}/{s.D}/{s.E}";
    }

    private static void Stream(byte* p, byte[] model, ref FuzzInput input)
    {
        int length = model.Length == 0 ? 0 : input.Byte() % (model.Length + 1);
        using var stream = new UnmanagedMemoryStream(p, length, model.Length, FileAccess.ReadWrite);
        long position = 0, streamLength = length;
        var log = new List<string>();
        for (int step = 0; input.Remaining > 0 && step < 48; step++)
        {
            byte op = input.Byte();
            int arg = input.Byte();
            log.Add($"{op % 8}({arg})");
            string what = $"UnmanagedMemoryStream capacity {model.Length}, ops [{string.Join(" ", log)}]";
            switch (op % 8)
            {
                case 0:
                {
                    byte[] buffer = new byte[arg % 64];
                    int read = stream.Read(buffer, 0, buffer.Length);
                    int expected = (int)Math.Max(0, Math.Min(buffer.Length, streamLength - position));
                    Check.Equal(expected, read, $"Read count: {what}");
                    Check.That(read == 0 || buffer.AsSpan(0, read).SequenceEqual(model.AsSpan((int)position, read)), $"Read data: {what}");
                    position += read;
                    break;
                }

                case 1:
                {
                    byte[] buffer = Enumerable.Range(0, arg % 64).Select(i => (byte)(i + arg)).ToArray();
                    bool fits = position + buffer.Length <= model.Length;
                    var wrote = Outcome<bool>.Of(() => { stream.Write(buffer, 0, buffer.Length); return true; }, e => e is NotSupportedException or IOException);
                    Check.Equal(fits, wrote.Ok, $"Write of {buffer.Length} at {position}: {what}");
                    if (wrote.Ok)
                    {
                        if (position > streamLength)
                        {
                            Array.Clear(model, (int)streamLength, (int)(position - streamLength));
                        }

                        buffer.CopyTo(model, position);
                        position += buffer.Length;
                        streamLength = Math.Max(streamLength, position);
                    }

                    break;
                }

                case 2:
                {
                    long target = (sbyte)arg * 3;
                    var seek = Outcome<long>.Of(() => stream.Seek(target, (SeekOrigin)(op / 8 % 3)), e => e is IOException or ArgumentException);
                    long expected = (op / 8 % 3) switch { 0 => target, 1 => position + target, _ => streamLength + target };
                    Check.Equal(expected >= 0, seek.Ok, $"Seek({target}, {(SeekOrigin)(op / 8 % 3)}): {what}");
                    if (seek.Ok)
                    {
                        Check.Equal(expected, seek.Value, $"Seek result: {what}");
                        position = expected;
                    }

                    break;
                }

                case 3:
                {
                    long newLength = arg * 2;
                    var set = Outcome<bool>.Of(() => { stream.SetLength(newLength); return true; }, e => e is IOException or NotSupportedException or ArgumentException);
                    Check.Equal(newLength <= model.Length, set.Ok, $"SetLength({newLength}): {what}");
                    if (set.Ok)
                    {
                        if (newLength > streamLength)
                        {
                            Array.Clear(model, (int)streamLength, (int)(newLength - streamLength));
                        }

                        streamLength = newLength;
                        position = Math.Min(position, newLength);
                    }

                    break;
                }

                case 4:
                {
                    int b = stream.ReadByte();
                    Check.Equal(position < streamLength ? model[position] : -1, b, $"ReadByte: {what}");
                    if (b >= 0)
                    {
                        position++;
                    }

                    break;
                }

                case 5:
                {
                    var wrote = Outcome<bool>.Of(() => { stream.WriteByte((byte)arg); return true; }, e => e is NotSupportedException or IOException);
                    Check.Equal(position < model.Length, wrote.Ok, $"WriteByte at {position}: {what}");
                    if (wrote.Ok)
                    {
                        if (position > streamLength)
                        {
                            Array.Clear(model, (int)streamLength, (int)(position - streamLength));
                        }

                        model[position++] = (byte)arg;
                        streamLength = Math.Max(streamLength, position);
                    }

                    break;
                }

                case 6:
                {
                    Span<byte> span = stackalloc byte[arg % 48];
                    int read = stream.Read(span);
                    int expected = (int)Math.Max(0, Math.Min(span.Length, streamLength - position));
                    Check.Equal(expected, read, $"Read(span) count: {what}");
                    Check.That(read == 0 || span[..read].SequenceEqual(model.AsSpan((int)position, read)), $"Read(span) data: {what}");
                    position += read;
                    break;
                }

                default:
                {
                    long target = (sbyte)arg * 2;
                    var set = Outcome<bool>.Of(() => { stream.Position = target; return true; }, e => e is ArgumentOutOfRangeException);
                    Check.Equal(target >= 0, set.Ok, $"Position = {target}: {what}");
                    if (set.Ok)
                    {
                        position = target;
                    }

                    break;
                }
            }

            Check.Equal(position, stream.Position, $"Position: {what}");
            Check.Equal(streamLength, stream.Length, $"Length: {what}");
        }

        Check.That(new ReadOnlySpan<byte>(p, (int)Math.Min(streamLength, model.Length)).SequenceEqual(model.AsSpan(0, (int)Math.Min(streamLength, model.Length))), $"memory differs from the model after ops [{string.Join(" ", log)}]");
    }
}
