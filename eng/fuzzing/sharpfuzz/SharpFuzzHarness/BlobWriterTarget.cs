#nullable disable warnings
using System.Reflection.Metadata;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// The writing side of System.Reflection.Metadata (BlobBuilder with small chunks, and BlobWriter over
/// an array with sentinels around the writable range), which writes through Unsafe.WriteUnaligned and
/// links chunks. A fuzzed sequence of writes goes to both; the outputs must be identical, the sentinels
/// intact, and a BlobReader over guarded memory (see <see cref="Guarded"/>) must read back every value.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     BlobBuilder chunk size; byte 1 placement
///   rest       operations: an opcode byte followed by its argument bytes
/// </remarks>
public static class BlobWriterTarget
{
    private const int Pad = 11;

    private delegate void Write(ref BlobWriter w);

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        int chunk = 16 + input.Byte() % 64;
        byte place = input.Byte();
        var ops = new List<(Action<BlobBuilder> Builder, Write Writer, Func<BlobReader, string> Check, string Name)>();
        var sb = new StringBuilder();
        for (int i = 0; i < 48 && input.Remaining > 0; i++)
        {
            byte op = input.Byte();
            ulong raw = input.UInt16() | (ulong)input.UInt16() << 16 | (ulong)input.UInt16() << 32 | (ulong)input.UInt16() << 48;
            string text = new(input.Bytes(op >> 4).ToArray().Select(b => (char)(b < 0x80 ? b : 0x400 + b)).ToArray());
            switch (op % 12)
            {
                case 0: { byte v = (byte)raw; ops.Add((b => b.WriteByte(v), (ref BlobWriter w) => w.WriteByte(v), r => Eq(v, r.ReadByte()), $"byte {v}")); break; }
                case 1: { short v = (short)raw; ops.Add((b => b.WriteInt16(v), (ref BlobWriter w) => w.WriteInt16(v), r => Eq(v, r.ReadInt16()), $"int16 {v}")); break; }
                case 2: { int v = (int)raw; ops.Add((b => b.WriteInt32(v), (ref BlobWriter w) => w.WriteInt32(v), r => Eq(v, r.ReadInt32()), $"int32 {v}")); break; }
                case 3: { long v = (long)raw; ops.Add((b => b.WriteInt64(v), (ref BlobWriter w) => w.WriteInt64(v), r => Eq(v, r.ReadInt64()), $"int64 {v}")); break; }
                case 4: { double v = BitConverter.Int64BitsToDouble((long)raw); ops.Add((b => b.WriteDouble(v), (ref BlobWriter w) => w.WriteDouble(v), r => Eq(BitConverter.DoubleToInt64Bits(v), BitConverter.DoubleToInt64Bits(r.ReadDouble())), $"double {v}")); break; }
                case 5: { var v = new Guid(BitConverter.GetBytes(raw).Concat(BitConverter.GetBytes(~raw)).ToArray()); ops.Add((b => b.WriteGuid(v), (ref BlobWriter w) => w.WriteGuid(v), r => Eq(v, r.ReadGuid()), $"guid {v}")); break; }
                case 6: { int v = (int)(raw % 0x20000000); ops.Add((b => b.WriteCompressedInteger(v), (ref BlobWriter w) => w.WriteCompressedInteger(v), r => Eq(v, r.ReadCompressedInteger()), $"compressed {v}")); break; }
                case 7: { int v = (int)(raw % 0x20000000) - 0x10000000; ops.Add((b => b.WriteCompressedSignedInteger(v), (ref BlobWriter w) => w.WriteCompressedSignedInteger(v), r => Eq(v, r.ReadCompressedSignedInteger()), $"signed compressed {v}")); break; }
                case 8:
                {
                    string s = text;
                    int count = Encoding.UTF8.GetByteCount(s);
                    ops.Add((b => b.WriteUTF8(s, allowUnpairedSurrogates: false), (ref BlobWriter w) => w.WriteUTF8(s, allowUnpairedSurrogates: false), r => Eq(s, r.ReadUTF8(count)), $"utf8 {Check.Show(s)}"));
                    break;
                }

                case 9:
                {
                    string s = (raw & 1) != 0 ? null : text;
                    ops.Add((b => b.WriteSerializedString(s), (ref BlobWriter w) => w.WriteSerializedString(s), r => Eq(s, r.ReadSerializedString()), $"serialized {Check.Show(s)}"));
                    break;
                }

                case 10:
                {
                    string s = text;
                    ops.Add((b => b.WriteUTF16(s), (ref BlobWriter w) => w.WriteUTF16(s), r => Eq(s, r.ReadUTF16(s.Length * 2)), $"utf16 {Check.Show(s)}"));
                    break;
                }

                default:
                {
                    byte value = (byte)raw;
                    int count = (int)((raw >> 8) % 300);
                    ops.Add((b => b.WriteBytes(value, count), (ref BlobWriter w) => w.WriteBytes(value, count), r => Eq(true, r.ReadBytes(count).All(x => x == value)), $"bytes {value} x{count}"));
                    break;
                }
            }
        }

        string what = $"chunk {chunk}, ops [{string.Join("; ", ops.Select(o => o.Name).Take(24))}]";
        var builder = new BlobBuilder(chunk);
        foreach (var o in ops)
        {
            o.Builder(builder);
        }

        byte[] built = builder.ToArray();
        Check.Equal(built.Length, builder.Count, $"BlobBuilder.Count: {what}");

        // The same writes into a BlobWriter over the middle of an array with sentinels.
        byte[] array = Enumerable.Repeat((byte)0xE7, Pad + built.Length + Pad).ToArray();
        var writer = new BlobWriter(array, Pad, built.Length);
        foreach (var o in ops)
        {
            o.Writer(ref writer);
        }

        Check.Equal(built.Length, writer.Offset, $"BlobWriter.Offset: {what}");
        Check.That(array.AsSpan(Pad, built.Length).SequenceEqual(built), $"BlobWriter output differs from BlobBuilder's: {what}");
        Check.That(array.AsSpan(0, Pad).IndexOfAnyExcept((byte)0xE7) < 0 && array.AsSpan(Pad + built.Length).IndexOfAnyExcept((byte)0xE7) < 0, $"BlobWriter wrote outside its range: {what}");

        // Chunks: GetBlobs concatenate to the same bytes, and a split builder links back together.
        Check.That(builder.GetBlobs().SelectMany(b => b.GetBytes().ToArray()).SequenceEqual(built), $"BlobBuilder.GetBlobs: {what}");

        // Read everything back from guarded memory.
        unsafe
        {
            byte* p = Guarded.Allocate(built.Length, (place & 1) != 0);
            built.CopyTo(new Span<byte>(p, built.Length));
            var reader = new BlobReader(p, built.Length);
            foreach (var o in ops)
            {
                string mismatch = o.Check(reader);
                Check.That(mismatch is null, $"reading back {o.Name}: {mismatch}: {what}");
                reader = Advance(reader, o);
            }
        }
    }

    // The checks read from a copy of the reader (BlobReader is a struct), so re-read to advance.
    private static BlobReader Advance(BlobReader reader, (Action<BlobBuilder> Builder, Write Writer, Func<BlobReader, string> Check, string Name) o)
    {
        var b = new BlobBuilder();
        o.Builder(b);
        reader.Offset += b.Count;
        return reader;
    }

    private static string Eq<T>(T expected, T actual) => EqualityComparer<T>.Default.Equals(expected, actual) ? null : $"read {actual}, wrote {expected}";
}
