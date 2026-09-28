#nullable disable warnings
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// Interop marshalling over native memory that sits against a guard page (see <see cref="Guarded"/>):
/// Marshal.PtrToStructure / StructureToPtr for structs with by-value strings and arrays, bools and
/// explicit layouts, from and into exactly Marshal.SizeOf bytes; the PtrToString* family with lengths
/// and NUL-terminated (the NUL being the last byte before the guard page); MemoryMarshal
/// CreateReadOnlySpanFromNullTerminated; the source-generated string marshallers; and string to
/// native round trips.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     operation; byte 1 placement bits
///   rest       the native bytes
/// </remarks>
public static unsafe class UnsafeMarshalTarget
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct Wide
    {
        public int A;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)] public string Name;
        public byte B;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)] public short[] Arr;
        [MarshalAs(UnmanagedType.Bool)] public bool Flag;
        public double D;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct Narrow
    {
        public byte A;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 7)] public string Name;
        public long L;
        [MarshalAs(UnmanagedType.U1)] public bool Flag;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)] public char[] Chars;
        [MarshalAs(UnmanagedType.I1)] public bool Small;
    }

    [StructLayout(LayoutKind.Explicit, Size = 24)]
    public struct Overlap
    {
        [FieldOffset(0)] public long L;
        [FieldOffset(4)] public int I;
        [FieldOffset(8)] public double D;
        [FieldOffset(20)] public float F;
        [FieldOffset(23)] public byte B;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public sealed class Holder
    {
        public int X;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 3)] public string S;
        public Narrow Inner;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)] public Overlap[] Items;
    }

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte op = input.Byte();
        byte place = input.Byte();
        byte[] bytes = input.Rest().ToArray();
        if (bytes.Length > 4096)
        {
            return;
        }

        bool atStart = (place & 1) != 0;
        string what = $"op {op % 5} place {place:X2}, {bytes.Length} bytes 0x{Convert.ToHexString(bytes.AsSpan(0, Math.Min(bytes.Length, 48)))}";
        switch (op % 5)
        {
            case 0: Structure<Wide>(bytes, atStart, what); break;
            case 1: Structure<Narrow>(bytes, atStart, what); break;
            case 2: Structure<Overlap>(bytes, atStart, what); Class(bytes, atStart, what); break;
            case 3: Strings(bytes, atStart, what); break;
            default: Terminated(bytes, place, what); break;
        }
    }

    private static byte* Native(ReadOnlySpan<byte> bytes, bool atStart)
    {
        byte* p = Guarded.Allocate(bytes.Length, atStart);
        bytes.CopyTo(new Span<byte>(p, bytes.Length));
        return p;
    }

    /// <summary>Reads a struct from exactly SizeOf bytes, writes it back into exactly SizeOf bytes, reads it again.</summary>
    private static void Structure<T>(byte[] bytes, bool atStart, string what) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        byte[] raw = new byte[size];
        bytes.AsSpan(0, Math.Min(size, bytes.Length)).CopyTo(raw);
        byte* p = Native(raw, atStart);
        T first = Marshal.PtrToStructure<T>((nint)p);
        byte* q = Guarded.Allocate(size, !atStart);
        new Span<byte>(q, size).Fill(0xCC);
        if (!ToNative(first, q, what))
        {
            return;
        }

        T second = Marshal.PtrToStructure<T>((nint)q);
        Check.That(Same(first, second), $"{typeof(T).Name} doesn't survive StructureToPtr / PtrToStructure: {Describe(first)} vs {Describe(second)}: {what}");
        Marshal.DestroyStructure<T>((nint)q);
    }

    private static void Class(byte[] bytes, bool atStart, string what)
    {
        int size = Marshal.SizeOf<Holder>();
        byte[] raw = new byte[size];
        bytes.AsSpan(0, Math.Min(size, bytes.Length)).CopyTo(raw);
        byte* p = Native(raw, atStart);
        var first = new Holder();
        Marshal.PtrToStructure((nint)p, first);
        byte* q = Guarded.Allocate(size, !atStart);
        if (!ToNative(first, q, what))
        {
            return;
        }

        Holder second = Marshal.PtrToStructure<Holder>((nint)q);
        Check.That(first.X == second.X && SameString(first.S, second.S, 3) && Same(first.Inner, second.Inner) && first.Items.Zip(second.Items).All(t => Same(t.First, t.Second)),
            $"Holder doesn't survive StructureToPtr / PtrToStructure: {what}");
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    // Known (MARSHAL-TSTR-1): an ANSI (UTF-8) by-value string is encoded into SizeConst bytes, which throws
    // ArgumentException when the UTF-8 is longer (ASCII strings are truncated instead).
    private static bool ToNative(object value, byte* native, string what)
    {
        try
        {
            Marshal.StructureToPtr(value, (nint)native, fDeleteOld: false);
            return true;
        }
        catch (ArgumentException e) when (!s_reportKnownIssues && e.StackTrace?.Contains("CSTRMarshaler.ConvertFixedToNative", StringComparison.Ordinal) == true)
        {
            return false;
        }
    }

    private static string Describe<T>(T value) => value switch
    {
        Wide w => $"Wide({w.A}, {Check.Show(w.Name)}, {w.B}, [{string.Join(",", w.Arr ?? [])}], {w.Flag}, {w.D})",
        Narrow n => $"Narrow({n.A}, {Check.Show(n.Name)}, {n.L}, {n.Flag}, {Check.Show(new string(n.Chars ?? []))}, {n.Small})",
        Overlap o => $"Overlap({o.L}, {o.I}, {o.D}, {o.F}, {o.B})",
        _ => value?.ToString(),
    };

    // By-value strings are cut at SizeConst - 1 characters (plus the NUL) when written, and ANSI
    // strings are converted through UTF-8 here, so only ASCII names are compared exactly.
    private static bool SameString(string a, string b, int sizeConst) =>
        a == b || a is not null && b is not null && (a.Length >= sizeConst - 1 && a.StartsWith(b, StringComparison.Ordinal) || a.Any(c => c > 0x7F));

    private static bool Same<T>(T a, T b) => (a, b) switch
    {
        (Wide x, Wide y) => x.A == y.A && SameString(x.Name, y.Name, 16) && x.B == y.B && x.Arr.SequenceEqual(y.Arr) && x.Flag == y.Flag && BitConverter.DoubleToInt64Bits(x.D) == BitConverter.DoubleToInt64Bits(y.D),
        (Narrow x, Narrow y) => x.A == y.A && SameString(x.Name, y.Name, 7) && x.L == y.L && x.Flag == y.Flag && (x.Chars.SequenceEqual(y.Chars) || x.Chars.Any(c => c > 0x7F)) && x.Small == y.Small,
        (Overlap x, Overlap y) => x.L == y.L && x.I == y.I && BitConverter.DoubleToInt64Bits(x.D) == BitConverter.DoubleToInt64Bits(y.D) && BitConverter.SingleToInt32Bits(x.F) == BitConverter.SingleToInt32Bits(y.F) && x.B == y.B,
        _ => Equals(a, b),
    };

    /// <summary>Strings from native memory with explicit lengths, and strings to native memory and back.</summary>
    private static void Strings(byte[] bytes, bool atStart, string what)
    {
        byte* p = Native(bytes, atStart);
        Check.Equal(Encoding.UTF8.GetString(bytes), Marshal.PtrToStringUTF8((nint)p, bytes.Length), $"PtrToStringUTF8(ptr, length): {what}");
        Check.Equal(Encoding.UTF8.GetString(bytes), Marshal.PtrToStringAnsi((nint)p, bytes.Length), $"PtrToStringAnsi(ptr, length): {what}");
        Check.Equal(Encoding.UTF8.GetString(bytes), new string((sbyte*)p, 0, bytes.Length, Encoding.UTF8), $"new string(sbyte*, 0, length, UTF8): {what}");
        int chars = bytes.Length / 2;
        byte* w = Native(bytes.AsSpan(0, chars * 2), !atStart);
        string wide = new string(MemoryMarshal.Cast<byte, char>(bytes.AsSpan(0, chars * 2))); // raw chars, lone surrogates included
        Check.Equal(wide, Marshal.PtrToStringUni((nint)w, chars), $"PtrToStringUni(ptr, length): {what}");
        Check.Equal(wide, new string((char*)w, 0, chars), $"new string(char*, 0, length): {what}");

        // Managed strings to native memory and back (the text is the UTF-8 decoding of the bytes).
        string text = Encoding.UTF8.GetString(bytes);
        foreach (int kind in (int[])[0, 1, 2, 3])
        {
            nint native = kind switch
            {
                0 => Marshal.StringToHGlobalUni(text),
                1 => Marshal.StringToCoTaskMemUTF8(text),
                2 => Marshal.StringToHGlobalAnsi(text),
                _ => (nint)Utf8StringMarshaller.ConvertToUnmanaged(text),
            };
            string back = kind switch
            {
                0 => Marshal.PtrToStringUni(native),
                1 => Marshal.PtrToStringUTF8(native),
                2 => Marshal.PtrToStringAnsi(native),
                _ => Utf8StringMarshaller.ConvertToManaged((byte*)native),
            };
            string expected = text.Contains('\0') ? text[..text.IndexOf('\0')] : text;
            Check.Equal(expected, back, $"string to native ({kind}) and back: {what}");
            switch (kind)
            {
                case 0: case 2: Marshal.FreeHGlobal(native); break;
                case 1: Marshal.FreeCoTaskMem(native); break;
                default: Utf8StringMarshaller.Free((byte*)native); break;
            }
        }
    }

    /// <summary>NUL-terminated strings whose terminator is the last byte (char) before the guard page.</summary>
    private static void Terminated(byte[] bytes, byte place, string what)
    {
        int nul = bytes.AsSpan().IndexOf((byte)0);
        byte[] s = (nul >= 0 ? bytes.AsSpan(0, nul) : bytes).ToArray();
        byte[] z = [.. s, 0];
        byte* p = Guarded.Allocate(z.Length, atStart: false);
        z.CopyTo(new Span<byte>(p, z.Length));
        string expected = Encoding.UTF8.GetString(s);
        Check.Equal(s.Length, MemoryMarshal.CreateReadOnlySpanFromNullTerminated(p).Length, $"CreateReadOnlySpanFromNullTerminated(byte*): {what}");
        Check.Equal(expected, Marshal.PtrToStringUTF8((nint)p), $"PtrToStringUTF8(ptr): {what}");
        Check.Equal(expected, Marshal.PtrToStringAnsi((nint)p), $"PtrToStringAnsi(ptr): {what}");
        Check.Equal(expected, Utf8StringMarshaller.ConvertToManaged(p), $"Utf8StringMarshaller.ConvertToManaged: {what}");
        Check.Equal(expected, AnsiStringMarshaller.ConvertToManaged(p), $"AnsiStringMarshaller.ConvertToManaged: {what}");
        Check.Equal(expected, new string((sbyte*)p), $"new string(sbyte*): {what}");

        // UTF-16, the NUL char last.
        char[] chars = Encoding.Unicode.GetString(bytes, 0, bytes.Length & ~1).ToCharArray();
        int nulChar = Array.IndexOf(chars, '\0');
        char[] cs = (nulChar >= 0 ? chars.AsSpan(0, nulChar) : chars).ToArray();
        char[] cz = [.. cs, '\0'];
        char* c = (char*)Guarded.Allocate(cz.Length * 2L, atStart: false);
        cz.CopyTo(new Span<char>(c, cz.Length));
        Check.Equal(cs.Length, MemoryMarshal.CreateReadOnlySpanFromNullTerminated(c).Length, $"CreateReadOnlySpanFromNullTerminated(char*): {what}");
        Check.Equal(new string(cs), Marshal.PtrToStringUni((nint)c), $"PtrToStringUni(ptr): {what}");
        Check.Equal(new string(cs), Utf16StringMarshaller.ConvertToManaged((ushort*)c), $"Utf16StringMarshaller.ConvertToManaged: {what}");
        Check.Equal(new string(cs), new string(c), $"new string(char*): {what}");
    }
}
