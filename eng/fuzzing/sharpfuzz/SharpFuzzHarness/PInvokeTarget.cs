#nullable disable warnings
using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SharpFuzzHarness;

/// <summary>
/// Built-in (DllImport IL stub) and source-generated (LibraryImport) P/Invoke marshalling against
/// libc, whose results are checked against managed models: strings as LPStr / LPUTF8Str / LPWStr /
/// StringBuilder / custom marshaler / byte pointers, char / bool / string / struct arrays in and out
/// (the .NET 11 managed array element marshalers), by-ref / in / out structs, blittable struct
/// returns (div / ldiv), SetLastError and errno, qsort / bsearch with delegate and function-pointer
/// callbacks (arrays of ints, non-blittable structs and strings sorted in place), SafeHandle
/// parameters and returns over files in /dev/shm and pipes, NativeLibrary exports called through
/// delegates and function pointers, a DllImportResolver, and libm against System.Math. Native
/// buffers sit against guard pages.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     operation; byte 1 flags
///   rest       data (strings are NUL-separated segments)
/// </remarks>
public static unsafe partial class PInvokeTarget
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct Rec
    {
        public int Key;
        [MarshalAs(UnmanagedType.U1)] public bool Flag;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 6)] public string Name;
        public double D;
    }

    [StructLayout(LayoutKind.Sequential)] public struct DivT { public int Quot, Rem; }
    [StructLayout(LayoutKind.Sequential)] public struct LDivT { public long Quot, Rem; }
    [StructLayout(LayoutKind.Sequential)] public struct Tm { public int Sec, Min, Hour, MDay, Mon, Year, WDay, YDay, IsDst; public long GmtOff; public IntPtr Zone; }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate int QsortCmp(IntPtr a, IntPtr b);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate nuint StrlenFn([MarshalAs(UnmanagedType.LPUTF8Str)] string s);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate nuint StrlenRawFn(byte* s);

    /// <summary>An ICustomMarshaler for UTF-8 strings that counts its calls.</summary>
    public sealed class Utf8Marshaler : ICustomMarshaler
    {
        public static int Cleanups, ToNative, ToManaged;
        public static string LastCookie;
        private static readonly Utf8Marshaler s_instance = new();
        public static ICustomMarshaler GetInstance(string cookie) { LastCookie = cookie; return s_instance; }
        public object MarshalNativeToManaged(IntPtr p) { ToManaged++; return Marshal.PtrToStringUTF8(p); }
        public IntPtr MarshalManagedToNative(object o) { ToNative++; return Marshal.StringToCoTaskMemUTF8((string)o); }
        public void CleanUpNativeData(IntPtr p) { Cleanups++; Marshal.FreeCoTaskMem(p); }
        public void CleanUpManagedData(object o) { }
        public int GetNativeDataSize() => -1;
    }

    // ------------------------------------------------------------ DllImport (IL stubs)
    [DllImport("libc", EntryPoint = "strlen")] private static extern nuint strlen_utf8([MarshalAs(UnmanagedType.LPUTF8Str)] string s);
    [DllImport("libc", EntryPoint = "strlen", CharSet = CharSet.Ansi)] private static extern nuint strlen_ansi(string s);
    [DllImport("libc", EntryPoint = "strlen", CharSet = CharSet.Unicode)] private static extern nuint strlen_wide(string s);
    [DllImport("libc", EntryPoint = "strlen", CharSet = CharSet.Ansi)] private static extern nuint strlen_sb(StringBuilder s);
    [DllImport("libc", EntryPoint = "strlen")] private static extern nuint strlen_ptr(byte* s);
    [DllImport("libc", EntryPoint = "strlen")] private static extern nuint strlen_arr(byte[] s);
    [DllImport("libc", EntryPoint = "strlen")] private static extern nuint strlen_ref(ref byte s);
    [DllImport("libc", EntryPoint = "strlen")] private static extern nuint strlen_custom([MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(Utf8Marshaler), MarshalCookie = "ck")] string s);
    [DllImport("libc", EntryPoint = "strlen")] private static extern nuint strlen_bstr([MarshalAs(UnmanagedType.BStr)] string s);
    [DllImport("libc")] private static extern int strncmp([MarshalAs(UnmanagedType.LPUTF8Str)] string a, [MarshalAs(UnmanagedType.LPUTF8Str)] string b, nuint n);
    [DllImport("libc")] private static extern IntPtr strdup([MarshalAs(UnmanagedType.LPUTF8Str)] string s);
    [DllImport("libc")] private static extern void free(IntPtr p);
    [DllImport("libc")] private static extern IntPtr memchr(byte* s, int c, nuint n);
    [DllImport("libc")] private static extern int snprintf(byte* buf, nuint size, [MarshalAs(UnmanagedType.LPUTF8Str)] string fmt, long value);
    [DllImport("libc")] private static extern int memcmp(byte* a, byte* b, nuint n);
    [DllImport("libc", EntryPoint = "memcmp", CharSet = CharSet.Ansi)] private static extern int memcmp_chars([In] char[] a, [In] char[] b, nuint n);
    [DllImport("libc", EntryPoint = "memcpy", CharSet = CharSet.Ansi)] private static extern IntPtr memcpy_chars_out([Out] char[] dst, byte[] src, nuint n);
    [DllImport("libc", EntryPoint = "memcpy", CharSet = CharSet.Ansi)] private static extern IntPtr memcpy_chars_inout([In, Out] char[] dst, byte[] src, nuint n);
    [DllImport("libc", EntryPoint = "memcpy", CharSet = CharSet.Unicode)] private static extern IntPtr memcpy_wchars([Out] char[] dst, byte[] src, nuint n);
    [DllImport("libc", EntryPoint = "memcpy", CharSet = CharSet.Ansi)] private static extern IntPtr memcpy_sb(StringBuilder dst, byte[] src, nuint n);
    [DllImport("libc", EntryPoint = "memcpy", CharSet = CharSet.Unicode)] private static extern IntPtr memcpy_wsb(StringBuilder dst, byte[] src, nuint n);
    [DllImport("libc", EntryPoint = "memcpy")] private static extern IntPtr memcpy_bools([Out] bool[] dst, byte[] src, nuint n);
    [DllImport("libc", EntryPoint = "memcpy")] private static extern IntPtr memcpy_bools_u1([Out, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U1)] bool[] dst, byte[] src, nuint n);
    [DllImport("libc", EntryPoint = "memcpy")] private static extern IntPtr memcpy_strs([Out, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPStr, SizeParamIndex = 3)] string[] dst, IntPtr[] src, nuint n, int count);
    [DllImport("libc", EntryPoint = "memcpy")] private static extern IntPtr memcpy_recs([Out] Rec[] dst, byte* src, nuint n);
    [DllImport("libc", EntryPoint = "memcpy")] private static extern IntPtr memcpy_recs_in(byte* dst, [In] Rec[] src, nuint n);
    [DllImport("libc", EntryPoint = "memcpy")] private static extern IntPtr memcpy_rec_ref(byte* dst, ref Rec src, nuint n);
    [DllImport("libc", EntryPoint = "memcpy")] private static extern IntPtr memcpy_rec_in(byte* dst, in Rec src, nuint n);
    [DllImport("libc", EntryPoint = "memcpy")] private static extern IntPtr memcpy_rec_out(out Rec dst, byte* src, nuint n);
    [DllImport("libc", EntryPoint = "memcpy")] private static extern IntPtr memcpy_dec(byte* dst, [MarshalAs(UnmanagedType.LPStruct)] decimal d, nuint n);
    [DllImport("libc", EntryPoint = "memcpy")] private static extern IntPtr memcpy_guid(byte* dst, ref Guid g, nuint n);
    [DllImport("libc", EntryPoint = "memcpy")] private static extern IntPtr memcpy_ints(byte* dst, int[] src, nuint n);
    [DllImport("libc", EntryPoint = "memcpy")] private static extern IntPtr memcpy_ints_out([Out] int[] dst, byte* src, nuint n);
    [DllImport("libc", SetLastError = true)] private static extern long strtol(byte* s, out byte* end, int @base);
    [DllImport("libc", SetLastError = true)] private static extern ulong strtoul(byte* s, out byte* end, int @base);
    [DllImport("libc", SetLastError = true)] private static extern double strtod(byte* s, out byte* end);
    [DllImport("libc")] private static extern void qsort(int[] array, nuint n, nuint size, QsortCmp cmp);
    [DllImport("libc", EntryPoint = "qsort")] private static extern void qsort_recs([In, Out] Rec[] array, nuint n, nuint size, QsortCmp cmp);
    [DllImport("libc", EntryPoint = "qsort")] private static extern void qsort_strs([In, Out, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPStr)] string[] array, nuint n, nuint size, QsortCmp cmp);
    [DllImport("libc", EntryPoint = "qsort")] private static extern void qsort_ptr(void* array, nuint n, nuint size, delegate* unmanaged[Cdecl]<void*, void*, int> cmp);
    [DllImport("libc")] private static extern int* bsearch(ref int key, int* array, nuint n, nuint size, delegate* unmanaged[Cdecl]<void*, void*, int> cmp);
    [DllImport("libc", SetLastError = true)] private static extern SafeFileHandle open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, int mode);
    [DllImport("libc", SetLastError = true)] private static extern nint write(SafeFileHandle fd, byte* buf, nuint n);
    [DllImport("libc", SetLastError = true)] private static extern nint read(SafeFileHandle fd, byte* buf, nuint n);
    [DllImport("libc", SetLastError = true)] private static extern nint pread(SafeFileHandle fd, byte[] buf, nuint n, long offset);
    [DllImport("libc", SetLastError = true)] private static extern long lseek(SafeFileHandle fd, long offset, int whence);
    [DllImport("libc", SetLastError = true)] private static extern int close(int fd);
    [DllImport("libc", SetLastError = true)] private static extern int pipe([Out] int[] fds);
    [DllImport("libc", SetLastError = true)] private static extern int unlink([MarshalAs(UnmanagedType.LPUTF8Str)] string path);
    [DllImport("libc", SetLastError = true)] private static extern SafeFileHandle dup(SafeFileHandle fd);
    [DllImport("libc")] private static extern DivT div(int a, int b);
    [DllImport("libc")] private static extern LDivT ldiv(long a, long b);
    [DllImport("libc")] private static extern IntPtr gmtime_r(in long t, out Tm result);
    [DllImport("libm.so.6")] private static extern double cbrt(double x);
    [DllImport("libm.so.6")] private static extern double sin(double x);
    [DllImport("libm.so.6")] private static extern double cos(double x);
    [DllImport("libm.so.6")] private static extern double exp(double x);
    [DllImport("libm.so.6")] private static extern double log(double x);
    [DllImport("libm.so.6")] private static extern double log2(double x);
    [DllImport("libm.so.6")] private static extern double atan2(double y, double x);
    [DllImport("libm.so.6")] private static extern double fma(double x, double y, double z);
    [DllImport("libm.so.6")] private static extern float fmaf(float x, float y, float z);
    [DllImport("libm.so.6")] private static extern double copysign(double x, double y);
    [DllImport("libm.so.6")] private static extern double ldexp(double x, int e);
    [DllImport("libm.so.6")] private static extern double frexp(double x, out int e);
    [DllImport("libm.so.6")] private static extern double modf(double x, out double ip);
    [DllImport("libm.so.6")] private static extern int ilogb(double x);
    [DllImport("libm.so.6")] private static extern double nextafter(double x, double y);
    [DllImport("libm.so.6")] private static extern double fmod(double x, double y);
    [DllImport("libm.so.6")] private static extern double remainder(double x, double y);
    [DllImport("libm.so.6")] private static extern double sqrt(double x);
    [DllImport("libm.so.6")] private static extern float sqrtf(float x);
    [DllImport("libm.so.6")] private static extern double round(double x);
    [DllImport("libm.so.6")] private static extern double trunc(double x);
    [DllImport("fuzzlib", EntryPoint = "strlen")] private static extern nuint strlen_resolved(byte* s);

    // ------------------------------------------------------------ LibraryImport (source generated)
    [LibraryImport("libc", EntryPoint = "strlen", StringMarshalling = StringMarshalling.Utf8)] private static partial nuint li_strlen(string s);
    [LibraryImport("libc", EntryPoint = "strlen", StringMarshalling = StringMarshalling.Utf16)] private static partial nuint li_strlen16(string s);
    [LibraryImport("libc", EntryPoint = "strlen")] private static partial nuint li_strlen_span(ReadOnlySpan<byte> s);
    [LibraryImport("libc", EntryPoint = "memcpy")] private static partial IntPtr li_memcpy([Out] byte[] dst, [In] byte[] src, nuint n);
    [LibraryImport("libc", EntryPoint = "memcpy")] private static partial IntPtr li_memcpy_ints([Out] int[] dst, [In] int[] src, nuint n);
    [LibraryImport("libc", EntryPoint = "memcpy")] private static partial IntPtr li_memcpy_span(Span<byte> dst, ReadOnlySpan<byte> src, nuint n);
    [LibraryImport("libc", EntryPoint = "memcpy")] private static partial IntPtr li_memcpy_ref(ref byte dst, in byte src, nuint n);
    [LibraryImport("libc", EntryPoint = "memcpy")] private static partial IntPtr li_memcpy_bools([Out, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U1)] bool[] dst, [In] byte[] src, nuint n);
    [LibraryImport("libc", EntryPoint = "memcpy")] private static partial IntPtr li_memcpy_out(out int dst, in int src, nuint n);
    [LibraryImport("libc", EntryPoint = "strtol", SetLastError = true)] private static partial long li_strtol(ReadOnlySpan<byte> s, out IntPtr end, int b);
    [LibraryImport("libc", EntryPoint = "open", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)] private static partial SafeFileHandle li_open(string path, int flags, int mode);
    [LibraryImport("libc", EntryPoint = "write", SetLastError = true)] private static partial nint li_write(SafeFileHandle fd, ReadOnlySpan<byte> buf, nuint n);
    [LibraryImport("libc", EntryPoint = "pread", SetLastError = true)] private static partial nint li_pread(SafeFileHandle fd, Span<byte> buf, nuint n, long offset);
    [LibraryImport("libc", EntryPoint = "gmtime_r")] private static partial IntPtr li_gmtime_r(in long t, out Tm result);
    [LibraryImport("libc", EntryPoint = "qsort")] private static partial void li_qsort(Span<int> array, nuint n, nuint size, delegate* unmanaged[Cdecl]<void*, void*, int> cmp);
    [LibraryImport("libc", EntryPoint = "ldiv")] private static partial LDivT li_ldiv(long a, long b);
    [LibraryImport("libc", EntryPoint = "isatty")] [return: MarshalAs(UnmanagedType.I4)] private static partial bool li_isatty(int fd);
    [LibraryImport("libc", EntryPoint = "strncmp", StringMarshalling = StringMarshalling.Utf8)] private static partial int li_strncmp(string a, string b, nuint n);

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;
    private static readonly IntPtr s_libc;
    private static readonly delegate* unmanaged[Cdecl]<byte*, nuint> s_strlenPtr;
    private static readonly StrlenFn s_strlenDelegate;
    private static readonly StrlenRawFn s_strlenRawDelegate;
    private static int s_files;

    static PInvokeTarget()
    {
        s_libc = NativeLibrary.Load("libc.so.6");
        IntPtr strlen = NativeLibrary.GetExport(s_libc, "strlen");
        s_strlenPtr = (delegate* unmanaged[Cdecl]<byte*, nuint>)strlen;
        s_strlenDelegate = Marshal.GetDelegateForFunctionPointer<StrlenFn>(strlen);
        s_strlenRawDelegate = Marshal.GetDelegateForFunctionPointer<StrlenRawFn>(strlen);
        NativeLibrary.SetDllImportResolver(typeof(PInvokeTarget).Assembly, (name, assembly, path) => name == "fuzzlib" ? s_libc : IntPtr.Zero);
        Marshal.PrelinkAll(typeof(PInvokeTarget));
    }

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte op = input.Byte();
        byte flags = input.Byte();
        switch (op % 9)
        {
            case 0: Strings(ref input, flags); break;
            case 1: Arrays(ref input, flags); break;
            case 2: Numbers(ref input, flags); break;
            case 3: Sorting(ref input, flags); break;
            case 4: Files(ref input, flags); break;
            case 5: Structs(ref input, flags); break;
            case 6: Math_(ref input, flags); break;
            case 7: Library(ref input, flags); break;
            default: Generated(ref input, flags); break;
        }
    }

    /// <summary>NUL-terminated copy of <paramref name="bytes"/> against a guard page.</summary>
    private static byte* Terminated(ReadOnlySpan<byte> bytes, bool atStart)
    {
        byte* p = Guarded.Allocate(bytes.Length + 1, atStart);
        bytes.CopyTo(new Span<byte>(p, bytes.Length));
        p[bytes.Length] = 0;
        return p;
    }

    private static byte* Native(ReadOnlySpan<byte> bytes, bool atStart)
    {
        byte* p = Guarded.Allocate(bytes.Length, atStart);
        bytes.CopyTo(new Span<byte>(p, bytes.Length));
        return p;
    }

    /// <summary>Text from input bytes without NULs, as the UTF-8 marshallers will see it (lone surrogates become U+FFFD).</summary>
    private static string Utf8Text(ReadOnlySpan<byte> bytes)
    {
        string s = Encoding.UTF8.GetString(bytes).Replace("\0", "");
        return Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(s));
    }

    // ------------------------------------------------------------ strings

    private static void Strings(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        string s = Utf8Text(input.SegmentBytes());
        byte[] utf8 = Encoding.UTF8.GetBytes(s);
        nuint expected = (nuint)utf8.Length;
        string what = $"strlen of {Check.Show(s)}";
        Check.Equal(expected, strlen_utf8(s), $"LPUTF8Str {what}");
        Check.Equal(expected, strlen_ansi(s), $"LPStr {what}");
        Check.Equal(expected, strlen_custom(s), $"custom marshaler {what}");
        Check.Equal("ck", Utf8Marshaler.LastCookie, "custom marshaler cookie");
        Check.Equal(Utf8Marshaler.ToNative, Utf8Marshaler.Cleanups, "custom marshaler cleanup count");
        Check.Equal(expected, li_strlen(s), $"LibraryImport Utf8 {what}");
        Check.Equal(expected, s_strlenDelegate(s), $"delegate from NativeLibrary export {what}");
        Check.Equal(expected, strlen_sb(new StringBuilder(s)), $"StringBuilder {what}");
        // BSTR / UTF-16 pointers: strlen stops at the first zero byte of the UTF-16LE encoding.
        byte[] utf16 = Encoding.Unicode.GetBytes(s);
        int firstZero = Array.IndexOf(utf16, (byte)0);
        nuint expected16 = (nuint)(firstZero < 0 ? utf16.Length : firstZero);
        Check.Equal(expected16, strlen_wide(s), $"LPWStr {what}");
        Check.Equal(expected16, strlen_bstr(s), $"BStr {what}");
        Check.Equal(expected16, li_strlen16(s), $"LibraryImport Utf16 {what}");
        // Pointers / arrays / refs / spans of NUL-terminated bytes against the guard page.
        byte* p = Terminated(utf8, atStart);
        Check.Equal(expected, strlen_ptr(p), $"byte* {what}");
        Check.Equal(expected, s_strlenPtr(p), $"function pointer {what}");
        Check.Equal(expected, s_strlenRawDelegate(p), $"raw delegate {what}");
        Check.Equal(expected, strlen_resolved(p), $"DllImportResolver {what}");
        byte[] z = [.. utf8, 0];
        Check.Equal(expected, strlen_arr(z), $"byte[] {what}");
        Check.Equal(expected, strlen_ref(ref z[0]), $"ref byte {what}");
        Check.Equal(expected, li_strlen_span(new ReadOnlySpan<byte>(p, z.Length)), $"ReadOnlySpan<byte> {what}");
        // strncmp against the UTF-8 byte order.
        string t = Utf8Text(input.SegmentBytes());
        byte[] tb = Encoding.UTF8.GetBytes(t);
        nuint n = (nuint)(flags >> 1);
        int cmp = Math.Sign(strncmp(s, t, n));
        int expectedCmp = Math.Sign(utf8.AsSpan(0, Math.Min((int)n, utf8.Length)).SequenceCompareTo(tb.AsSpan(0, Math.Min((int)n, tb.Length))));
        Check.Equal(expectedCmp, cmp, $"strncmp({Check.Show(s)}, {Check.Show(t)}, {n})");
        Check.Equal(expectedCmp, Math.Sign(li_strncmp(s, t, n)), $"LibraryImport strncmp({Check.Show(s)}, {Check.Show(t)}, {n})");
        // strdup: an IntPtr return read back and freed.
        IntPtr dup = strdup(s);
        Check.Equal(s, Marshal.PtrToStringUTF8(dup), $"strdup {what}");
        free(dup);
        // memchr on guarded memory returns a pointer inside it or null.
        byte c = (byte)(flags >> 1);
        IntPtr found = memchr(p, c, expected);
        int idx = Array.IndexOf(utf8, c);
        Check.Equal(idx, found == IntPtr.Zero ? -1 : (int)((byte*)found - p), $"memchr({Check.Show(s)}, {c})");
        // snprintf with a long: a varargs integer.
        long v = (long)input.Int32() << 32 | (uint)input.Int32();
        string text = v.ToString(CultureInfo.InvariantCulture);
        int size = Math.Min(text.Length + 1, (flags >> 2) + 1);
        byte* buf = Guarded.Allocate(size, !atStart);
        int written = snprintf(buf, (nuint)size, "%ld", v);
        Check.Equal(text.Length, written, $"snprintf %ld {v}");
        Check.Equal(text.Substring(0, size - 1), Marshal.PtrToStringUTF8((IntPtr)buf), $"snprintf %ld {v} into {size} bytes");
    }

    // ------------------------------------------------------------ arrays and buffers

    private static void Arrays(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        byte[] bytes = input.Bytes(Math.Min(input.Remaining, 200)).ToArray();
        int n = bytes.Length;
        string what = $"{n} bytes 0x{Convert.ToHexString(bytes.AsSpan(0, Math.Min(n, 24)))}";

        // ANSI char[]: one byte per char natively (the .NET 11 AnsiCharArrayMarshaler), in and out.
        char[] chars = bytes.Select(b => (char)(b & 0x7F)).ToArray();
        char[] other = chars.ToArray();
        if (n > 0)
        {
            other[n / 2] = (char)(other[n / 2] ^ 1);
        }

        Check.Equal(0, memcmp_chars(chars, chars.ToArray(), (nuint)n), $"memcmp of equal ANSI char[]: {what}");
        Check.Equal(n == 0 ? 0 : Math.Sign(chars[n / 2] - other[n / 2]), Math.Sign(memcmp_chars(chars, other, (nuint)n)), $"memcmp of differing ANSI char[]: {what}");
        char[] outChars = new char[n];
        memcpy_chars_out(outChars, bytes, (nuint)n);
        Check.Equal(n, outChars.Length, $"[Out] ANSI char[] length: {what}");
        // Known (MARSHAL-CHARARR-1): the bytes are decoded as one UTF-8 string, so multi-byte or invalid
        // sequences shift the following elements; only all-ASCII contents are byte-per-char.
        if (s_reportKnownIssues || bytes.All(b => b < 0x80))
        {
            for (int i = 0; i < n; i++)
            {
                if (bytes[i] < 0x80)
                {
                    Check.Equal((char)bytes[i], outChars[i], $"[Out] ANSI char[] element {i}: {what}");
                }
            }
        }

        char[] inOut = chars.ToArray();
        memcpy_chars_inout(inOut, bytes, (nuint)n);
        if (s_reportKnownIssues || bytes.All(b => b < 0x80))
        {
            Check.That(inOut.SequenceEqual(outChars), $"[In, Out] ANSI char[] differs from [Out]: {what}");
        }
        // Unicode char[]: blittable, pinned.
        char[] wide = new char[n / 2];
        memcpy_wchars(wide, bytes, (nuint)(wide.Length * 2));
        Check.That(MemoryMarshal.AsBytes(wide.AsSpan()).SequenceEqual(bytes.AsSpan(0, wide.Length * 2)), $"[Out] Unicode char[]: {what}");
        // StringBuilder: the native buffer starts with the current content and gets read back up to the NUL.
        int capacity = Math.Max(n, 1) + (flags >> 2);
        var sb = new StringBuilder(new string('x', capacity), capacity);
        byte[] ascii = bytes.Select(b => (byte)(b % 0x7F + 1)).ToArray();
        memcpy_sb(sb, ascii, (nuint)n);
        Check.Equal(Encoding.ASCII.GetString(ascii) + new string('x', capacity - n), sb.ToString(), $"ANSI StringBuilder after memcpy: {what}");
        var wsb = new StringBuilder(new string('x', capacity), capacity);
        byte[] wideBytes = MemoryMarshal.AsBytes(Encoding.ASCII.GetString(ascii).AsSpan()).ToArray();
        memcpy_wsb(wsb, wideBytes, (nuint)wideBytes.Length);
        Check.Equal(Encoding.ASCII.GetString(ascii) + new string('x', capacity - n), wsb.ToString(), $"Unicode StringBuilder after memcpy: {what}");
        // bool[]: 4-byte BOOL by default, 1-byte with ArraySubType U1; any non-zero value is true.
        bool[] bools = new bool[n / 4];
        memcpy_bools(bools, bytes, (nuint)(bools.Length * 4));
        for (int i = 0; i < bools.Length; i++)
        {
            Check.Equal(BitConverter.ToInt32(bytes, i * 4) != 0, bools[i], $"[Out] bool[] element {i}: {what}");
        }

        bool[] bools1 = new bool[n];
        memcpy_bools_u1(bools1, bytes, (nuint)n);
        for (int i = 0; i < n; i++)
        {
            Check.Equal(bytes[i] != 0, bools1[i], $"[Out] U1 bool[] element {i}: {what}");
        }

        bool[] liBools = new bool[n];
        li_memcpy_bools(liBools, bytes, (nuint)n);
        Check.That(liBools.SequenceEqual(bools1), $"LibraryImport U1 bool[] differs: {what}");
        // string[] out: pointers to guarded NUL-terminated strings become managed strings.
        int count = Math.Min(n, 5);
        var pointers = new IntPtr[count];
        var expectedStrings = new string[count];
        for (int i = 0; i < count; i++)
        {
            byte[] piece = bytes.AsSpan(i, Math.Min(n - i, 7)).ToArray();
            int nul = Array.IndexOf(piece, (byte)0);
            if (nul >= 0)
            {
                piece = piece.AsSpan(0, nul).ToArray();
            }

            expectedStrings[i] = Encoding.UTF8.GetString(piece);
            pointers[i] = Marshal.StringToCoTaskMemUTF8(expectedStrings[i]); // freed by the [Out] marshaller
        }

        var strings = new string[count];
        memcpy_strs(strings, pointers, (nuint)(count * IntPtr.Size), count);
        Check.That(strings.SequenceEqual(expectedStrings), $"[Out] string[] {string.Join("|", strings.Select(Check.Show))} != {string.Join("|", expectedStrings.Select(Check.Show))}: {what}");
        // int[] in / out through pointers to guarded memory, DllImport (pinned) and LibraryImport (copied).
        int[] ints = MemoryMarshal.Cast<byte, int>(bytes).ToArray();
        byte* dst = Guarded.Allocate(ints.Length * 4L, !atStart);
        memcpy_ints(dst, ints, (nuint)(ints.Length * 4));
        Check.That(new ReadOnlySpan<byte>(dst, ints.Length * 4).SequenceEqual(MemoryMarshal.AsBytes(ints.AsSpan())), $"int[] in: {what}");
        int[] back = new int[ints.Length];
        memcpy_ints_out(back, dst, (nuint)(ints.Length * 4));
        Check.That(back.SequenceEqual(ints), $"[Out] int[]: {what}");
        int[] liBack = new int[ints.Length];
        li_memcpy_ints(liBack, ints, (nuint)(ints.Length * 4));
        Check.That(liBack.SequenceEqual(ints), $"LibraryImport [Out] int[]: {what}");
        byte[] liBytes = new byte[n];
        li_memcpy(liBytes, bytes, (nuint)n);
        Check.That(liBytes.SequenceEqual(bytes), $"LibraryImport [Out] byte[]: {what}");
        byte* spanDst = Guarded.Allocate(n, atStart);
        li_memcpy_span(new Span<byte>(spanDst, n), bytes, (nuint)n);
        Check.That(new ReadOnlySpan<byte>(spanDst, n).SequenceEqual(bytes), $"LibraryImport Span<byte>: {what}");
        if (n > 0)
        {
            byte target = 0;
            li_memcpy_ref(ref target, in bytes[n - 1], 1);
            Check.Equal(bytes[n - 1], target, $"LibraryImport ref byte / in byte: {what}");
            int intTarget;
            int source = ints.Length > 0 ? ints[0] : n;
            li_memcpy_out(out intTarget, in source, 4);
            Check.Equal(source, intTarget, $"LibraryImport out int / in int: {what}");
        }
    }

    // ------------------------------------------------------------ numbers and errno

    private static void Numbers(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        byte[] text = input.SegmentBytes().ToArray();
        byte* p = Terminated(text, atStart);
        int @base = ((flags >> 1) % 3) switch { 0 => 10, 1 => 16, _ => 0 };
        string s = Encoding.ASCII.GetString(text.Select(b => b < 0x80 ? b : (byte)'?').ToArray());
        string what = $"{Check.Show(s)} base {@base}";

        Marshal.SetLastSystemError(0);
        long value = strtol(p, out byte* end, @base);
        int errno = Marshal.GetLastPInvokeError();
        Check.That(end >= p && end <= p + text.Length, $"strtol end pointer outside the string: {what}");
        (long expectedValue, int consumed, bool overflow) = ModelStrtol(s, @base);
        Check.Equal(consumed, (int)(end - p), $"strtol consumed for {what}");
        Check.Equal(expectedValue, value, $"strtol value for {what}");
        Check.Equal(overflow ? 34 : 0, errno, $"strtol errno for {what}");
        Marshal.SetLastSystemError(0);
        long liValue = li_strtol(new ReadOnlySpan<byte>(p, text.Length + 1), out IntPtr liEnd, @base);
        Check.Equal(value, liValue, $"LibraryImport strtol value for {what}");
        Check.Equal((int)(end - p), (int)((byte*)liEnd - p), $"LibraryImport strtol end for {what}");
        Check.Equal(errno, Marshal.GetLastPInvokeError(), $"LibraryImport strtol errno for {what}");
        if (errno != 0)
        {
            Check.That(Marshal.GetLastPInvokeErrorMessage().Length > 0, "GetLastPInvokeErrorMessage");
            Check.Equal(Marshal.GetPInvokeErrorMessage(errno), Marshal.GetLastPInvokeErrorMessage(), "GetPInvokeErrorMessage");
        }

        ulong u = strtoul(p, out byte* uend, @base);
        Check.That(uend >= p && uend <= p + text.Length, $"strtoul end pointer outside the string: {what}");
        // strtod: only plain decimal prefixes are modelled (hex floats, inf, nan(...) are libc's business).
        double d = strtod(p, out byte* dend);
        Check.That(dend >= p && dend <= p + text.Length, $"strtod end pointer outside the string: {what}");
        int len = (int)(dend - p);
        string prefix = s.Substring(0, len).TrimStart();
        if (len > 0 && System.Text.RegularExpressions.Regex.IsMatch(prefix, @"^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$"))
        {
            double expected = double.Parse(prefix, NumberStyles.Float, CultureInfo.InvariantCulture);
            Check.Equal(BitConverter.DoubleToInt64Bits(expected), BitConverter.DoubleToInt64Bits(d), $"strtod {Check.Show(prefix)}");
        }
    }

    /// <summary>strtol as documented: optional whitespace, sign, 0x prefix for base 16 / 0, saturation with ERANGE.</summary>
    private static (long Value, int Consumed, bool Overflow) ModelStrtol(string s, int @base)
    {
        int i = 0;
        while (i < s.Length && (s[i] == ' ' || s[i] is >= '\t' and <= '\r'))
        {
            i++;
        }

        bool negative = false;
        if (i < s.Length && (s[i] == '+' || s[i] == '-'))
        {
            negative = s[i] == '-';
            i++;
        }

        int digitsStart = i;
        if ((@base == 16 || @base == 0) && i + 1 < s.Length && s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X') && i + 2 < s.Length && Digit(s[i + 2]) < 16)
        {
            @base = 16;
            i += 2;
            digitsStart = i;
        }
        else if (@base == 0)
        {
            @base = i < s.Length && s[i] == '0' ? 8 : 10;
        }

        System.Numerics.BigInteger acc = 0;
        while (i < s.Length && Digit(s[i]) < @base)
        {
            acc = acc * @base + Digit(s[i]);
            i++;
        }

        if (i == digitsStart)
        {
            return (0, 0, false);
        }

        if (negative)
        {
            acc = -acc;
        }

        if (acc > long.MaxValue)
        {
            return (long.MaxValue, i, true);
        }

        if (acc < long.MinValue)
        {
            return (long.MinValue, i, true);
        }

        return ((long)acc, i, false);
    }

    private static int Digit(char c) => c is >= '0' and <= '9' ? c - '0' : c is >= 'a' and <= 'z' ? c - 'a' + 10 : c is >= 'A' and <= 'Z' ? c - 'A' + 10 : 99;

    // ------------------------------------------------------------ qsort / bsearch

    private static int s_compares;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int CompareInts(void* a, void* b)
    {
        s_compares++;
        return (*(int*)a).CompareTo(*(int*)b);
    }

    private static void Sorting(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        int[] ints = MemoryMarshal.Cast<byte, int>(input.Bytes(Math.Min(input.Remaining, 160))).ToArray();
        string what = $"{ints.Length} ints [{string.Join(",", ints.Take(8))}{(ints.Length > 8 ? ",..." : "")}]";
        int[] expected = ints.ToArray();
        Array.Sort(expected);

        // Delegate comparator, pinned int[].
        int[] a = ints.ToArray();
        int calls = 0;
        QsortCmp cmp = (x, y) => { calls++; return (*(int*)x).CompareTo(*(int*)y); };
        qsort(a, (nuint)a.Length, 4, cmp);
        GC.KeepAlive(cmp);
        Check.That(a.SequenceEqual(expected), $"qsort(int[], delegate): {what}");
        Check.That(a.Length < 2 || calls > 0, $"qsort never called the comparator: {what}");
        // Function pointer comparator over guarded memory, then bsearch for a fuzzed key.
        int* native = (int*)Guarded.Allocate(ints.Length * 4L, atStart);
        ints.CopyTo(new Span<int>(native, ints.Length));
        s_compares = 0;
        qsort_ptr(native, (nuint)ints.Length, 4, &CompareInts);
        Check.That(new ReadOnlySpan<int>(native, ints.Length).SequenceEqual(expected), $"qsort(void*, function pointer): {what}");
        int key = ints.Length > 0 ? ints[flags % ints.Length] ^ (flags >> 1 & 1) : flags;
        int* found = bsearch(ref key, native, (nuint)ints.Length, 4, &CompareInts);
        int index = Array.BinarySearch(expected, key);
        Check.Equal(index >= 0, found != null, $"bsearch({key}) found: {what}");
        if (found != null)
        {
            Check.Equal(key, *found, $"bsearch({key}) value: {what}");
            Check.That(found >= native && found < native + ints.Length, $"bsearch({key}) pointer outside the array: {what}");
        }

        int[] span = ints.ToArray();
        li_qsort(span, (nuint)span.Length, 4, &CompareInts);
        Check.That(span.SequenceEqual(expected), $"LibraryImport qsort(Span<int>): {what}");

        // Non-blittable structs: marshalled to a native array, sorted there by key, marshalled back.
        int count = Math.Min(ints.Length, 12);
        var recs = new Rec[count];
        for (int i = 0; i < count; i++)
        {
            recs[i] = new Rec { Key = ints[i], Flag = (ints[i] & 0x100) != 0, Name = new string((char)('a' + (ints[i] >> 9 & 15)), ints[i] >> 13 & 3), D = ints[i] * 0.5 };
        }

        Rec[] sortedRecs = recs.OrderBy(r => r.Key).ToArray();
        int size = Marshal.SizeOf<Rec>();
        QsortCmp cmpRec = (x, y) => (*(int*)x).CompareTo(*(int*)y);
        qsort_recs(recs, (nuint)count, (nuint)size, cmpRec);
        GC.KeepAlive(cmpRec);
        for (int i = 0; i < count; i++)
        {
            Check.That(recs[i].Key == sortedRecs[i].Key, $"qsort(Rec[]) order at {i}: {what}");
            Rec match = sortedRecs.First(r => r.Key == recs[i].Key);
            Check.That(recs[i].Flag == match.Flag && recs[i].Name == match.Name && recs[i].D == match.D, $"qsort(Rec[]) element {i} fields {recs[i].Key} {recs[i].Flag} {Check.Show(recs[i].Name)} {recs[i].D}: {what}");
        }

        // Strings: sorted by their UTF-8 bytes through char** pointers, written back as new strings.
        var strings = new string[count];
        for (int i = 0; i < count; i++)
        {
            strings[i] = Utf8Text(input.SegmentBytes());
        }

        string[] sortedStrings = strings.OrderBy(s => Encoding.UTF8.GetBytes(s), Comparer<byte[]>.Create((x, y) => x.AsSpan().SequenceCompareTo(y))).ToArray();
        QsortCmp cmpStr = (x, y) => Encoding.UTF8.GetBytes(Marshal.PtrToStringUTF8(*(IntPtr*)x)).AsSpan().SequenceCompareTo(Encoding.UTF8.GetBytes(Marshal.PtrToStringUTF8(*(IntPtr*)y)));
        qsort_strs(strings, (nuint)count, (nuint)IntPtr.Size, cmpStr);
        GC.KeepAlive(cmpStr);
        Check.That(strings.SequenceEqual(sortedStrings), $"qsort(string[]): [{string.Join("|", strings.Select(Check.Show))}] != [{string.Join("|", sortedStrings.Select(Check.Show))}]: {what}");
    }

    // ------------------------------------------------------------ files and SafeHandles

    private const int O_RDWR = 2, O_CREAT = 0x40, O_TRUNC = 0x200;

    private static void Files(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        byte[] payload = input.Bytes(Math.Min(input.Remaining, 300)).ToArray();
        string path = $"/dev/shm/sharpfuzz-pinvoke-{Environment.ProcessId}-{s_files++}";
        string what = $"{payload.Length} bytes to {path}";
        using SafeFileHandle fd = (flags & 2) != 0 ? li_open(path, O_RDWR | O_CREAT | O_TRUNC, 384) : open(path, O_RDWR | O_CREAT | O_TRUNC, 384);
        try
        {
            Check.That(!fd.IsInvalid, $"open failed with errno {Marshal.GetLastPInvokeError()}: {what}");
            byte* src = Native(payload, atStart);
            Check.Equal((nint)payload.Length, write(fd, src, (nuint)payload.Length), $"write: {what}");
            Check.Equal((nint)payload.Length, li_write(fd, payload, (nuint)payload.Length), $"LibraryImport write: {what}");
            Check.Equal(2L * payload.Length, lseek(fd, 0, 1), $"lseek(cur): {what}");
            Check.Equal(0L, lseek(fd, 0, 0), $"lseek(set): {what}");
            byte* dst = Guarded.Allocate(payload.Length, !atStart);
            Check.Equal((nint)payload.Length, read(fd, dst, (nuint)payload.Length), $"read: {what}");
            Check.That(new ReadOnlySpan<byte>(dst, payload.Length).SequenceEqual(payload), $"read contents: {what}");
            byte[] buffer = new byte[payload.Length];
            Check.Equal((nint)payload.Length, pread(fd, buffer, (nuint)payload.Length, payload.Length), $"pread: {what}");
            Check.That(buffer.SequenceEqual(payload), $"pread contents: {what}");
            byte* spanDst = Guarded.Allocate(payload.Length, atStart);
            var span = new Span<byte>(spanDst, payload.Length);
            Check.Equal((nint)payload.Length, li_pread(fd, span, (nuint)payload.Length, 0), $"LibraryImport pread: {what}");
            Check.That(span.SequenceEqual(payload), $"LibraryImport pread contents: {what}");
            // A SafeHandle returned from dup owns a second descriptor.
            using SafeFileHandle dup2 = dup(fd);
            Check.That(!dup2.IsInvalid && dup2.DangerousGetHandle() != fd.DangerousGetHandle(), $"dup: {what}");
            Check.Equal((nint)payload.Length, pread(dup2, buffer, (nuint)payload.Length, 0), $"pread through dup: {what}");
            Check.That(!li_isatty((int)fd.DangerousGetHandle()), "isatty on a file");
            // Errors: ENOENT from open, EBADF from close(-1).
            using SafeFileHandle missing = open("/dev/shm/sharpfuzz-no-such-dir/x", 0, 0);
            Check.That(missing.IsInvalid, "open of a missing path succeeded");
            Check.Equal(2, Marshal.GetLastPInvokeError(), "errno after a failed open");
            Check.Equal(-1, close(-1), "close(-1)");
            Check.Equal(9, Marshal.GetLastPInvokeError(), "errno after close(-1)");
            // A pipe: [Out] int[2], then SafeHandles around the descriptors.
            int[] fds = new int[2];
            Check.Equal(0, pipe(fds), "pipe");
            using var reader = new SafeFileHandle((IntPtr)fds[0], ownsHandle: true);
            using var writer = new SafeFileHandle((IntPtr)fds[1], ownsHandle: true);
            int chunk = Math.Min(payload.Length, 4096);
            Check.Equal((nint)chunk, write(writer, src, (nuint)chunk), $"write to pipe: {what}");
            byte* pipeDst = Guarded.Allocate(chunk, atStart);
            Check.Equal((nint)chunk, read(reader, pipeDst, (nuint)chunk), $"read from pipe: {what}");
            Check.That(new ReadOnlySpan<byte>(pipeDst, chunk).SequenceEqual(payload.AsSpan(0, chunk)), $"pipe contents: {what}");
        }
        finally
        {
            unlink(path);
        }
    }

    // ------------------------------------------------------------ structs

    private static void Structs(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        int a = input.Int32(), b = input.Int32();
        if (b != 0 && !(a == int.MinValue && b == -1))
        {
            DivT d = div(a, b);
            Check.That(d.Quot == a / b && d.Rem == a % b, $"div({a}, {b}) = {d.Quot} r {d.Rem}");
        }

        long la = (long)input.Int32() << 32 | (uint)input.Int32(), lb = (long)input.Int32() << 32 | (uint)input.Int32();
        if (lb != 0 && !(la == long.MinValue && lb == -1))
        {
            LDivT d = ldiv(la, lb);
            Check.That(d.Quot == la / lb && d.Rem == la % lb, $"ldiv({la}, {lb}) = {d.Quot} r {d.Rem}");
            LDivT e = li_ldiv(la, lb);
            Check.That(e.Quot == la / lb && e.Rem == la % lb, $"LibraryImport ldiv({la}, {lb}) = {e.Quot} r {e.Rem}");
        }

        // gmtime_r: an out struct filled by libc, against DateTime.
        long t = Math.Clamp(la, -62135596800, 253402300799);
        IntPtr ok = gmtime_r(in t, out Tm tm);
        Check.That(ok != IntPtr.Zero, $"gmtime_r({t}) failed");
        DateTime dt = DateTime.UnixEpoch.AddSeconds(t);
        Check.That(tm.Year + 1900 == dt.Year && tm.Mon + 1 == dt.Month && tm.MDay == dt.Day && tm.Hour == dt.Hour && tm.Min == dt.Minute && tm.Sec == dt.Second && tm.WDay == (int)dt.DayOfWeek && tm.YDay == dt.DayOfYear - 1,
            $"gmtime_r({t}) = {tm.Year + 1900}-{tm.Mon + 1}-{tm.MDay} {tm.Hour}:{tm.Min}:{tm.Sec} wday {tm.WDay} yday {tm.YDay}, DateTime {dt:O}");
        li_gmtime_r(in t, out Tm tm2);
        Check.That(tm2.Year == tm.Year && tm2.YDay == tm.YDay && tm2.Sec == tm.Sec, $"LibraryImport gmtime_r({t})");

        // Rec by ref / in / out and arrays of Rec through memcpy, against StructureToPtr.
        var rec = new Rec { Key = a, Flag = (flags & 2) != 0, Name = Ascii(input.Bytes(5), 5), D = BitConverter.Int64BitsToDouble(lb) };
        int size = Marshal.SizeOf<Rec>();
        byte* expected = Guarded.Allocate(size, atStart);
        new Span<byte>(expected, size).Fill(0xCC);
        Marshal.StructureToPtr(rec, (IntPtr)expected, false);
        byte* dst = Guarded.Allocate(size, !atStart);
        new Span<byte>(dst, size).Fill(0xCC);
        memcpy_rec_ref(dst, ref rec, (nuint)size);
        SameRec(expected, dst, size, "ref Rec");
        Check.That(rec.Key == a && rec.Name.Length <= 5, "ref Rec came back changed");
        new Span<byte>(dst, size).Fill(0xCC);
        memcpy_rec_in(dst, in rec, (nuint)size);
        SameRec(expected, dst, size, "in Rec");
        memcpy_rec_out(out Rec outRec, expected, (nuint)size);
        Check.That(outRec.Key == rec.Key && outRec.Flag == rec.Flag && outRec.Name == rec.Name && BitConverter.DoubleToInt64Bits(outRec.D) == BitConverter.DoubleToInt64Bits(rec.D), $"out Rec: {outRec.Key} {outRec.Flag} {Check.Show(outRec.Name)} {outRec.D}");
        const int Count = 4;
        Rec[] recs = Enumerable.Range(0, Count).Select(i => new Rec { Key = rec.Key + i, Flag = rec.Flag ^ (i & 1) != 0, Name = rec.Name, D = rec.D + i }).ToArray();
        byte* dstN = Guarded.Allocate(size * Count, atStart);
        memcpy_recs_in(dstN, recs, (nuint)(size * Count));
        for (int i = 0; i < Count; i++)
        {
            Check.Equal(recs[i].Key, *(int*)(dstN + i * size), $"[In] Rec[] element {i} key");
            Check.Equal(recs[i].Flag ? 1 : 0, dstN[i * size + 4], $"[In] Rec[] element {i} flag");
        }

        Rec[] outRecs = new Rec[Count];
        memcpy_recs(outRecs, dstN, (nuint)(size * Count));
        for (int i = 0; i < Count; i++)
        {
            Check.That(outRecs[i].Key == recs[i].Key && outRecs[i].Flag == recs[i].Flag && outRecs[i].Name == recs[i].Name && BitConverter.DoubleToInt64Bits(outRecs[i].D) == BitConverter.DoubleToInt64Bits(recs[i].D), $"[Out] Rec[] element {i}");
        }

        // decimal as LPStruct (a pointer to DECIMAL) and Guid by ref: 16 bytes each.
        decimal dec = new decimal(a, b, (int)la, (flags & 4) != 0, (byte)(flags % 29));
        byte* decDst = Guarded.Allocate(16, atStart);
        memcpy_dec(decDst, dec, 16);
        ReadOnlySpan<byte> decBytes = MemoryMarshal.AsBytes(new ReadOnlySpan<decimal>(in dec));
        Check.That(new ReadOnlySpan<byte>(decDst, 16).SequenceEqual(decBytes), $"LPStruct decimal {dec}: {Convert.ToHexString(new ReadOnlySpan<byte>(decDst, 16))} vs {Convert.ToHexString(decBytes)}");
        var guid = new Guid(a, (short)b, (short)(b >> 16), (byte)la, (byte)(la >> 8), (byte)(la >> 16), (byte)(la >> 24), (byte)lb, (byte)(lb >> 8), (byte)(lb >> 16), (byte)(lb >> 24));
        byte* guidDst = Guarded.Allocate(16, !atStart);
        memcpy_guid(guidDst, ref guid, 16);
        Check.Equal(guid, new Guid(new ReadOnlySpan<byte>(guidDst, 16)), "ref Guid");
    }

    private static void SameRec(byte* expected, byte* actual, int size, string how)
    {
        // Key (4), Flag (1), Name up to its NUL, D (8): padding is unspecified.
        Check.That(new ReadOnlySpan<byte>(expected, 5).SequenceEqual(new ReadOnlySpan<byte>(actual, 5)), $"{how}: key / flag bytes differ");
        int nameLen = new ReadOnlySpan<byte>(expected + 5, 6).IndexOf((byte)0) + 1;
        Check.That(new ReadOnlySpan<byte>(expected + 5, nameLen).SequenceEqual(new ReadOnlySpan<byte>(actual + 5, nameLen)), $"{how}: name bytes differ");
        Check.That(new ReadOnlySpan<byte>(expected + 16, 8).SequenceEqual(new ReadOnlySpan<byte>(actual + 16, 8)), $"{how}: double bytes differ");
    }

    private static string Ascii(ReadOnlySpan<byte> bytes, int max)
    {
        var sb = new StringBuilder();
        foreach (byte b in bytes)
        {
            if (sb.Length < max && b is > 0 and < 0x80)
            {
                sb.Append((char)b);
            }
        }

        return sb.ToString();
    }

    // ------------------------------------------------------------ libm against System.Math

    private static void Math_(ref FuzzInput input, byte flags)
    {
        double x = BitConverter.Int64BitsToDouble((long)input.Int32() << 32 | (uint)input.Int32());
        double y = BitConverter.Int64BitsToDouble((long)input.Int32() << 32 | (uint)input.Int32());
        double z = BitConverter.Int64BitsToDouble((long)input.Int32() << 32 | (uint)input.Int32());
        int e = (short)input.UInt16();
        string what = $"x={x:R} y={y:R} z={z:R}";
        Same(Math.Cbrt(x), cbrt(x), $"cbrt {what}");
        Same(Math.Sin(x), sin(x), $"sin {what}");
        Same(Math.Cos(x), cos(x), $"cos {what}");
        Same(Math.Exp(x), exp(x), $"exp {what}");
        Same(Math.Log(x), log(x), $"log {what}");
        Same(Math.Log2(x), log2(x), $"log2 {what}");
        Same(Math.Atan2(y, x), atan2(y, x), $"atan2 {what}");
        Same(Math.FusedMultiplyAdd(x, y, z), fma(x, y, z), $"fma {what}");
        Same(MathF.FusedMultiplyAdd((float)x, (float)y, (float)z), fmaf((float)x, (float)y, (float)z), $"fmaf {what}");
        Same(Math.CopySign(x, y), copysign(x, y), $"copysign {what}");
        Same(Math.ScaleB(x, e), ldexp(x, e), $"ldexp {what} e={e}");
        Same(Math.Sqrt(x), sqrt(x), $"sqrt {what}");
        Same(MathF.Sqrt((float)x), sqrtf((float)x), $"sqrtf {what}");
        Same(Math.Round(x, MidpointRounding.AwayFromZero), round(x), $"round {what}");
        Same(Math.Truncate(x), trunc(x), $"trunc {what}");
        double rem = remainder(x, y);
        if (rem != 0)
        {
            Same(Math.IEEERemainder(x, y), rem, $"remainder {what}");
        }
        else
        {
            Check.That(Math.IEEERemainder(x, y) == 0, $"remainder {what}: Math {Math.IEEERemainder(x, y):R}, libm {rem:R}"); // sign of zero: glibc differs (MATH-REM-1)
        }
        Same(x % y, fmod(x, y), $"fmod {what}");
        if (double.IsFinite(x) && x != 0)
        {
            Check.Equal(Math.ILogB(x), ilogb(x), $"ilogb {what}");
        }

        Same(double.BitIncrement(x), nextafter(x, double.PositiveInfinity), $"nextafter up {what}");
        Same(double.BitDecrement(x), nextafter(x, double.NegativeInfinity), $"nextafter down {what}");
        double m = frexp(x, out int exponent);
        if (double.IsFinite(x) && x != 0)
        {
            Check.That(Math.Abs(m) >= 0.5 && Math.Abs(m) < 1 && Math.ScaleB(m, exponent) == x, $"frexp {what} = {m:R} * 2^{exponent}");
        }

        double frac = modf(x, out double ip);
        if (double.IsFinite(x))
        {
            Check.That(ip == Math.Truncate(x) && (frac == x - ip || Math.Abs(frac - (x - ip)) <= Math.Abs(x) * 1e-15), $"modf {what} = {ip:R} + {frac:R}");
        }
    }

    /// <summary>Bit-identical, or both NaN.</summary>
    private static void Same(double expected, double actual, string what)
    {
        Check.That(BitConverter.DoubleToInt64Bits(expected) == BitConverter.DoubleToInt64Bits(actual) || double.IsNaN(expected) && double.IsNaN(actual), $"{what}: Math {expected:R}, libm {actual:R}");
    }

    private static void Same(float expected, float actual, string what)
    {
        Check.That(BitConverter.SingleToInt32Bits(expected) == BitConverter.SingleToInt32Bits(actual) || float.IsNaN(expected) && float.IsNaN(actual), $"{what}: MathF {expected:R}, libm {actual:R}");
    }

    // ------------------------------------------------------------ NativeLibrary

    private static void Library(ref FuzzInput input, byte flags)
    {
        string name = Encoding.UTF8.GetString(input.SegmentBytes()).Replace("\0", "");
        string what = $"symbol {Check.Show(name)}";
        bool found = NativeLibrary.TryGetExport(s_libc, name, out IntPtr address);
        Check.Equal(found, address != IntPtr.Zero, $"TryGetExport result and address disagree for {what}");
        if (name is "strlen" or "memcpy" or "malloc" or "free" or "qsort")
        {
            Check.That(found, $"TryGetExport failed for {what}");
        }

        try
        {
            IntPtr export = NativeLibrary.GetExport(s_libc, name);
            Check.That(found && export == address, $"GetExport / TryGetExport disagree for {what}");
        }
        catch (EntryPointNotFoundException)
        {
            Check.That(!found, $"GetExport threw but TryGetExport succeeded for {what}");
        }

        if (found && name == "strlen")
        {
            var fn = (delegate* unmanaged[Cdecl]<byte*, nuint>)address;
            byte* p = Terminated("hello"u8, (flags & 1) != 0);
            Check.Equal((nuint)5, fn(p), "strlen through TryGetExport");
        }

        // Library names: dlopen with an arbitrary name must fail cleanly (no path separators, so nothing real gets loaded by accident).
        string lib = name.Replace("/", "").Replace("\\", "");
        if (lib.Length > 0 && lib.Length < 64 && (flags & 2) != 0)
        {
            bool loaded = NativeLibrary.TryLoad(lib, out IntPtr handle);
            if (loaded)
            {
                NativeLibrary.Free(handle);
            }

            try
            {
                IntPtr h = NativeLibrary.Load(lib);
                Check.That(loaded, $"Load succeeded but TryLoad failed for {Check.Show(lib)}");
                NativeLibrary.Free(h);
            }
            catch (DllNotFoundException)
            {
                Check.That(!loaded, $"Load threw but TryLoad succeeded for {Check.Show(lib)}");
            }
        }

        Check.That(NativeLibrary.TryLoad("libc.so.6", out IntPtr libc) && libc == s_libc, "TryLoad(libc.so.6)");
        Check.That(NativeLibrary.TryGetExport(NativeLibrary.GetMainProgramHandle(), "malloc", out _), "malloc through the main program handle");
    }

    // ------------------------------------------------------------ more LibraryImport shapes

    private static void Generated(ref FuzzInput input, byte flags)
    {
        // The generated stubs in the other cases cover strings, spans, arrays, SafeHandles and structs;
        // here the same input goes through the DllImport and LibraryImport versions side by side.
        bool atStart = (flags & 1) != 0;
        byte[] bytes = input.Bytes(Math.Min(input.Remaining, 100)).ToArray();
        string s = Utf8Text(bytes);
        Check.Equal(strlen_utf8(s), li_strlen(s), $"strlen DllImport vs LibraryImport for {Check.Show(s)}");
        Check.Equal(strlen_wide(s), li_strlen16(s), $"UTF-16 strlen DllImport vs LibraryImport for {Check.Show(s)}");
        int n = bytes.Length;
        byte* dst1 = Guarded.Allocate(n, atStart);
        byte* dst2 = Guarded.Allocate(n, !atStart);
        memcpy_ints(dst1, MemoryMarshal.Cast<byte, int>(bytes).ToArray(), (nuint)(n & ~3));
        li_memcpy_span(new Span<byte>(dst2, n), bytes, (nuint)n);
        Check.That(new ReadOnlySpan<byte>(dst1, n & ~3).SequenceEqual(new ReadOnlySpan<byte>(dst2, n & ~3)), $"memcpy DllImport vs LibraryImport for {n} bytes");
        long t = Math.Clamp((long)input.Int32() << 32 | (uint)input.Int32(), -62135596800, 253402300799);
        gmtime_r(in t, out Tm a);
        li_gmtime_r(in t, out Tm b);
        Check.That(a.Sec == b.Sec && a.Min == b.Min && a.Hour == b.Hour && a.MDay == b.MDay && a.Mon == b.Mon && a.Year == b.Year && a.WDay == b.WDay && a.YDay == b.YDay, $"gmtime_r DllImport vs LibraryImport for {t}");
    }
}
