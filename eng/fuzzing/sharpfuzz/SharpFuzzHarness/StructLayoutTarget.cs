#nullable disable warnings
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SharpFuzzHarness;

/// <summary>
/// The struct marshalling layer over types built at run time: a struct (and an inner struct it can
/// embed) is emitted with Reflection.Emit from the input (LayoutKind, CharSet, Pack, Size, field
/// offsets, and fields of every kind the built-in marshaller knows: primitives, bool / char with
/// MarshalAs variants, decimal / DateTime / Guid / Half / Int128, strings as LPStr / LPWStr /
/// LPUTF8Str / BStr / ByValTStr, ByValArray of primitives / chars / bools / strings / structs,
/// nested structs, delegates, enums, SafeHandle, object and a generic struct). Then:
/// Marshal.SizeOf / OffsetOf against a layout model; StructureToPtr into exactly SizeOf guarded
/// bytes and PtrToStructure back (field equality); PtrToStructure from arbitrary bytes (no
/// pointer fields) and marshalling that again; a DllImport stub emitted for memcpy(byte*, ref T,
/// nuint) and memcpy(byte*, T[], nuint) against StructureToPtr; and, for explicit layouts, that the
/// type loader never accepts a reference field overlapping a non-reference field or sitting at an
/// unaligned offset. Exercises the .NET 11 managed StructureMarshaler / LayoutClassMarshaler /
/// array element marshalers and the native field layout code.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     layout kind (0 sequential, 1 explicit, 2 auto) | charset (bits 2-3) | pack index (bits 4-7)
///   byte 1     field count (1-8), bit 7: emit an inner struct first (then the outer may embed it), bit 6: layout classes instead of structs
///   bytes 2-3  Size (0 = none; capped at 512)
///   per field  kind byte, parameter byte, explicit offset (2 bytes, only for explicit layout)
///   (the inner struct, when present, comes first with the same layout)
///   rest       field values
/// </remarks>
public static unsafe class StructLayoutTarget
{
    public delegate int IntFn(int x);
    public enum ByteEnum : byte { A = 1, B = 2, C = 3 }
    public enum LongEnum : long { A = 1, B = 1L << 40, C = -1 }
    public static int Twice(int x) => x * 2;

    private delegate object Reader(ref FuzzInput input);

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;
    private static readonly bool s_trace = Environment.GetEnvironmentVariable("SHARPFUZZ_TRACE") is not null;
    private static readonly PackingSize[] s_packs = [PackingSize.Unspecified, PackingSize.Size1, PackingSize.Size2, PackingSize.Size4, PackingSize.Size8, PackingSize.Size16, PackingSize.Size32, PackingSize.Size64, PackingSize.Size128];
    private static readonly MethodInfo s_unsafeSizeOf = typeof(Unsafe).GetMethod(nameof(Unsafe.SizeOf), BindingFlags.Public | BindingFlags.Static);
    private static int s_assemblies;

    /// <summary>One field of a generated struct and what the layout model expects of it.</summary>
    private sealed class FieldSpec
    {
        public string Name;
        public Type Type;
        public UnmanagedType? MarshalAs;
        public int SizeConst = -1;
        public UnmanagedType? ArraySubType;
        public int Offset = -1;       // explicit layout only
        public int NativeSize;        // per the documented marshalling rules
        public int NativeAlign;
        public bool Pointer;          // the native representation is (or contains) a pointer
        public bool IsReference;      // the managed field is a reference (or contains one)
        public bool MayFail;          // marshalling isn't supported for this kind on Unix / for this type
        public bool Terminated;       // a NUL-terminated fixed buffer (bytes after the NUL are unspecified)
        public Spec Inner;            // nested struct spec
        public Reader Value;
        public Func<object, object, bool> Same;
        public FieldBuilder Builder;
    }

    private sealed class Spec
    {
        public LayoutKind Layout;
        public CharSet CharSet;
        public int PackIndex;
        public int Size;
        public List<FieldSpec> Fields = new();
        public Type Type;
        public bool TypeConfused;
        public bool IsClass;     // a layout class (reference type): marshalled as a pointer to its native layout
        public int Pack => PackIndex == 0 ? (HasInt128 ? 16 : 8) : 1 << (PackIndex - 1);
        public bool HasInt128 => Fields.Any(f => f.Type == typeof(Int128) || (f.Inner?.HasInt128 ?? false));
        public int NativeAlign => Math.Min(Pack, Fields.Count == 0 ? 1 : Fields.Max(f => f.NativeAlign));
        public bool AnyPointer => Fields.Any(f => f.Pointer || (f.Inner?.AnyPointer ?? false));
        public bool AnyMayFail => Fields.Any(f => f.MayFail || (f.Inner?.AnyMayFail ?? false));
        public bool ContainsReferences => Fields.Any(f => f.IsReference || (f.Inner?.ContainsReferences ?? false));
        public override string ToString() => $"{(IsClass ? "class " : "")}{Layout}/{CharSet}/pack{PackIndex}/size{Size}[{string.Join(", ", Fields.Select(f => $"{f.Name}:{Describe(f)}"))}]";

        private static string Describe(FieldSpec f) =>
            (f.Inner is not null ? (f.Type.IsArray ? "inner[](" + f.Inner + ")" : "inner(" + f.Inner + ")") : f.Type.Name) + (f.MarshalAs is null ? "" : $"/{f.MarshalAs}") + (f.SizeConst >= 0 ? $"x{f.SizeConst}" : "") + (f.ArraySubType is null ? "" : $"/{f.ArraySubType}") + (f.Offset >= 0 ? $"@{f.Offset}" : "");
    }

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte header = input.Byte();
        byte countByte = input.Byte();
        int size = Math.Min((int)input.UInt16(), 512);
        LayoutKind layout = (header & 3) switch { 0 => LayoutKind.Sequential, 1 => LayoutKind.Explicit, 2 => LayoutKind.Auto, _ => LayoutKind.Sequential };
        CharSet charSet = ((header >> 2) & 3) switch { 0 => CharSet.Ansi, 1 => CharSet.Unicode, 2 => CharSet.Auto, _ => CharSet.None };
        int packIndex = (header >> 4) % s_packs.Length;
        int count = (countByte & 7) + 1;
        bool withInner = (countByte & 0x80) != 0;
        bool isClass = (countByte & 0x40) != 0;

        var module = AssemblyBuilder.DefineDynamicAssembly(new AssemblyName("Fuzz" + Interlocked.Increment(ref s_assemblies)), AssemblyBuilderAccess.RunAndCollect).DefineDynamicModule("m");
        Spec inner = null;
        if (withInner)
        {
            inner = Describe(ref input, layout, charSet, packIndex, size, Math.Max(1, count / 2), null);
            inner.IsClass = isClass;
            if (!Emit(module, inner, "Inner"))
            {
                return;
            }
        }

        Spec outer = Describe(ref input, layout, charSet, packIndex, size, count, inner);
        outer.IsClass = isClass;
        if (!Emit(module, outer, "Outer") || outer.TypeConfused || (inner?.TypeConfused ?? false))
        {
            return;
        }

        Exercise(module, outer, ref input);
    }

    // ---------------------------------------------------------------- describing and emitting

    private static Spec Describe(ref FuzzInput input, LayoutKind layout, CharSet charSet, int packIndex, int size, int count, Spec inner)
    {
        var spec = new Spec { Layout = layout, CharSet = charSet, PackIndex = packIndex, Size = size };
        for (int i = 0; i < count; i++)
        {
            byte kind = input.Byte();
            byte param = input.Byte();
            int offset = layout == LayoutKind.Explicit ? Math.Min((int)input.UInt16(), 600) : -1;
            FieldSpec f = Field(kind, param, charSet, inner);
            f.Name = "f" + i;
            f.Offset = offset;
            spec.Fields.Add(f);
        }

        return spec;
    }

    private static bool Emit(ModuleBuilder module, Spec spec, string name)
    {
        TypeAttributes attrs = TypeAttributes.Public | TypeAttributes.Sealed |
            spec.Layout switch { LayoutKind.Explicit => TypeAttributes.ExplicitLayout, LayoutKind.Auto => TypeAttributes.AutoLayout, _ => TypeAttributes.SequentialLayout } |
            spec.CharSet switch { CharSet.Unicode => TypeAttributes.UnicodeClass, CharSet.Auto => TypeAttributes.AutoClass, _ => TypeAttributes.AnsiClass };
        TypeBuilder tb = module.DefineType(name, attrs, spec.IsClass ? typeof(object) : typeof(ValueType), s_packs[spec.PackIndex], spec.Size);
        foreach (FieldSpec f in spec.Fields)
        {
            f.Builder = tb.DefineField(f.Name, f.Type, FieldAttributes.Public);
            if (f.Offset >= 0)
            {
                f.Builder.SetOffset(f.Offset);
            }

            if (f.MarshalAs is UnmanagedType ut)
            {
                var fields = new List<FieldInfo>();
                var values = new List<object>();
                if (f.SizeConst >= 0)
                {
                    fields.Add(typeof(MarshalAsAttribute).GetField(nameof(MarshalAsAttribute.SizeConst)));
                    values.Add(f.SizeConst);
                }

                if (f.ArraySubType is UnmanagedType sub)
                {
                    fields.Add(typeof(MarshalAsAttribute).GetField(nameof(MarshalAsAttribute.ArraySubType)));
                    values.Add(sub);
                }

                f.Builder.SetCustomAttribute(new CustomAttributeBuilder(typeof(MarshalAsAttribute).GetConstructor([typeof(UnmanagedType)]), [ut], fields.ToArray(), values.ToArray()));
            }
        }

        try
        {
            spec.Type = tb.CreateType();
        }
        catch (TypeLoadException) when (spec.Layout == LayoutKind.Explicit || spec.AnyMayFail)
        {
            // Overlapping / misaligned references, or a field type the loader rejects.
            return false;
        }

        // The loader must reject any explicit layout where a reference field overlaps a
        // non-reference field or isn't pointer aligned (otherwise the GC could see a non-pointer
        // as a reference). Only direct fields are checked; nested structs with references are
        // treated as opaque (the loader's rules for those are stricter still).
        if (spec.Layout == LayoutKind.Explicit)
        {
            // Overlapping reference-bearing fields alias native pointer slots (LAYOUT-ALIAS-1): StructureToPtr
            // marshals overlapping strings / arrays into the same bytes and DestroyStructure frees them per field,
            // which double-frees. A ByValArray of strings owns k inline pointers, so its whole [offset, offset +
            // k*8) region counts. Such layouts are only exercised through the loader checks below, not marshalled.
            var refs = spec.Fields.Where(f => f.IsReference || (f.Inner?.ContainsReferences ?? false)).ToList();
            spec.TypeConfused = refs.Any(r => refs.Any(o => o != r && r.Offset < o.Offset + Math.Max(o.NativeSize, 8) && o.Offset < r.Offset + Math.Max(r.NativeSize, 8)));
            // Non-reference overlaps alias managed memory too: a DateTime or decimal whose bits another
            // field overwrote is (rightly) rejected as an invalid OLE date / currency, so skip those as well.
            spec.TypeConfused |= spec.Fields.Any(f => (f.Type == typeof(DateTime) || f.Type == typeof(decimal) || f.Type == typeof(DateTimeOffset)) &&
                spec.Fields.Any(o => o != f && f.Offset < o.Offset + Math.Max(o.NativeSize, 8) && o.Offset < f.Offset + f.NativeSize));
            foreach (FieldSpec r in spec.Fields.Where(f => f.IsReference && f.Inner is null))
            {
                Check.That(r.Offset % IntPtr.Size == 0, $"loader accepted reference field {r.Name} at unaligned offset {r.Offset}: {spec}");
                foreach (FieldSpec o in spec.Fields.Where(f => !f.IsReference && f.Inner?.ContainsReferences != true))
                {
                    int managedSize = (int)s_unsafeSizeOf.MakeGenericMethod(o.Type).Invoke(null, null);
                    Check.That(r.Offset + IntPtr.Size <= o.Offset || o.Offset + managedSize <= r.Offset,
                        $"loader accepted reference field {r.Name}@{r.Offset} overlapping {o.Name}@{o.Offset}+{managedSize}: {spec}");
                }
            }
        }

        return true;
    }

    private static FieldSpec Field(byte kind, byte param, CharSet charSet, Spec inner)
    {
        bool ansi = charSet != CharSet.Unicode; // CharSet.Auto is ANSI on Unix
        int charSize = ansi ? 1 : 2;
        int k = (param & 7) + 1;    // array lengths
        int sc = (param & 31) + 1;  // ByValTStr sizes
        switch (kind % 54)
        {
            case 0: return Prim<byte>(1, (ref FuzzInput i) => i.Byte());
            case 1: return Prim<sbyte>(1, (ref FuzzInput i) => (sbyte)i.Byte());
            case 2: return Prim<short>(2, (ref FuzzInput i) => (short)i.UInt16());
            case 3: return Prim<ushort>(2, (ref FuzzInput i) => i.UInt16());
            case 4: return Prim<int>(4, (ref FuzzInput i) => i.Int32());
            case 5: return Prim<uint>(4, (ref FuzzInput i) => (uint)i.Int32());
            case 6: return Prim<long>(8, (ref FuzzInput i) => (long)i.Int32() << 32 | (uint)i.Int32());
            case 7: return Prim<ulong>(8, (ref FuzzInput i) => (ulong)i.Int32() << 32 | (uint)i.Int32());
            case 8: return Prim<nint>(8, (ref FuzzInput i) => (nint)i.Int32());
            case 9: return Prim<float>(4, (ref FuzzInput i) => BitConverter.Int32BitsToSingle(i.Int32()), (a, b) => BitConverter.SingleToInt32Bits((float)a) == BitConverter.SingleToInt32Bits((float)b));
            case 10: return Prim<double>(8, (ref FuzzInput i) => BitConverter.Int64BitsToDouble((long)i.Int32() << 32 | (uint)i.Int32()), (a, b) => BitConverter.DoubleToInt64Bits((double)a) == BitConverter.DoubleToInt64Bits((double)b));
            case 11: return Prim<Guid>(16, (ref FuzzInput i) => new Guid(i.Bytes(16).ToArray().Concat(new byte[16]).Take(16).ToArray()), align: 4);
            case 12: return Prim<decimal>(16, (ref FuzzInput i) => new decimal(i.Int32(), i.Int32(), i.Int32(), (i.Byte() & 1) != 0, (byte)(i.Byte() % 29)), (a, b) => decimal.GetBits((decimal)a).SequenceEqual(decimal.GetBits((decimal)b)), align: 8);
            case 13:
                // Currency: 4 decimal places, |value| < 2^63 / 10^4.
                return Prim<decimal>(8, (ref FuzzInput i) => decimal.FromOACurrency((long)i.Int32() << 16 | (uint)i.UInt16()), (a, b) => (decimal)a == (decimal)b, marshalAs: UnmanagedType.Currency, align: 8);
            case 14:
                // DateTime marshals as an OLE DATE (double): milliseconds survive, ticks don't.
                return Prim<DateTime>(8, (ref FuzzInput i) =>
                {
                    double d = BitConverter.Int64BitsToDouble((long)i.Int32() << 32 | (uint)i.Int32());
                    d = double.IsFinite(d) ? Math.Clamp(d % 2e6, -650000, 2900000) : 0;
                    return DateTime.FromOADate(d);
                }, (a, b) => ((DateTime)a).ToOADate() == ((DateTime)b).ToOADate(), align: 8);
            case 15: return Prim<TimeSpan>(8, (ref FuzzInput i) => new TimeSpan((long)i.Int32() << 32 | (uint)i.Int32()));
            case 16: return Prim<Half>(2, (ref FuzzInput i) => BitConverter.Int16BitsToHalf((short)i.UInt16()), (a, b) => BitConverter.HalfToInt16Bits((Half)a) == BitConverter.HalfToInt16Bits((Half)b));
            case 17: return Prim<Int128>(16, (ref FuzzInput i) => new Int128((ulong)i.Int32() << 32 | (uint)i.Int32(), (ulong)i.Int32() << 32 | (uint)i.Int32()), align: 16);
            case 18: return Prim<bool>(4, (ref FuzzInput i) => (i.Byte() & 1) != 0);
            case 19: return Prim<bool>(1, (ref FuzzInput i) => (i.Byte() & 1) != 0, marshalAs: UnmanagedType.U1);
            case 20: return Prim<bool>(1, (ref FuzzInput i) => (i.Byte() & 1) != 0, marshalAs: UnmanagedType.I1);
            case 21: return Prim<bool>(2, (ref FuzzInput i) => (i.Byte() & 1) != 0, marshalAs: UnmanagedType.VariantBool, mayFail: true);
            case 22: return Prim<bool>(4, (ref FuzzInput i) => (i.Byte() & 1) != 0, marshalAs: UnmanagedType.Bool);
            case 23: return Prim<char>(charSize, (ref FuzzInput i) => (char)i.UInt16(), SameChar(charSize == 1));
            case 24: return Prim<char>(1, (ref FuzzInput i) => (char)i.UInt16(), SameChar(true), marshalAs: UnmanagedType.U1);
            case 25: return Prim<char>(2, (ref FuzzInput i) => (char)i.UInt16(), marshalAs: UnmanagedType.U2);
            case 26: return Prim<char>(1, (ref FuzzInput i) => (char)i.UInt16(), SameChar(true), marshalAs: UnmanagedType.I1);
            case 27: return Prim<char>(2, (ref FuzzInput i) => (char)i.UInt16(), marshalAs: UnmanagedType.I2);
            case 28: return Str(null, utf8: ansi);
            case 29: return Str(UnmanagedType.LPStr, utf8: true);
            case 30: return Str(UnmanagedType.LPWStr, utf8: false);
            case 31: return Str(UnmanagedType.LPUTF8Str, utf8: true);
            case 32: return Str(UnmanagedType.BStr, utf8: false);
            case 33:
                return new FieldSpec
                {
                    Type = typeof(string), MarshalAs = UnmanagedType.ByValTStr, SizeConst = sc, NativeSize = sc * charSize, NativeAlign = charSize, Terminated = true, IsReference = true,
                    Value = (ref FuzzInput i) => Ascii(i.SegmentBytes(), sc - 1),
                    // A field read from raw bytes can hold SizeConst chars (no terminator); written back, the
                    // terminator takes the last byte when the text fills the field (MARSHAL-TSTR-1).
                    Same = (a, b) => (string)a == (string)b || a is string x && b is string y && y == Refit(x, sc, ansi),
                };
            case 34: return Str(UnmanagedType.LPTStr, utf8: false);
#pragma warning disable CS0618
            case 35: return Str(UnmanagedType.AnsiBStr, utf8: true, mayFail: true);
#pragma warning restore CS0618
            case 36: return Arr<byte>(k, 1, (ref FuzzInput i) => i.Byte());
            case 37: return Arr<int>(k, 4, (ref FuzzInput i) => i.Int32());
            case 38: return Arr<double>(k, 8, (ref FuzzInput i) => (double)i.Int32());
            case 39:
                return ((param >> 3) % 3) switch
                {
                    0 => Arr<char>(k, charSize, (ref FuzzInput i) => (char)(i.Byte() & 0x7F)),
                    1 => Arr<char>(k, 1, (ref FuzzInput i) => (char)(i.Byte() & 0x7F), UnmanagedType.U1),
                    _ => Arr<char>(k, 2, (ref FuzzInput i) => (char)i.UInt16(), UnmanagedType.U2),
                };
            case 40:
                return ((param >> 3) % 3) switch
                {
                    0 => Arr<bool>(k, 4, (ref FuzzInput i) => (i.Byte() & 1) != 0),
                    1 => Arr<bool>(k, 1, (ref FuzzInput i) => (i.Byte() & 1) != 0, UnmanagedType.U1),
                    _ => Arr<bool>(k, 2, (ref FuzzInput i) => (i.Byte() & 1) != 0, UnmanagedType.VariantBool, mayFail: true),
                };
            case 41:
            {
                UnmanagedType sub = ((param >> 3) % 3) switch { 0 => UnmanagedType.LPStr, 1 => UnmanagedType.LPWStr, _ => UnmanagedType.BStr };
                bool utf8 = sub == UnmanagedType.LPStr;
                return new FieldSpec
                {
                    Type = typeof(string[]), MarshalAs = UnmanagedType.ByValArray, SizeConst = k, ArraySubType = sub, NativeSize = k * 8, NativeAlign = 8, Pointer = true, IsReference = true,
                    Value = (ref FuzzInput i) =>
                    {
                        var array = new string[k];
                        for (int n = 0; n < k; n++)
                        {
                            array[n] = Text(i.SegmentBytes(), utf8);
                        }

                        return array;
                    },
                    Same = (a, b) => ((string[])a).SequenceEqual((string[])b),
                };
            }
            case 42 when inner?.Type is not null:
                return new FieldSpec
                {
                    Type = inner.Type, Inner = inner, NativeSize = NativeSizeOf(inner), NativeAlign = inner.NativeAlign, Pointer = inner.AnyPointer, IsReference = inner.IsClass || inner.ContainsReferences, MayFail = inner.AnyMayFail || inner.IsClass,
                    Value = (ref FuzzInput i) => Instantiate(inner, ref i),
                    Same = (a, b) => SameStruct(inner, a, b),
                };
            case 43 when inner?.Type is not null:
                return new FieldSpec
                {
                    Type = inner.Type.MakeArrayType(), Inner = inner, MarshalAs = UnmanagedType.ByValArray, SizeConst = k, NativeSize = k * NativeSizeOf(inner), NativeAlign = inner.NativeAlign, Pointer = inner.AnyPointer, IsReference = true, MayFail = inner.AnyMayFail,
                    Value = (ref FuzzInput i) =>
                    {
                        Array array = Array.CreateInstance(inner.Type, k);
                        for (int n = 0; n < k; n++)
                        {
                            array.SetValue(Instantiate(inner, ref i), n);
                        }

                        return array;
                    },
                    Same = (a, b) => ((Array)a).Cast<object>().Zip(((Array)b).Cast<object>()).All(t => SameStruct(inner, t.First, t.Second)),
                };
            case 44:
                return new FieldSpec
                {
                    Type = typeof(IntFn), NativeSize = 8, NativeAlign = 8, Pointer = true, IsReference = true,
                    Value = (ref FuzzInput i) => (i.Byte() & 1) != 0 ? null : new IntFn(Twice),
                    Same = (a, b) => a is null ? b is null : b is IntFn fn && fn(21) == 42,
                };
            case 45:
                return new FieldSpec
                {
                    Type = typeof(object), NativeSize = 8, NativeAlign = 8, Pointer = true, IsReference = true, MayFail = true, MarshalAs = (param & 1) != 0 ? UnmanagedType.IUnknown : null,
                    Value = (ref FuzzInput i) => null,
                    Same = (a, b) => a is null && b is null,
                };
            case 46: return Prim<ByteEnum>(1, (ref FuzzInput i) => (ByteEnum)i.Byte());
            case 47: return Prim<LongEnum>(8, (ref FuzzInput i) => (LongEnum)((long)i.Int32() << 32 | (uint)i.Int32()));
            case 48: return Prim<DayOfWeek>(4, (ref FuzzInput i) => (DayOfWeek)i.Int32());
            case 49: return Prim<IntPtr>(8, (ref FuzzInput i) => (IntPtr)i.Int32());
            case 50:
                // A generic struct: not marshallable.
                return new FieldSpec { Type = typeof(KeyValuePair<int, int>), NativeSize = 8, NativeAlign = 4, MayFail = true, Value = (ref FuzzInput i) => new KeyValuePair<int, int>(i.Int32(), i.Int32()), Same = (a, b) => Equals(a, b) };
            case 51:
                return new FieldSpec { Type = typeof(DateTimeOffset), NativeSize = 16, NativeAlign = 8, MayFail = true, Value = (ref FuzzInput i) => new DateTimeOffset(new DateTime(2000, 1, 1).AddSeconds(i.Int32() & 0xFFFFFF)), Same = (a, b) => Equals(a, b) };
            case 52:
                return new FieldSpec
                {
                    Type = typeof(SafeFileHandle), NativeSize = 8, NativeAlign = 8, Pointer = true, IsReference = true, MayFail = true,
                    Value = (ref FuzzInput i) => new SafeFileHandle((IntPtr)(-1), ownsHandle: false),
                    Same = (a, b) => a is SafeFileHandle x && b is SafeFileHandle y && x.DangerousGetHandle() == y.DangerousGetHandle(),
                };
            default:
                return Prim<int>(4, (ref FuzzInput i) => i.Int32());
        }
    }

    private static FieldSpec Prim<T>(int size, Reader read, Func<object, object, bool> same = null, UnmanagedType? marshalAs = null, int align = 0, bool mayFail = false) =>
        new()
        {
            Type = typeof(T), MarshalAs = marshalAs, NativeSize = size, NativeAlign = align == 0 ? size : align, MayFail = mayFail,
            Value = read,
            Same = same ?? ((a, b) => Equals(a, b)),
        };

    private static Func<object, object, bool> SameChar(bool ansi) => (a, b) => (char)a == (char)b || ansi && (char)a > 0x7F;

    private static FieldSpec Str(UnmanagedType? marshalAs, bool utf8, bool mayFail = false) =>
        new()
        {
            Type = typeof(string), MarshalAs = marshalAs, NativeSize = 8, NativeAlign = 8, Pointer = true, IsReference = true, MayFail = mayFail,
            Value = (ref FuzzInput i) => (i.Byte() & 7) == 0 ? null : Text(i.SegmentBytes(), utf8),
            Same = (a, b) => (string)a == (string)b,
        };

    private static FieldSpec Arr<T>(int k, int elementSize, Reader read, UnmanagedType? subType = null, bool mayFail = false) =>
        new()
        {
            Type = typeof(T[]), MarshalAs = UnmanagedType.ByValArray, SizeConst = k, ArraySubType = subType, NativeSize = k * elementSize, NativeAlign = elementSize, IsReference = true, MayFail = mayFail,
            Terminated = typeof(T) == typeof(char) && elementSize == 1,
            Value = (ref FuzzInput i) =>
            {
                var array = new T[k];
                for (int n = 0; n < k; n++)
                {
                    array[n] = (T)read(ref i);
                }

                return array;
            },
            Same = (a, b) => ((T[])a).SequenceEqual((T[])b),
        };

    /// <summary>Text from input bytes: UTF-8 decoded, no NULs; through UTF-8 twice when the native form is UTF-8 (lone surrogates become U+FFFD).</summary>
    private static string Text(ReadOnlySpan<byte> bytes, bool utf8)
    {
        string s = Encoding.UTF8.GetString(bytes).Replace("\0", "");
        return utf8 ? Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(s)) : s;
    }

    /// <summary>What a ByValTStr field of <paramref name="sizeConst"/> units holds after writing <paramref name="text"/> and reading it back.</summary>
    private static string Refit(string text, int sizeConst, bool ansi)
    {
        if (!ansi)
        {
            return text.Length >= sizeConst ? text.Substring(0, sizeConst - 1) : text;
        }

        byte[] bytes = Encoding.UTF8.GetBytes(text);
        return bytes.Length >= sizeConst ? Encoding.UTF8.GetString(bytes, 0, sizeConst - 1) : Encoding.UTF8.GetString(bytes);
    }

    private static string Ascii(ReadOnlySpan<byte> bytes, int max)
    {
        var sb = new StringBuilder();
        foreach (byte b in bytes)
        {
            if (sb.Length == max)
            {
                break;
            }

            if (b is > 0 and < 0x80)
            {
                sb.Append((char)b);
            }
        }

        return sb.ToString();
    }

    // ---------------------------------------------------------------- the layout model

    private static int NativeSizeOf(Spec spec)
    {
        if (spec.Layout == LayoutKind.Explicit)
        {
            int end = spec.Fields.Count == 0 ? 0 : spec.Fields.Max(f => f.Offset + f.NativeSize);
            return spec.Size > 0 ? Math.Max(spec.Size, end) : RoundUp(end, spec.NativeAlign);
        }

        int offset = 0;
        foreach (FieldSpec f in spec.Fields)
        {
            offset = RoundUp(offset, Math.Min(spec.Pack, f.NativeAlign)) + f.NativeSize;
        }

        return spec.Size > 0 ? Math.Max(spec.Size, offset) : RoundUp(offset, spec.NativeAlign);
    }

    private static int RoundUp(int value, int align) => align <= 1 ? value : (value + align - 1) / align * align;

    private static object Instantiate(Spec spec, ref FuzzInput input)
    {
        object boxed = Activator.CreateInstance(spec.Type);
        foreach (FieldSpec f in spec.Fields)
        {
            spec.Type.GetField(f.Name).SetValue(boxed, f.Value(ref input));
        }

        return boxed;
    }

    private static bool SameStruct(Spec spec, object a, object b)
    {
        foreach (FieldSpec f in spec.Fields)
        {
            if (Overlaps(spec, f))
            {
                continue;
            }

            if (!f.Same(spec.Type.GetField(f.Name).GetValue(a), spec.Type.GetField(f.Name).GetValue(b)))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>In an explicit layout, fields sharing bytes don't round-trip independently.</summary>
    private static bool Overlaps(Spec spec, FieldSpec f) =>
        spec.Layout == LayoutKind.Explicit && spec.Fields.Any(o => o != f && f.Offset < o.Offset + o.NativeSize && o.Offset < f.Offset + f.NativeSize);

    private static string Describe(Spec spec, object boxed)
    {
        if (boxed is null)
        {
            return "null";
        }

        var sb = new StringBuilder("{");
        foreach (FieldSpec f in spec.Fields)
        {
            object v = boxed is null ? null : spec.Type.GetField(f.Name).GetValue(boxed);
            sb.Append(f.Name).Append('=').Append(v switch
            {
                null => "null",
                string s => Check.Show(s),
                Array a => "[" + string.Join(",", a.Cast<object>().Select(e => e is string es ? Check.Show(es) : f.Inner is not null ? Describe(f.Inner, e) : Check.Show(e))) + "]",
                _ when f.Inner is not null => Describe(f.Inner, v),
                _ => Check.Show(v),
            }).Append(' ');
        }

        return sb.Append('}').ToString();
    }

    // ---------------------------------------------------------------- exercising

    private static bool Allowed(Exception e) =>
        e is ArgumentException or TypeLoadException or MarshalDirectiveException or NotSupportedException or PlatformNotSupportedException or OverflowException or MissingMethodException or InvalidOperationException;

    private static void Exercise(ModuleBuilder module, Spec spec, ref FuzzInput input)
    {
        Type t = spec.Type;
        string what = spec.ToString();
        bool strict = !spec.AnyMayFail;
        if (s_trace)
        {
            Console.WriteLine($"spec: {what}");
        }

        int size;
        try
        {
            size = Marshal.SizeOf(t);
        }
        catch (ArgumentException) when (spec.Layout == LayoutKind.Auto)
        {
            return; // documented: auto layout can't be marshalled
        }
        catch (Exception e) when (Allowed(e) && !strict)
        {
            return;
        }
        catch (ArgumentException e)
        {
            throw new ConsistencyException($"Marshal.SizeOf threw {e.Message} for {what}");
        }

        Check.That(spec.Layout != LayoutKind.Auto, $"Marshal.SizeOf accepted an auto-layout struct: {what}");
        Check.That(size > 0 && size <= Guarded.SlotBytes / 4, $"Marshal.SizeOf {size} for {what}");
        if (strict)
        {
            if (spec.Layout == LayoutKind.Sequential)
            {
                Check.Equal(NativeSizeOf(spec), size, $"Marshal.SizeOf for {what}");
            }
            else
            {
                int end = Math.Max(spec.Size, spec.Fields.Max(f => f.Offset + f.NativeSize));
                Check.That(size >= end, $"Marshal.SizeOf {size} < {end} for {what}");
            }
        }

        int expectedOffset = 0;
        foreach (FieldSpec f in spec.Fields)
        {
            int offset;
            try
            {
                offset = (int)Marshal.OffsetOf(t, f.Name);
            }
            catch (Exception e) when (Allowed(e) && !strict)
            {
                return;
            }

            if (strict)
            {
                if (spec.Layout == LayoutKind.Explicit)
                {
                    Check.Equal(f.Offset, offset, $"Marshal.OffsetOf({f.Name}) for {what}");
                }
                else
                {
                    expectedOffset = RoundUp(expectedOffset, Math.Min(spec.Pack, f.NativeAlign));
                    Check.Equal(expectedOffset, offset, $"Marshal.OffsetOf({f.Name}) for {what}");
                    expectedOffset += f.NativeSize;
                }
            }

            Check.That(offset >= 0 && (!strict || offset + f.NativeSize <= size), $"field {f.Name} at {offset}+{f.NativeSize} outside SizeOf {size} for {what}");
        }

        // Values in, through exactly SizeOf guarded bytes, and back.
        object value = Instantiate(spec, ref input);
        byte* p = Guarded.Allocate(size, atStart: false);
        new Span<byte>(p, size).Fill(0xCC);
        if (!ToNative(value, p, !strict, what))
        {
            return;
        }

        object back;
        try
        {
            back = Marshal.PtrToStructure((nint)p, t);
            if (spec.IsClass)
            {
                // The in-place overload fills an existing instance.
                object existing = Activator.CreateInstance(t);
                Marshal.PtrToStructure((nint)p, existing);
                Check.That(SameStruct(spec, value, existing), $"in-place PtrToStructure changed the value: {Describe(spec, value)} -> {Describe(spec, existing)}: {what}");
            }
        }
        finally
        {
            Marshal.DestroyStructure((nint)p, t);
        }

        Check.That(SameStruct(spec, value, back), $"round trip changed the value: {Describe(spec, value)} -> {Describe(spec, back)}: {what}");

        // The emitted DllImport stubs: memcpy(byte*, ref T, nuint) and memcpy(byte*, T[], nuint) must
        // hand memcpy the same bytes StructureToPtr produces (field by field; padding is unspecified).
        if ((input.Byte() & 1) != 0 && strict)
        {
            if (spec.IsClass)
            {
                ClassStubs(module, spec, value, size, what);
            }
            else
            {
                Stubs(module, spec, value, size, what);
            }
        }

        // Arbitrary bytes as the native representation (only without pointers), marshalled back out
        // and in again: the second read must equal the first.
        if (!spec.AnyPointer)
        {
            byte* q = Guarded.Allocate(size, atStart: true);
            ReadOnlySpan<byte> raw = input.Bytes(size);
            raw.CopyTo(new Span<byte>(q, size));
            new Span<byte>(q + raw.Length, size - raw.Length).Clear();
            object first;
            try
            {
                first = Marshal.PtrToStructure((nint)q, t);
            }
            catch (Exception e) when (e is ArgumentException or OverflowException)
            {
                return; // e.g. an invalid OLE date or DECIMAL scale
            }

            byte* r = Guarded.Allocate(size, atStart: false);
            new Span<byte>(r, size).Fill(0xCC);
            object second;
            try
            {
                if (!ToNative(first, r, !strict, what))
                {
                    return;
                }

                second = Marshal.PtrToStructure((nint)r, t);
            }
            catch (Exception e) when (e is ArgumentException or OverflowException)
            {
                return; // e.g. a DateTime outside the OLE date range, a decimal outside the Currency range
            }

            Check.That(SameStruct(spec, first, second), $"re-marshalling changed the value: {Describe(spec, first)} -> {Describe(spec, second)}: {what}");
        }
    }

    // Known (MARSHAL-TSTR-1): ANSI by-value strings / char arrays throw ArgumentException for non-ASCII text.
    private static bool ToNative(object value, byte* native, bool mayFail, string what)
    {
        try
        {
            Marshal.StructureToPtr(value, (nint)native, fDeleteOld: false);
            return true;
        }
        catch (ArgumentException e) when (!s_reportKnownIssues && (e.StackTrace?.Contains("CSTRMarshaler.ConvertFixedToNative", StringComparison.Ordinal) == true ||
            e.StackTrace?.Contains("AnsiCharArrayMarshaler", StringComparison.Ordinal) == true))
        {
            return false;
        }
        catch (Exception e) when (mayFail && Allowed(e))
        {
            return false;
        }
    }

    private static void Stubs(ModuleBuilder module, Spec spec, object value, int size, string what)
    {
        Type t = spec.Type;
        CharSet charSet = spec.CharSet == CharSet.None ? CharSet.Ansi : spec.CharSet;
        TypeBuilder tb = module.DefineType("Native", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
        MethodBuilder byRef = tb.DefinePInvokeMethod("memcpy", "libc", "memcpy", MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl, CallingConventions.Standard,
            typeof(IntPtr), [typeof(IntPtr), t.MakeByRefType(), typeof(nuint)], CallingConvention.Cdecl, charSet);
        byRef.SetImplementationFlags(MethodImplAttributes.PreserveSig);
        MethodBuilder byArray = tb.DefinePInvokeMethod("memcpyArray", "libc", "memcpy", MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl, CallingConventions.Standard,
            typeof(IntPtr), [typeof(IntPtr), t.MakeArrayType(), typeof(nuint)], CallingConvention.Cdecl, charSet);
        byArray.SetImplementationFlags(MethodImplAttributes.PreserveSig);
        Type native = tb.CreateType();

        byte* expected = Guarded.Allocate(size, atStart: true);
        new Span<byte>(expected, size).Fill(0xCC);
        Marshal.StructureToPtr(value, (nint)expected, fDeleteOld: false);
        try
        {
            byte* dst = Guarded.Allocate(size, atStart: false);
            new Span<byte>(dst, size).Fill(0xCC);
            object[] args = [(IntPtr)dst, value, (nuint)size];
            try
            {
                native.GetMethod("memcpy").Invoke(null, args);
            }
            catch (TargetInvocationException e) when (Allowed(e.InnerException))
            {
                return; // the stub generator rejects the type
            }

            CompareFields(spec, expected, dst, "memcpy(byte*, ref T, n)", what);
            Check.That(SameStruct(spec, value, args[1]), $"ref T came back changed by memcpy(byte*, ref T, n): {Describe(spec, value)} -> {Describe(spec, args[1])}: {what}");

            const int Count = 3;
            byte* dst3 = Guarded.Allocate(size * Count, atStart: false);
            new Span<byte>(dst3, size * Count).Fill(0xCC);
            Array array = Array.CreateInstance(t, Count);
            for (int i = 0; i < Count; i++)
            {
                array.SetValue(value, i);
            }

            try
            {
                native.GetMethod("memcpyArray").Invoke(null, [(IntPtr)dst3, array, (nuint)(size * Count)]);
            }
            catch (TargetInvocationException e) when (Allowed(e.InnerException))
            {
                return;
            }

            for (int i = 0; i < Count; i++)
            {
                CompareFields(spec, expected, dst3 + i * size, $"memcpy(byte*, T[], n) element {i}", what);
            }
        }
        finally
        {
            Marshal.DestroyStructure((nint)expected, t);
        }
    }

    /// <summary>Layout classes as P/Invoke parameters: [In] (pointer to the native layout), [Out] and [In, Out] (copied back), and arrays of them.</summary>
    private static void ClassStubs(ModuleBuilder module, Spec spec, object value, int size, string what)
    {
        Type t = spec.Type;
        CharSet charSet = spec.CharSet == CharSet.None ? CharSet.Ansi : spec.CharSet;
        TypeBuilder tb = module.DefineType("Native", TypeAttributes.Public | TypeAttributes.Abstract | TypeAttributes.Sealed);
        MethodBuilder inStub = tb.DefinePInvokeMethod("memcpyIn", "libc", "memcpy", MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl, CallingConventions.Standard,
            typeof(IntPtr), [typeof(IntPtr), t, typeof(nuint)], CallingConvention.Cdecl, charSet);
        inStub.SetImplementationFlags(MethodImplAttributes.PreserveSig);
        MethodBuilder outStub = tb.DefinePInvokeMethod("memcpyOut", "libc", "memcpy", MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl, CallingConventions.Standard,
            typeof(IntPtr), [t, typeof(IntPtr), typeof(nuint)], CallingConvention.Cdecl, charSet);
        outStub.SetImplementationFlags(MethodImplAttributes.PreserveSig);
        outStub.DefineParameter(1, ParameterAttributes.Out, "dst");
        MethodBuilder inOutStub = tb.DefinePInvokeMethod("memcpyInOut", "libc", "memcpy", MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl, CallingConventions.Standard,
            typeof(IntPtr), [t, typeof(IntPtr), typeof(nuint)], CallingConvention.Cdecl, charSet);
        inOutStub.SetImplementationFlags(MethodImplAttributes.PreserveSig);
        inOutStub.DefineParameter(1, ParameterAttributes.In | ParameterAttributes.Out, "dst");
        MethodBuilder arrayIn = tb.DefinePInvokeMethod("memcpyArrayIn", "libc", "memcpy", MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl, CallingConventions.Standard,
            typeof(IntPtr), [typeof(IntPtr), t.MakeArrayType(), typeof(nuint)], CallingConvention.Cdecl, charSet);
        arrayIn.SetImplementationFlags(MethodImplAttributes.PreserveSig);
        MethodBuilder arrayOut = tb.DefinePInvokeMethod("memcpyArrayOut", "libc", "memcpy", MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl, CallingConventions.Standard,
            typeof(IntPtr), [t.MakeArrayType(), typeof(IntPtr), typeof(nuint)], CallingConvention.Cdecl, charSet);
        arrayOut.SetImplementationFlags(MethodImplAttributes.PreserveSig);
        arrayOut.DefineParameter(1, ParameterAttributes.Out, "dst");
        Type native = tb.CreateType();

        byte* expected = Guarded.Allocate(size, atStart: true);
        new Span<byte>(expected, size).Fill(0xCC);
        Marshal.StructureToPtr(value, (nint)expected, fDeleteOld: false);
        try
        {
            // [In]: memcpy reads the native layout the stub built.
            byte* dst = Guarded.Allocate(size, atStart: false);
            new Span<byte>(dst, size).Fill(0xCC);
            try
            {
                native.GetMethod("memcpyIn").Invoke(null, [(IntPtr)dst, value, (nuint)size]);
            }
            catch (TargetInvocationException e) when (Allowed(e.InnerException))
            {
                return;
            }

            CompareFields(spec, expected, dst, "memcpy(byte*, [In] class, n)", what);
            // [Out]: the stub's temporary is filled by memcpy from the expected bytes and copied into a fresh instance.
            object fresh = Activator.CreateInstance(spec.Type);
            object[] outArgs = [fresh, (IntPtr)expected, (nuint)size];
            native.GetMethod("memcpyOut").Invoke(null, outArgs);
            Check.That(SameStruct(spec, value, fresh), $"[Out] class came back as {Describe(spec, fresh)}, expected {Describe(spec, value)}: {what}");
            // [In, Out]: starts from the value, memcpy overwrites the temporary with the same bytes, the value is copied back.
            object inOut = Activator.CreateInstance(spec.Type);
            native.GetMethod("memcpyInOut").Invoke(null, [inOut, (IntPtr)expected, (nuint)size]);
            Check.That(SameStruct(spec, value, inOut), $"[In, Out] class came back as {Describe(spec, inOut)}, expected {Describe(spec, value)}: {what}");
            // Arrays of layout classes: one native layout per element, in and out.
            const int Count = 3;
            Array array = Array.CreateInstance(t, Count);
            for (int i = 0; i < Count; i++)
            {
                array.SetValue(value, i);
            }

            byte* dst3 = Guarded.Allocate(size * Count, atStart: false);
            new Span<byte>(dst3, size * Count).Fill(0xCC);
            native.GetMethod("memcpyArrayIn").Invoke(null, [(IntPtr)dst3, array, (nuint)(size * Count)]);
            for (int i = 0; i < Count; i++)
            {
                CompareFields(spec, expected, dst3 + i * size, $"memcpy(byte*, [In] class[], n) element {i}", what);
            }

            Array outArray = Array.CreateInstance(t, Count);
            native.GetMethod("memcpyArrayOut").Invoke(null, [outArray, (IntPtr)dst3, (nuint)(size * Count)]);
            for (int i = 0; i < Count; i++)
            {
                Check.That(outArray.GetValue(i) is object element && SameStruct(spec, value, element), $"[Out] class[] element {i} came back as {Describe(spec, outArray.GetValue(i))}: {what}");
            }
        }
        finally
        {
            Marshal.DestroyStructure((nint)expected, t);
        }
    }

    private static void CompareFields(Spec spec, byte* expected, byte* actual, string how, string what)
    {
        foreach (FieldSpec f in spec.Fields)
        {
            if (f.Pointer || f.Inner is not null)
            {
                continue; // pointers to separately allocated strings differ; nested padding is unspecified
            }

            int offset = (int)Marshal.OffsetOf(spec.Type, f.Name);
            var e = new ReadOnlySpan<byte>(expected + offset, f.NativeSize);
            var a = new ReadOnlySpan<byte>(actual + offset, f.NativeSize);
            if (f.Terminated)
            {
                // Only the text up to and including its NUL is specified.
                int nul = e.IndexOf((byte)0);
                if (nul >= 0)
                {
                    e = e.Slice(0, nul + 1);
                    a = a.Slice(0, nul + 1);
                }
            }

            Check.That(e.SequenceEqual(a), $"{how}: field {f.Name} bytes {Convert.ToHexString(a)} differ from StructureToPtr's {Convert.ToHexString(e)}: {what}");
        }
    }
}
