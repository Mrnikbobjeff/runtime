#nullable disable warnings
using System.Globalization;
using System.Reflection;
using System.Reflection.Emit;

namespace SharpFuzzHarness;

/// <summary>Fuzzes Enum parsing, formatting and name lookup.</summary>
/// <remarks>
/// Input layout:
///   byte 0     enum type index (see <see cref="s_types"/>)
///   byte 1     0x01 ignoreCase
///   8 bytes    raw value for formatting checks
///   segment    text to parse
///   segment    format string
/// The enums cover every underlying type, [Flags], duplicate and zero-valued names, sparse and
/// contiguous values, an empty enum and, built with EnumBuilder, char/bool/float/double/nint/nuint
/// underlying types that C# can't declare.
/// Checks: Parse / TryParse (generic, non-generic, string, span) agree with each other and with a
/// reference for plain name lists and plain numbers; ToString / Enum.Format / TryFormat agree;
/// "G" and "D" output parses back; GetName, IsDefined and ToString agree.
/// </remarks>
public static class EnumTarget
{
    public enum Plain { A, B, C, D = 10, E = -1 }
    [Flags] public enum ByteFlags : byte { None = 0, X = 1, Y = 2, Z = 4, XY = 3, High = 0x80 }
    public enum SByteEnum : sbyte { Min = -128, Zero = 0, Max = 127 }
    [Flags] public enum ShortFlags : short { A = 1, B = 2, C = 4, Negative = -32768, AllLow = 7 }
    public enum UShortDuplicates : ushort { First = 5, Second = 5, Other = 6, zero = 0, Zero = 0 }
    [Flags] public enum UIntFlags : uint { Bit0 = 1, Bit1 = 2, Bit31 = 0x80000000, All = 0xFFFFFFFF }
    public enum LongEnum : long { Min = long.MinValue, Max = long.MaxValue, Zero = 0, MinusOne = -1 }
    [Flags] public enum ULongFlags : ulong { None = 0, One = 1, High = 1UL << 63, Both = One | High }
    public enum Empty { }
    [Flags] public enum ZeroAlias { Nothing = 0, Zip = 0, A = 1, B = 2, AB = 3, C = 8, ABC = 11 }
    public enum Sparse { N5 = -5, N0 = 0, N3 = 3, N7 = 7, N1000 = 1000, N1001 = 1001, NMax = int.MaxValue }
    public enum Contiguous { M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, M16, M17, M18, M19, M20, M21, M22, M23, M24, M25, M26, M27, M28, M29, M30, M31, M32, M33, M34, M35, M36, M37, M38, M39 }
    [Flags] public enum ManyFlags { F0 = 1 << 0, F1 = 1 << 1, F2 = 1 << 2, F3 = 1 << 3, F4 = 1 << 4, F5 = 1 << 5, F6 = 1 << 6, F7 = 1 << 7, F8 = 1 << 8, F9 = 1 << 9, F10 = 1 << 10, F11 = 1 << 11, F12 = 1 << 12, F13 = 1 << 13, F14 = 1 << 14, F15 = 1 << 15, F16 = 1 << 16, F30 = 1 << 30, Low4 = 15, Mid = 0x30, Neg = int.MinValue }
    public enum Unicode { Äpfel, Ölig, Straße, ǅ, ﬁ, Ǆ = 7, İ }

    private static readonly Type[] s_types = BuildTypes();

    private static Type[] BuildTypes()
    {
        var types = new List<Type>
        {
            typeof(Plain), typeof(ByteFlags), typeof(SByteEnum), typeof(ShortFlags), typeof(UShortDuplicates), typeof(UIntFlags),
            typeof(LongEnum), typeof(ULongFlags), typeof(Empty), typeof(ZeroAlias), typeof(Sparse), typeof(Contiguous),
            typeof(ManyFlags), typeof(Unicode), typeof(DayOfWeek), typeof(AttributeTargets), typeof(BindingFlags), typeof(StringSplitOptions),
        };

        // Underlying types C# can't declare. Each one is optional: skip it if the runtime refuses.
        // (bool/float/double-backed enums load, but every Enum API rejects them as "Unknown enum type".)
        ModuleBuilder module = AssemblyBuilder.DefineDynamicAssembly(new AssemblyName("FuzzEnums"), AssemblyBuilderAccess.Run).DefineDynamicModule("FuzzEnums");
        (Type Underlying, bool Flags, object[] Values)[] dynamic =
        [
            (typeof(char), false, ['a', 'b', 'z', '\0', '￿']),
            (typeof(char), true, [(char)1, (char)2, (char)4, (char)0x8000]),
            (typeof(nint), false, [(nint)0, (nint)1, (nint)(-1), nint.MaxValue]),
            (typeof(nuint), true, [(nuint)1, (nuint)2, nuint.MaxValue]),
        ];
        int n = 0;
        foreach (var (underlying, flags, values) in dynamic)
        {
            try
            {
                EnumBuilder builder = module.DefineEnum($"Dyn{n++}_{underlying.Name}", TypeAttributes.Public, underlying);
                if (flags)
                {
                    builder.SetCustomAttribute(new CustomAttributeBuilder(typeof(FlagsAttribute).GetConstructor(Type.EmptyTypes)!, []));
                }

                for (int i = 0; i < values.Length; i++)
                {
                    builder.DefineLiteral($"V{i}", values[i]);
                }

                types.Add(builder.CreateType());
            }
            catch (Exception e) when (e is ArgumentException or NotSupportedException or TypeLoadException or InvalidOperationException)
            {
            }
        }

        return types.ToArray();
    }

    private static bool IsParseError(Exception e) => e is ArgumentException or OverflowException;

    // Generic overloads, for the compile-time enums.
    private static readonly Dictionary<Type, Action<string, bool, Outcome<(bool, object)>>> s_generic = s_types
        .Where(t => t.Assembly == typeof(EnumTarget).Assembly || t.Assembly == typeof(object).Assembly)
        .ToDictionary(t => t, t => typeof(EnumTarget).GetMethod(nameof(Generic), BindingFlags.NonPublic | BindingFlags.Static)!
            .MakeGenericMethod(t).CreateDelegate<Action<string, bool, Outcome<(bool, object)>>>());

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        Type type = s_types[input.Byte() % s_types.Length];
        bool ignoreCase = (input.Byte() & 1) != 0;
        ulong raw = (uint)input.Int32() | ((ulong)(uint)input.Int32() << 32);
        string text = input.Segment();
        string format = input.Segment();
        if (text.Length > 256 || format.Length > 16)
        {
            return;
        }

        string what = $"{type.Name} {Check.Show(text)} ignoreCase={ignoreCase}";
        var eq = EqualityComparer<object>.Default;
        var tryParse = Outcome<(bool, object)>.Of(() => (Enum.TryParse(type, text, ignoreCase, out object? v), v!), _ => false);
        var parse = Outcome<object>.Of(() => Enum.Parse(type, text, ignoreCase), IsParseError);
        Check.ParseAgreement(what, eq, parse, [typeof(ArgumentException), typeof(OverflowException)], tryParse,
            ("TryParse(span)", Outcome<(bool, object)>.Of(() => (Enum.TryParse(type, text.AsSpan(), ignoreCase, out object? v), v!), _ => false)));
        var parseSpan = Outcome<object>.Of(() => Enum.Parse(type, text.AsSpan(), ignoreCase), IsParseError);
        Check.That(parse.SameAs(parseSpan), $"Enum.Parse(string) {parse} != Enum.Parse(span) {parseSpan} for {what}");
        if (s_generic.TryGetValue(type, out var generic))
        {
            generic(text, ignoreCase, tryParse);
        }

        CheckReference(type, text, ignoreCase, tryParse.Value.Item1, tryParse.Value.Item2, what);

        object value = Enum.ToObject(type, ConvertRaw(type, raw));
        if (tryParse.Value.Item1)
        {
            CheckValue(type, tryParse.Value.Item2, format);
        }

        CheckValue(type, value, format);
    }

    private static void Generic<T>(string text, bool ignoreCase, Outcome<(bool, object)> expected)
        where T : struct, Enum
    {
        bool ok = Enum.TryParse(text, ignoreCase, out T v);
        bool okSpan = Enum.TryParse(text.AsSpan(), ignoreCase, out T vSpan);
        string what = $"{typeof(T).Name} {Check.Show(text)} ignoreCase={ignoreCase}";
        Check.That(ok == expected.Value.Item1 && (!ok || v.Equals(expected.Value.Item2)), $"Enum.TryParse<{typeof(T).Name}> {ok}/{v} != non-generic {expected} for {what}");
        Check.That(okSpan == ok && vSpan.Equals(v), $"Enum.TryParse<{typeof(T).Name}>(span) {okSpan}/{vSpan} != string overload for {what}");
        var parse = Outcome<T>.Of(() => Enum.Parse<T>(text, ignoreCase), IsParseError);
        Check.That(parse.Ok == ok && (!ok || parse.Value.Equals(v)), $"Enum.Parse<{typeof(T).Name}> {parse} != TryParse for {what}");

        char[] buffer = new char[512];
        foreach (string f in (string[])["G", "D", "X", "F", "g", "d", "x", "f", ""])
        {
            string s = v.ToString(f);
            Check.That(Enum.TryFormat(v, buffer, out int written, f) && buffer.AsSpan(0, written).SequenceEqual(s), $"Enum.TryFormat<{typeof(T).Name}>({v}, {f}) != ToString {Check.Show(s)}");
            Check.That(s.Length == 0 || !Enum.TryFormat(v, buffer.AsSpan(0, s.Length - 1), out _, f), $"Enum.TryFormat<{typeof(T).Name}>({v}, {f}) into a short buffer succeeded");
        }
    }

    private static object ConvertRaw(Type type, ulong raw) => Type.GetTypeCode(Enum.GetUnderlyingType(type)) switch
    {
        TypeCode.Char => (char)raw,
        TypeCode.Boolean => (raw & 1) != 0,
        TypeCode.Single => (float)BitConverter.Int32BitsToSingle((int)raw),
        TypeCode.Double => BitConverter.Int64BitsToDouble((long)raw),
        _ when Enum.GetUnderlyingType(type) == typeof(nint) => (long)raw,
        _ => raw,
    };

    /// <summary>
    /// Reference semantics for two input shapes: a plain integer (optionally signed and padded with
    /// whitespace), and a comma-separated list of identifiers. Anything else isn't checked.
    /// </summary>
    private static void CheckReference(Type type, string text, bool ignoreCase, bool ok, object value, string what)
    {
        Type underlying = Enum.GetUnderlyingType(type);
        TypeCode code = Type.GetTypeCode(underlying);
        if (code is < TypeCode.SByte or > TypeCode.UInt64)
        {
            return;
        }

        string trimmed = text.Trim();
        if (trimmed.Length == 0)
        {
            Check.That(!ok, $"Enum.TryParse accepted blank {what}");
            return;
        }

        if (char.IsAsciiDigit(trimmed[0]) || trimmed[0] is '-' or '+')
        {
            bool refOk = code switch
            {
                TypeCode.SByte => sbyte.TryParse(trimmed, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out _),
                TypeCode.Byte => byte.TryParse(trimmed, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out _),
                TypeCode.Int16 => short.TryParse(trimmed, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out _),
                TypeCode.UInt16 => ushort.TryParse(trimmed, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out _),
                TypeCode.Int32 => int.TryParse(trimmed, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out _),
                TypeCode.UInt32 => uint.TryParse(trimmed, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out _),
                TypeCode.Int64 => long.TryParse(trimmed, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out _),
                _ => ulong.TryParse(trimmed, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out _),
            };
            if (refOk)
            {
                object expected = Convert.ChangeType(decimal.Parse(trimmed, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture), underlying, CultureInfo.InvariantCulture);
                Check.That(ok && Convert.ChangeType(value, underlying, CultureInfo.InvariantCulture).Equals(expected), $"Enum.TryParse gave {(ok ? value : "failure")} for numeric {what}, expected {expected}");
            }

            return;
        }

        string[] names = Enum.GetNames(type);
        ulong[] values = Enum.GetValues(type).Cast<object>().Select(v => ToUInt64(v, code)).ToArray();
        ulong result = 0;
        foreach (string token in trimmed.Split(','))
        {
            string name = token.Trim();
            if (name.Length == 0 || !(char.IsLetter(name[0]) || name[0] == '_') || !name.All(ch => char.IsLetterOrDigit(ch) || ch == '_'))
            {
                return; // Not a plain identifier list; no reference.
            }

            int index = Array.FindIndex(names, n => string.Equals(n, name, StringComparison.Ordinal));
            if (index < 0 && ignoreCase)
            {
                index = Array.FindIndex(names, n => string.Equals(n, name, StringComparison.OrdinalIgnoreCase));
            }

            if (index < 0)
            {
                Check.That(!ok, $"Enum.TryParse accepted {what} although {Check.Show(name)} isn't a member name");
                return;
            }

            result |= values[index];
        }

        Check.That(ok && ToUInt64(value, code) == result, $"Enum.TryParse gave {(ok ? value : "failure")} for {what}, expected {result:X}");
    }

    private static ulong ToUInt64(object value, TypeCode code) => code switch
    {
        TypeCode.SByte or TypeCode.Int16 or TypeCode.Int32 or TypeCode.Int64 => (ulong)Convert.ToInt64(value, CultureInfo.InvariantCulture),
        _ => Convert.ToUInt64(value, CultureInfo.InvariantCulture),
    };

    private static void CheckValue(Type type, object value, string format)
    {
        foreach (string f in new[] { format, "G", "D", "X", "F", "g", "d", "x", "f" })
        {
            var s = Outcome<string>.Of(() => ((Enum)value).ToString(f), e => e is FormatException);
            var formatted = Outcome<string>.Of(() => Enum.Format(type, value, f), e => e is FormatException);
            Check.That(s.SameAs(formatted), $"{type.Name} {value}: ToString({Check.Show(f)}) {s} != Enum.Format {formatted}");
            var span = Outcome<string>.Of(() =>
            {
                char[] buffer = new char[1024];
                return ((ISpanFormattable)value).TryFormat(buffer, out int written, f, null) ? new string(buffer, 0, written) : null!;
            }, e => e is FormatException);
            Check.That(s.SameAs(span), $"{type.Name} {value}: ToString({Check.Show(f)}) {s} != TryFormat {span}");
        }

        // "G" and "D" output must parse back (only checked for integral underlying types: a char
        // or float enum formats undefined values in ways Enum.Parse doesn't promise to accept).
        string g = value.ToString()!;
        string d = Enum.Format(type, value, "D");
        if (Type.GetTypeCode(Enum.GetUnderlyingType(type)) is >= TypeCode.SByte and <= TypeCode.UInt64)
        {
            bool ok = Enum.TryParse(type, g, false, out object? back);
            Check.That(ok && back!.Equals(value), $"{type.Name} {Check.Show(g)} (ToString of {d}) doesn't parse back: {(ok ? back : "failure")}");
            ok = Enum.TryParse(type, d, false, out back);
            Check.That(ok && back!.Equals(value), $"{type.Name} {Check.Show(d)} (format D) doesn't parse back: {(ok ? back : "failure")}");
        }

        string? name = Enum.GetName(type, value);
        Check.Equal(name is not null, Enum.IsDefined(type, value), $"{type.Name} {d}: GetName {Check.Show(name)} vs IsDefined");
        if (name is not null)
        {
            Check.Equal(name, g, $"{type.Name} {d}: GetName vs ToString");
        }

        Check.Equal(Enum.GetNames(type).Length, Enum.GetValues(type).Length, $"{type.Name}: GetNames vs GetValues");
        Check.Equal(Enum.GetValues(type).Length, Enum.GetValuesAsUnderlyingType(type).Length, $"{type.Name}: GetValues vs GetValuesAsUnderlyingType");
    }
}
