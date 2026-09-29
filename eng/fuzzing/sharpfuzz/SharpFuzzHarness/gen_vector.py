# Generates SharpFuzzHarness/VectorOpsTarget.cs: the same operations through Vector128 / 256 / 512 and
# Vector<T>, against a scalar model.
import os
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'VectorOpsTarget.cs')


def fp(fn):
    # float / double only overloads, from a generic context
    return (f'(typeof(T) == typeof(float) ? V.{fn}(x.As<T, float>()).As<float, T>() : V.{fn}(x.As<T, double>()).As<double, T>())')


FMA = ('(typeof(T) == typeof(float) ? V.FusedMultiplyAdd(x.As<T, float>(), y.As<T, float>(), z.As<T, float>()).As<float, T>()'
       ' : V.FusedMultiplyAdd(x.As<T, double>(), y.As<T, double>(), z.As<T, double>()).As<double, T>())')

# (name, vector expression, kinds, exact bits)
OPS = [
    ('Add', 'V.Add(x, y)', 'all', False),
    ('Subtract', 'V.Subtract(x, y)', 'all', False),
    ('Multiply', 'V.Multiply(x, y)', 'all', False),
    ('MultiplyScalar', 'V.Multiply(x, s)', 'all', False),
    ('Min', 'V.Min(x, y)', 'all', False),
    ('Max', 'V.Max(x, y)', 'all', False),
    ('MinNumber', 'V.MinNumber(x, y)', 'all', False),
    ('MaxNumber', 'V.MaxNumber(x, y)', 'all', False),
    ('MaxMagnitude', 'V.MaxMagnitude(x, y)', 'all', False),
    ('Clamp', 'V.Clamp(x, V.Min(y, z), V.Max(y, z))', 'all', False),
    ('Abs', 'V.Abs(x)', 'all', False),
    ('Negate', 'V.Negate(x)', 'all', False),
    ('Equals', 'V.Equals(x, y)', 'all', True),
    ('LessThan', 'V.LessThan(x, y)', 'all', True),
    ('GreaterThanOrEqual', 'V.GreaterThanOrEqual(x, y)', 'all', True),
    ('ConditionalSelect', 'V.ConditionalSelect(m, x, y)', 'all', True),
    ('And', 'V.BitwiseAnd(x, y)', 'all', True),
    ('Or', 'V.BitwiseOr(x, y)', 'all', True),
    ('Xor', 'V.Xor(x, y)', 'all', True),
    ('AndNot', 'V.AndNot(x, y)', 'all', True),
    ('OnesComplement', 'V.OnesComplement(x)', 'all', True),
    ('ShiftLeft', '(x << n)', 'int', True),
    ('ShiftRight', '(x >> n)', 'int', True),
    ('ShiftRightLogical', '(x >>> n)', 'int', True),
    ('CopySign', 'V.CopySign(x, y)', 'signed', False),
    ('Sqrt', fp('SQRT'), 'fp', False),
    ('Floor', fp('Floor'), 'fp', False),
    ('Ceiling', fp('Ceiling'), 'fp', False),
    ('Round', fp('Round'), 'fp', False),
    ('Truncate', fp('Truncate'), 'fp', False),
    ('FusedMultiplyAdd', FMA, 'fp', False),
    ('IsNaN', 'V.IsNaN(x)', 'all', True),
    ('IsNegative', 'V.IsNegative(x)', 'all', True),
    ('IsZero', 'V.IsZero(x)', 'all', True),
]

WIDTHS = [
    ('128', 'Vector128', 'Vector128<T>', 'Vector128<T>.Count', 'Sqrt'),
    ('256', 'Vector256', 'Vector256<T>', 'Vector256<T>.Count', 'Sqrt'),
    ('512', 'Vector512', 'Vector512<T>', 'Vector512<T>.Count', 'Sqrt'),
    ('Vec', 'Vector', 'Vector<T>', 'Vector<T>.Count', 'SquareRoot'),
]


def width_block(tag, cls, vt, count, sqrt):
    lines = []
    lines.append(f'    private static void Run{tag}<T>(int op, Span<T> a, Span<T> b, Span<T> c, Span<T> mask, T s, int n, Span<T> result)')
    lines.append('        where T : unmanaged, INumber<T>, IBitwiseOperators<T, T, T>')
    lines.append('    {')
    lines.append(f'        int count = {count};')
    lines.append('        for (int i = 0; i + count <= a.Length; i += count)')
    lines.append('        {')
    for v, arr in (('x', 'a'), ('y', 'b'), ('z', 'c'), ('m', 'mask')):
        lines.append(f'            {vt} {v} = {cls}.LoadUnsafe(ref MemoryMarshal.GetReference({arr}), (nuint)i);')
    lines.append(f'            {vt} r = op switch')
    lines.append('            {')
    for i, (name, expr, kinds, exact) in enumerate(OPS):
        e = expr.replace('SQRT', sqrt).replace('V.', cls + '.')
        lines.append(f'                {i} => {e},')
    lines.append('                _ => x,')
    lines.append('            };')
    lines.append('            r.StoreUnsafe(ref MemoryMarshal.GetReference(result), (nuint)i);')
    lines.append('        }')
    lines.append('    }')
    return '\n'.join(lines)


ops_meta = '\n'.join(f'        ("{name}", "{kinds}", {"true" if exact else "false"}),' for name, expr, kinds, exact in OPS)
model_cases = '\n'.join(f'                {i} => Model{name}(x, y, z, m, s, n),' for i, (name, expr, kinds, exact) in enumerate(OPS))
TC = 'where T : unmanaged, INumber<T>, IBitwiseOperators<T, T, T>'

models = {
    'Add': 'unchecked(x + y)',
    'Subtract': 'unchecked(x - y)',
    'Multiply': 'unchecked(x * y)',
    'MultiplyScalar': 'unchecked(x * s)',
    'Min': 'T.Min(x, y)',
    'Max': 'T.Max(x, y)',
    'MinNumber': 'T.MinNumber(x, y)',
    'MaxNumber': 'T.MaxNumber(x, y)',
    'MaxMagnitude': 'T.MaxMagnitude(x, y)',
    'Clamp': 'T.Min(T.Max(x, T.Min(y, z)), T.Max(y, z))',
    'Abs': 'T.IsNegative(x) ? unchecked(T.Zero - x) : x',
    'Negate': 'unchecked(-x)',
    'Equals': 'AllBits<T>(x == y)',
    'LessThan': 'AllBits<T>(x < y)',
    'GreaterThanOrEqual': 'AllBits<T>(x >= y)',
    'ConditionalSelect': '(m & x) | (~m & y)',
    'And': 'x & y',
    'Or': 'x | y',
    'Xor': 'x ^ y',
    'AndNot': 'x & ~y',
    'OnesComplement': '~x',
    'ShiftLeft': 'Shift(x, n, 0)',
    'ShiftRight': 'Shift(x, n, 1)',
    'ShiftRightLogical': 'Shift(x, n, 2)',
    'CopySign': 'IsFloat<T>() ? T.CopySign(x, y) : (T.IsNegative(x) == T.IsNegative(y) ? x : unchecked(T.Zero - x))',
    'Sqrt': 'Fp(x, y, z, 0)',
    'Floor': 'Fp(x, y, z, 1)',
    'Ceiling': 'Fp(x, y, z, 2)',
    'Round': 'Fp(x, y, z, 3)',
    'Truncate': 'Fp(x, y, z, 4)',
    'FusedMultiplyAdd': 'Fp(x, y, z, 5)',
    'IsNaN': 'AllBits<T>(T.IsNaN(x))',
    'IsNegative': 'AllBits<T>(T.IsNegative(x))',
    'IsZero': 'AllBits<T>(T.IsZero(x))',
}
model_methods = '\n'.join(f'    private static T Model{name}<T>(T x, T y, T z, T m, T s, int n) {TC} => {models[name]};' for name, _, _, _ in OPS)

body = f'''#nullable disable warnings
// <auto-generated> by gen_vector.py: the same operations through Vector128 / 256 / 512 and Vector<T>.
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace SharpFuzzHarness;

/// <summary>
/// The System.Runtime.Intrinsics vector APIs (Vector128 / 256 / 512 and Vector&lt;T&gt;) for every
/// primitive element type, against a scalar model built on generic math. Vector widths the hardware
/// doesn't accelerate (Vector512 without AVX-512, which the secondary instances disable) run the
/// software fallbacks built on Unsafe; accelerated ones go through the JIT's intrinsics. Operands are
/// loaded with LoadUnsafe from, and results stored with StoreUnsafe to, guarded memory
/// (see <see cref="Guarded"/>) that ends right after the last vector.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     element type; byte 1 operation; byte 2 shift count
///   rest       256 bytes: operands a, b, c and a mask, 64 bytes each (zero-filled)
/// </remarks>
public static class VectorOpsTarget
{{
    private static readonly (string Name, string Kinds, bool Exact)[] s_ops =
    [
{ops_meta}
    ];

    public static void Run(ReadOnlySpan<byte> data)
    {{
        var input = new FuzzInput(data);
        byte type = input.Byte();
        byte op = input.Byte();
        byte shift = input.Byte();
        Span<byte> raw = stackalloc byte[256];
        raw.Clear();
        ReadOnlySpan<byte> rest = input.Rest();
        rest[..Math.Min(rest.Length, 256)].CopyTo(raw);
        switch (type % 10)
        {{
            case 0: Test<sbyte>(op, shift, raw, "int", true); break;
            case 1: Test<byte>(op, shift, raw, "int", false); break;
            case 2: Test<short>(op, shift, raw, "int", true); break;
            case 3: Test<ushort>(op, shift, raw, "int", false); break;
            case 4: Test<int>(op, shift, raw, "int", true); break;
            case 5: Test<uint>(op, shift, raw, "int", false); break;
            case 6: Test<long>(op, shift, raw, "int", true); break;
            case 7: Test<ulong>(op, shift, raw, "int", false); break;
            case 8: Test<float>(op, shift, raw, "fp", true); break;
            default: Test<double>(op, shift, raw, "fp", true); break;
        }}
    }}

    private static bool IsFloat<T>() => typeof(T) == typeof(float) || typeof(T) == typeof(double);

    private static void Test<T>(byte op, byte shift, ReadOnlySpan<byte> raw, string kind, bool signed)
        {TC}
    {{
        int index = op % s_ops.Length;
        (string name, string kinds, bool exact) = s_ops[index];
        if (kinds == "int" && kind != "int" || kinds == "fp" && kind != "fp" || kinds == "signed" && !signed)
        {{
            return;
        }}

        int elements = 64 / Unsafe.SizeOf<T>();
        T[] a = MemoryMarshal.Cast<byte, T>(raw[..64]).ToArray();
        T[] b = MemoryMarshal.Cast<byte, T>(raw[64..128]).ToArray();
        T[] c = MemoryMarshal.Cast<byte, T>(raw[128..192]).ToArray();
        T[] mask = MemoryMarshal.Cast<byte, T>(raw[192..256]).ToArray();
        T s = b[^1];
        int n = shift;
        T[] expected = new T[elements];
        for (int i = 0; i < elements; i++)
        {{
            T x = a[i], y = b[i], z = c[i], m = mask[i];
            expected[i] = index switch
            {{
{model_cases}
                _ => x,
            }};
        }}

        string what = $"{{name}}<{{typeof(T).Name}}> shift {{n}}";
        foreach (string width in (string[])["128", "256", "512", "Vec"])
        {{
            // Operands and result in guarded memory that ends right after the last element.
            Span<T> ga = Guarded.Copy<T>(a, atStart: false), gb = Guarded.Copy<T>(b, false), gc = Guarded.Copy<T>(c, false), gm = Guarded.Copy<T>(mask, false);
            Span<T> result = Guarded.Copy<T>(new T[elements], false);
            switch (width)
            {{
                case "128": Run128(index, ga, gb, gc, gm, s, n, result); break;
                case "256": Run256(index, ga, gb, gc, gm, s, n, result); break;
                case "512": Run512(index, ga, gb, gc, gm, s, n, result); break;
                default: RunVec(index, ga, gb, gc, gm, s, n, result); break;
            }}

            int covered = width == "Vec" ? elements / Vector<T>.Count * Vector<T>.Count : elements;
            for (int i = 0; i < covered; i++)
            {{
                if (!(exact ? Bits(expected[i]) == Bits(result[i]) : Same(expected[i], result[i])))
                {{
                    Check.That(false, $"Vector{{width}} {{what}}: element {{i}} is {{result[i]}} (0x{{Bits(result[i])}}), expected {{expected[i]}} (0x{{Bits(expected[i])}}); a {{a[i]}} (0x{{Bits(a[i])}}) b {{b[i]}} (0x{{Bits(b[i])}}) c {{c[i]}} m 0x{{Bits(mask[i])}}");
                }}
            }}
        }}
    }}

    private static string Bits<T>(T value) where T : unmanaged
    {{
        Span<byte> bytes = stackalloc byte[Unsafe.SizeOf<T>()];
        MemoryMarshal.Write(bytes, in value);
        bytes.Reverse();
        return Convert.ToHexString(bytes);
    }}

    // Bitwise equality, except that any NaN matches any NaN (payloads and signs of NaN results aren't specified).
    private static bool Same<T>(T x, T y) where T : unmanaged, INumber<T> =>
        Bits(x) == Bits(y) || T.IsNaN(x) && T.IsNaN(y);

    private static T AllBits<T>(bool condition) {TC} =>
        condition ? ~T.Zero : T.Zero;

{model_methods}

    /// <summary>Shifts with the count masked to the element width (0 left, 1 right: arithmetic for signed types, 2 logical right).</summary>
    private static T Shift<T>(T x, int n, int kind) {TC}
    {{
        int bits = Unsafe.SizeOf<T>() * 8;
        n &= bits - 1;
        bool signedType = T.IsNegative(unchecked(T.Zero - T.One));
        ulong u = bits switch {{ 8 => Unsafe.As<T, byte>(ref x), 16 => Unsafe.As<T, ushort>(ref x), 32 => Unsafe.As<T, uint>(ref x), _ => Unsafe.As<T, ulong>(ref x) }};
        ulong mask = bits == 64 ? ulong.MaxValue : (1UL << bits) - 1;
        bool negative = (u >> (bits - 1) & 1) != 0;
        ulong r = kind switch
        {{
            0 => (u << n) & mask,
            1 when signedType && negative && n > 0 => (u >> n) | (mask & ~(mask >> n)),
            _ => u >> n,
        }};
        T result = default;
        switch (bits)
        {{
            case 8: Unsafe.As<T, byte>(ref result) = (byte)r; break;
            case 16: Unsafe.As<T, ushort>(ref result) = (ushort)r; break;
            case 32: Unsafe.As<T, uint>(ref result) = (uint)r; break;
            default: Unsafe.As<T, ulong>(ref result) = r; break;
        }}

        return result;
    }}

    private static T Fp<T>(T x, T y, T z, int kind) where T : unmanaged, INumber<T>
    {{
        if (typeof(T) == typeof(float))
        {{
            float a = (float)(object)x, b = (float)(object)y, c = (float)(object)z;
            float r = kind switch {{ 0 => MathF.Sqrt(a), 1 => MathF.Floor(a), 2 => MathF.Ceiling(a), 3 => MathF.Round(a), 4 => MathF.Truncate(a), _ => MathF.FusedMultiplyAdd(a, b, c) }};
            return (T)(object)r;
        }}

        double da = (double)(object)x, db = (double)(object)y, dc = (double)(object)z;
        double dr = kind switch {{ 0 => Math.Sqrt(da), 1 => Math.Floor(da), 2 => Math.Ceiling(da), 3 => Math.Round(da), 4 => Math.Truncate(da), _ => Math.FusedMultiplyAdd(da, db, dc) }};
        return (T)(object)dr;
    }}

{chr(10).join(width_block(*w) for w in WIDTHS)}
}}
'''

open(out, 'w', encoding='utf-8', newline='\n').write(body)
print('ok')
