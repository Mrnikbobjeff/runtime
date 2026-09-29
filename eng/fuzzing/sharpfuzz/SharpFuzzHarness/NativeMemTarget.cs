#nullable disable warnings
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace SharpFuzzHarness;

/// <summary>
/// The native-memory helpers against a byte-array model, with the native side against guard pages
/// where possible: Marshal.Copy in every element type and direction with fuzzed offsets and lengths
/// (out-of-range requests must throw, never touch memory), Marshal.Read* / Write* at unaligned
/// offsets, NativeMemory Alloc / AllocZeroed / AlignedAlloc / Realloc / AlignedRealloc / Copy / Fill /
/// Clear (alignment and content preservation), Marshal.AllocHGlobal / ReAllocHGlobal / CoTaskMem,
/// GCHandle / GCHandle&lt;T&gt; / PinnedGCHandle&lt;T&gt; / WeakGCHandle&lt;T&gt; round trips and pinned
/// addresses, SecureString operations against a model and every SecureStringTo* conversion, BSTR
/// helpers, and HRESULT / exception mapping.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     operation; byte 1 flags
///   rest       operations (opcode + operands) or data
/// </remarks>
public static unsafe class NativeMemTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte op = input.Byte();
        byte flags = input.Byte();
        switch (op % 6)
        {
            case 0: Copies(ref input, flags); break;
            case 1: ReadsWrites(ref input, flags); break;
            case 2: Allocations(ref input, flags); break;
            case 3: Handles(ref input, flags); break;
            case 4: Secure(ref input, flags); break;
            default: Misc(ref input, flags); break;
        }
    }

    private static bool Rejected(Exception e) => e is ArgumentException or ArgumentOutOfRangeException;

    // ------------------------------------------------------------ Marshal.Copy

    private static void Copies(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        int size = input.Byte() + 1;
        byte[] model = new byte[size];
        input.Bytes(size).CopyTo(model);
        byte* native = Guarded.Allocate(size, atStart);
        model.CopyTo(new Span<byte>(native, size));
        var log = new StringBuilder();
        for (int step = 0; step < 24 && input.Remaining > 0; step++)
        {
            int kind = input.Byte() % 9;
            int elem = kind switch { 0 => 1, 1 => 2, 2 => 4, 3 => 8, 4 => 2, 5 => 4, 6 => 8, 7 => 8, _ => 1 };
            int count = (input.Byte() * 3) % (size / elem + 3);          // sometimes too many
            int start = input.Byte() % (count + 2);                       // index into the managed array
            int nativeOffset = (input.Byte() * 5) % (size + 2) - 1;       // sometimes -1 or past the end
            bool toNative = (input.Byte() & 1) != 0;
            int arrayLength = count + input.Byte() % 3;                   // sometimes exactly count, sometimes more
            log.Append($" {(toNative ? "to" : "from")}{elem}x{count}@{start}/{arrayLength}+{nativeOffset}");
            string what = $"Marshal.Copy over {size} native bytes:{log}";
            bool nativeOk = nativeOffset >= 0 && (long)nativeOffset + (long)count * elem <= size;
            bool managedOk = start >= 0 && count >= 0 && start + count <= arrayLength;
            if (!nativeOk)
            {
                continue; // Marshal.Copy can't know the native size; that would be our bug, not the runtime's
            }

            IntPtr p = (IntPtr)(native + nativeOffset);
            try
            {
                if (toNative)
                {
                    Array managed = MakeArray(kind, arrayLength, ref input);
                    CopyToNative(kind, managed, start, p, count);
                    Check.That(managedOk, $"{what}: to-native copy with start {start} + count {count} > length {arrayLength} didn't throw");
                    Bytes(managed).Slice(start * elem, count * elem).CopyTo(model.AsSpan(nativeOffset));
                }
                else
                {
                    Array managed = MakeArray(kind, arrayLength, ref input);
                    byte[] before = Bytes(managed).ToArray();
                    CopyToManaged(kind, p, managed, start, count);
                    Check.That(managedOk, $"{what}: to-managed copy with start {start} + count {count} > length {arrayLength} didn't throw");
                    model.AsSpan(nativeOffset, count * elem).CopyTo(before.AsSpan(start * elem));
                    Check.That(Bytes(managed).SequenceEqual(before), $"{what}: managed array differs from the model");
                }
            }
            catch (Exception e) when (Rejected(e))
            {
                Check.That(!managedOk, $"{what}: valid copy threw {e.GetType().Name}: {e.Message}");
            }

            Check.That(new ReadOnlySpan<byte>(native, size).SequenceEqual(model), $"{what}: native memory differs from the model");
        }
    }

    private static Array MakeArray(int kind, int length, ref FuzzInput input)
    {
        Array array = kind switch
        {
            0 => new byte[length], 1 => new short[length], 2 => new int[length], 3 => new long[length],
            4 => new char[length], 5 => new float[length], 6 => new double[length], 7 => new IntPtr[length], _ => new byte[length],
        };
        Span<byte> bytes = Bytes(array);
        input.Bytes(Math.Min(bytes.Length, 16)).CopyTo(bytes);
        return array;
    }

    private static Span<byte> Bytes(Array array) => array switch
    {
        byte[] a => a,
        short[] a => MemoryMarshal.AsBytes(a.AsSpan()),
        int[] a => MemoryMarshal.AsBytes(a.AsSpan()),
        long[] a => MemoryMarshal.AsBytes(a.AsSpan()),
        char[] a => MemoryMarshal.AsBytes(a.AsSpan()),
        float[] a => MemoryMarshal.AsBytes(a.AsSpan()),
        double[] a => MemoryMarshal.AsBytes(a.AsSpan()),
        IntPtr[] a => MemoryMarshal.AsBytes(a.AsSpan()),
        _ => throw new ArgumentException(array.GetType().Name),
    };

    private static void CopyToNative(int kind, Array source, int start, IntPtr destination, int count)
    {
        switch (kind)
        {
            case 0: Marshal.Copy((byte[])source, start, destination, count); break;
            case 1: Marshal.Copy((short[])source, start, destination, count); break;
            case 2: Marshal.Copy((int[])source, start, destination, count); break;
            case 3: Marshal.Copy((long[])source, start, destination, count); break;
            case 4: Marshal.Copy((char[])source, start, destination, count); break;
            case 5: Marshal.Copy((float[])source, start, destination, count); break;
            case 6: Marshal.Copy((double[])source, start, destination, count); break;
            case 7: Marshal.Copy((IntPtr[])source, start, destination, count); break;
            default: Marshal.Copy((byte[])source, start, destination, count); break;
        }
    }

    private static void CopyToManaged(int kind, IntPtr source, Array destination, int start, int count)
    {
        switch (kind)
        {
            case 0: Marshal.Copy(source, (byte[])destination, start, count); break;
            case 1: Marshal.Copy(source, (short[])destination, start, count); break;
            case 2: Marshal.Copy(source, (int[])destination, start, count); break;
            case 3: Marshal.Copy(source, (long[])destination, start, count); break;
            case 4: Marshal.Copy(source, (char[])destination, start, count); break;
            case 5: Marshal.Copy(source, (float[])destination, start, count); break;
            case 6: Marshal.Copy(source, (double[])destination, start, count); break;
            case 7: Marshal.Copy(source, (IntPtr[])destination, start, count); break;
            default: Marshal.Copy(source, (byte[])destination, start, count); break;
        }
    }

    // ------------------------------------------------------------ Marshal.Read* / Write*

    private static void ReadsWrites(ref FuzzInput input, byte flags)
    {
        bool atStart = (flags & 1) != 0;
        int size = input.Byte() + 8;
        byte[] model = new byte[size];
        input.Bytes(size).CopyTo(model);
        byte* native = Guarded.Allocate(size, atStart);
        model.CopyTo(new Span<byte>(native, size));
        IntPtr p = (IntPtr)native;
        for (int step = 0; step < 32 && input.Remaining > 0; step++)
        {
            int kind = input.Byte() % 5;
            int width = kind switch { 0 => 1, 1 => 2, 2 => 4, 3 => 8, _ => 8 };
            int offset = input.Byte() % (size - width + 1);
            long value = (long)input.Int32() << 32 | (uint)input.Int32();
            string what = $"Marshal {(kind == 4 ? "IntPtr" : $"{width * 8}-bit")} at offset {offset} of {size}";
            long expected = kind switch
            {
                0 => model[offset],
                1 => BitConverter.ToInt16(model, offset),
                2 => BitConverter.ToInt32(model, offset),
                _ => BitConverter.ToInt64(model, offset),
            };
            long actual = kind switch
            {
                0 => Marshal.ReadByte(p, offset),
                1 => Marshal.ReadInt16(p, offset),
                2 => Marshal.ReadInt32(p, offset),
                3 => Marshal.ReadInt64(p, offset),
                _ => Marshal.ReadIntPtr(p, offset),
            };
            Check.Equal(expected, actual, $"read {what}");
            long viaPointer = kind switch { 0 => Marshal.ReadByte(p + offset), 1 => Marshal.ReadInt16(p + offset), 2 => Marshal.ReadInt32(p + offset), 3 => Marshal.ReadInt64(p + offset), _ => Marshal.ReadIntPtr(p + offset) };
            Check.Equal(expected, viaPointer, $"read (pointer + offset) {what}");
            switch (kind)
            {
                case 0: Marshal.WriteByte(p, offset, (byte)value); model[offset] = (byte)value; break;
                case 1: Marshal.WriteInt16(p, offset, (short)value); BitConverter.TryWriteBytes(model.AsSpan(offset), (short)value); break;
                case 2: Marshal.WriteInt32(p, offset, (int)value); BitConverter.TryWriteBytes(model.AsSpan(offset), (int)value); break;
                case 3: Marshal.WriteInt64(p, offset, value); BitConverter.TryWriteBytes(model.AsSpan(offset), value); break;
                default: Marshal.WriteIntPtr(p, offset, (IntPtr)value); BitConverter.TryWriteBytes(model.AsSpan(offset), value); break;
            }

            Check.That(new ReadOnlySpan<byte>(native, size).SequenceEqual(model), $"native memory differs from the model after write {what}");
        }

        // Marshal.Copy of the whole block into a fresh array and back through a CoTaskMem block.
        byte[] copy = new byte[size];
        Marshal.Copy(p, copy, 0, size);
        Check.That(copy.SequenceEqual(model), "Marshal.Copy whole block");
        IntPtr block = Marshal.AllocCoTaskMem(size);
        try
        {
            Marshal.Copy(copy, 0, block, size);
            Check.That(new ReadOnlySpan<byte>((void*)block, size).SequenceEqual(model), "CoTaskMem block contents");
            block = Marshal.ReAllocCoTaskMem(block, size * 2);
            Check.That(new ReadOnlySpan<byte>((void*)block, size).SequenceEqual(model), "CoTaskMem block contents after ReAlloc");
        }
        finally
        {
            Marshal.FreeCoTaskMem(block);
        }
    }

    // ------------------------------------------------------------ NativeMemory

    private static void Allocations(ref FuzzInput input, byte flags)
    {
        nuint size = (nuint)(input.UInt16() % 5000);
        int alignShift = input.Byte() % 14;
        nuint alignment = (nuint)1 << alignShift;
        nuint newSize = (nuint)(input.UInt16() % 5000);
        byte fill = input.Byte();
        string what = $"NativeMemory size {size} alignment {alignment} newSize {newSize}";

        void* p = NativeMemory.Alloc(size);
        Check.That(p != null, $"{what}: Alloc returned null");
        NativeMemory.Fill(p, size, fill);
        for (nuint i = 0; i < size; i++)
        {
            Check.That(((byte*)p)[i] == fill, $"{what}: Fill byte {i}");
        }

        p = NativeMemory.Realloc(p, newSize);
        Check.That(p != null, $"{what}: Realloc returned null");
        for (nuint i = 0; i < Math.Min(size, newSize); i++)
        {
            Check.That(((byte*)p)[i] == fill, $"{what}: byte {i} lost by Realloc");
        }

        NativeMemory.Clear(p, newSize);
        for (nuint i = 0; i < newSize; i++)
        {
            Check.That(((byte*)p)[i] == 0, $"{what}: Clear byte {i}");
        }

        NativeMemory.Free(p);

        void* z = NativeMemory.AllocZeroed(size);
        Check.That(z != null, $"{what}: AllocZeroed returned null");
        for (nuint i = 0; i < size; i++)
        {
            Check.That(((byte*)z)[i] == 0, $"{what}: AllocZeroed byte {i}");
        }

        NativeMemory.Free(z);

        // Element-count overloads must reject overflow with OutOfMemoryException.
        try
        {
            void* huge = NativeMemory.AllocZeroed((nuint)1 << 40, (nuint)1 << 40);
            NativeMemory.Free(huge);
            Check.That(false, "AllocZeroed(2^40, 2^40) succeeded");
        }
        catch (OutOfMemoryException)
        {
        }

        void* a = NativeMemory.AlignedAlloc(size, alignment);
        Check.That(a != null && ((nuint)a & (alignment - 1)) == 0, $"{what}: AlignedAlloc alignment");
        NativeMemory.Fill(a, size, fill);
        a = NativeMemory.AlignedRealloc(a, newSize, alignment);
        Check.That(a != null && ((nuint)a & (alignment - 1)) == 0, $"{what}: AlignedRealloc alignment");
        for (nuint i = 0; i < Math.Min(size, newSize); i++)
        {
            Check.That(((byte*)a)[i] == fill, $"{what}: byte {i} lost by AlignedRealloc");
        }

        NativeMemory.AlignedFree(a);
        try
        {
            void* bad = NativeMemory.AlignedAlloc(size, alignment + 1);
            NativeMemory.AlignedFree(bad);
            Check.That(alignment + 1 == 2, $"{what}: AlignedAlloc accepted a non-power-of-two alignment {alignment + 1}");
        }
        catch (ArgumentException)
        {
            Check.That(alignment + 1 != 2, $"{what}: AlignedAlloc rejected alignment 2");
        }

        // Copies with overlap behave like memmove.
        byte* src = (byte*)NativeMemory.Alloc(64);
        for (int i = 0; i < 64; i++)
        {
            src[i] = (byte)i;
        }

        int from = input.Byte() % 32, to = input.Byte() % 32, len = input.Byte() % 33;
        byte[] model = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
        Buffer.BlockCopy(model, from, model, to, len);
        NativeMemory.Copy(src + from, src + to, (nuint)len);
        Check.That(new ReadOnlySpan<byte>(src, 64).SequenceEqual(model), $"NativeMemory.Copy overlap from {from} to {to} length {len}");
        NativeMemory.Free(src);

        // Marshal.AllocHGlobal / ReAllocHGlobal preserve contents, and the negative size is rejected.
        IntPtr h = Marshal.AllocHGlobal((int)size);
        new Span<byte>((void*)h, (int)size).Fill(fill);
        h = Marshal.ReAllocHGlobal(h, (IntPtr)(long)newSize);
        for (nuint i = 0; i < Math.Min(size, newSize); i++)
        {
            Check.That(((byte*)h)[i] == fill, $"{what}: byte {i} lost by ReAllocHGlobal");
        }

        Marshal.FreeHGlobal(h);
        try
        {
            Marshal.FreeHGlobal(Marshal.AllocHGlobal(-1));
            Check.That(false, "AllocHGlobal(-1) succeeded");
        }
        catch (OutOfMemoryException)
        {
        }
    }

    // ------------------------------------------------------------ GCHandle

    private static void Handles(ref FuzzInput input, byte flags)
    {
        int length = input.Byte() + 1;
        byte[] array = new byte[length];
        input.Bytes(length).CopyTo(array);
        var target = new StrongBox<long>((long)input.Int32() << 32 | (uint)input.Int32());
        // Pinned: the address is the first element, and the classic and generic handles agree.
        GCHandle pinned = GCHandle.Alloc(array, GCHandleType.Pinned);
        try
        {
            IntPtr address = pinned.AddrOfPinnedObject();
            fixed (byte* p = array)
            {
                Check.That(address == (IntPtr)p, "AddrOfPinnedObject differs from fixed");
            }

            Check.That(Marshal.UnsafeAddrOfPinnedArrayElement(array, length - 1) == address + (length - 1), "UnsafeAddrOfPinnedArrayElement");
            Check.That(Marshal.UnsafeAddrOfPinnedArrayElement<byte>(array, 0) == address, "UnsafeAddrOfPinnedArrayElement<T>");
            Check.That(GCHandle.FromIntPtr(GCHandle.ToIntPtr(pinned)).Target == array, "GCHandle round trip through IntPtr");
            Check.That(pinned.IsAllocated && ReferenceEquals(pinned.Target, array), "pinned GCHandle target");
            using var pinnedGeneric = new PinnedGCHandle<byte[]>(array);
            Check.That(ReferenceEquals(pinnedGeneric.Target, array), "PinnedGCHandle<T>.Target");
            Check.That((IntPtr)pinnedGeneric.GetAddressOfObjectData() < address && (IntPtr)pinnedGeneric.GetAddressOfObjectData() >= address - 16, "PinnedGCHandle<byte[]>.GetAddressOfObjectData is before the elements");
            Check.That(PinnedGCHandle<byte[]>.FromIntPtr(PinnedGCHandle<byte[]>.ToIntPtr(pinnedGeneric)).Target == array, "PinnedGCHandle<T> round trip through IntPtr");
        }
        finally
        {
            pinned.Free();
        }

        Check.That(!pinned.IsAllocated, "freed handle still allocated");
        try
        {
            pinned.Free();
            Check.That(false, "double Free succeeded");
        }
        catch (InvalidOperationException)
        {
        }

        // Normal / weak / generic handles.
        using (var strong = new GCHandle<StrongBox<long>>(target))
        {
            Check.That(ReferenceEquals(strong.Target, target), "GCHandle<T>.Target");
            Check.That(GCHandle<StrongBox<long>>.FromIntPtr(GCHandle<StrongBox<long>>.ToIntPtr(strong)).Target == target, "GCHandle<T> round trip through IntPtr");
        }

        using (var weak = new WeakGCHandle<StrongBox<long>>(target))
        {
            Check.That(weak.TryGetTarget(out StrongBox<long> t) && ReferenceEquals(t, target), "WeakGCHandle<T>.TryGetTarget");
            weak.SetTarget(null);
            Check.That(!weak.TryGetTarget(out _), "WeakGCHandle<T> after SetTarget(null)");
        }

        GCHandle weakClassic = GCHandle.Alloc(target, GCHandleType.Weak);
        Check.That(ReferenceEquals(weakClassic.Target, target), "weak GCHandle target");
        weakClassic.Target = array;
        Check.That(ReferenceEquals(weakClassic.Target, array), "weak GCHandle retarget");
        weakClassic.Free();
        // A normal handle keeps an object alive through a full GC.
        var handle = GCHandle.Alloc(new StrongBox<int>(length));
        GC.Collect();
        Check.Equal(length, ((StrongBox<int>)handle.Target).Value, "normal GCHandle keeps the target alive");
        handle.Free();
        // Pinning a non-blittable object is rejected.
        try
        {
            GCHandle bad = GCHandle.Alloc(new string[1], GCHandleType.Pinned);
            bad.Free();
            Check.That(false, "pinned a string[]");
        }
        catch (ArgumentException)
        {
        }
    }

    // ------------------------------------------------------------ SecureString

    private static void Secure(ref FuzzInput input, byte flags)
    {
        var model = new List<char>();
        var secure = new SecureString();
        bool readOnly = false;
        var log = new StringBuilder();
        for (int step = 0; step < 48 && input.Remaining > 0; step++)
        {
            int op = input.Byte() % 8;
            char c = (char)input.UInt16();
            int index = input.Byte();
            string what = $"SecureString ops:{log} {op}({Check.Escape(c.ToString())},{index})";
            try
            {
                switch (op)
                {
                    case 0:
                    case 1:
                        secure.AppendChar(c);
                        Check.That(!readOnly, $"{what}: AppendChar on a read-only string");
                        model.Add(c);
                        break;
                    case 2:
                        secure.InsertAt(index, c);
                        Check.That(!readOnly && index <= model.Count, $"{what}: InsertAt accepted index {index} of {model.Count}");
                        model.Insert(index, c);
                        break;
                    case 3:
                        secure.RemoveAt(index);
                        Check.That(!readOnly && index < model.Count, $"{what}: RemoveAt accepted index {index} of {model.Count}");
                        model.RemoveAt(index);
                        break;
                    case 4:
                        secure.SetAt(index, c);
                        Check.That(!readOnly && index < model.Count, $"{what}: SetAt accepted index {index} of {model.Count}");
                        model[index] = c;
                        break;
                    case 5:
                        secure.Clear();
                        Check.That(!readOnly, $"{what}: Clear on a read-only string");
                        model.Clear();
                        break;
                    case 6:
                        if ((index & 1) != 0)
                        {
                            secure.MakeReadOnly();
                            readOnly = true;
                        }

                        Check.Equal(readOnly, secure.IsReadOnly(), $"{what}: IsReadOnly");
                        break;
                    default:
                        SecureString copy = secure.Copy();
                        Check.That(!copy.IsReadOnly() && copy.Length == model.Count, $"{what}: Copy");
                        copy.Dispose();
                        break;
                }
            }
            catch (InvalidOperationException)
            {
                Check.That(readOnly, $"{what}: InvalidOperationException on a writable string");
            }
            catch (ArgumentOutOfRangeException)
            {
                Check.That(readOnly || op == 2 && index > model.Count || op is 3 or 4 && index >= model.Count, $"{what}: ArgumentOutOfRangeException for a valid index");
            }

            log.Append($" {op}");
            Check.Equal(model.Count, secure.Length, $"{what}: Length");
        }

        string expected = new string(model.ToArray());
        Check.Equal(expected, Marshal.PtrToStringUni(Convert(secure, 0, out IntPtr h0), model.Count), "SecureStringToGlobalAllocUnicode"); Marshal.ZeroFreeGlobalAllocUnicode(h0);
        Check.Equal(expected, Marshal.PtrToStringUni(Convert(secure, 1, out IntPtr h1), model.Count), "SecureStringToCoTaskMemUnicode"); Marshal.ZeroFreeCoTaskMemUnicode(h1);
        Check.Equal(expected, Marshal.PtrToStringBSTR(Convert(secure, 2, out IntPtr h2)), "SecureStringToBSTR"); Marshal.ZeroFreeBSTR(h2);
        // ANSI is UTF-8 on Unix; the conversion stops at the first NUL like a C string would.
        string utf8Expected = Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(expected));
        int nul = utf8Expected.IndexOf('\0');
        string cExpected = nul >= 0 ? utf8Expected.Substring(0, nul) : utf8Expected;
        Check.Equal(cExpected, Marshal.PtrToStringAnsi(Convert(secure, 3, out IntPtr h3)), "SecureStringToGlobalAllocAnsi"); Marshal.ZeroFreeGlobalAllocAnsi(h3);
        Check.Equal(cExpected, Marshal.PtrToStringAnsi(Convert(secure, 4, out IntPtr h4)), "SecureStringToCoTaskMemAnsi"); Marshal.ZeroFreeCoTaskMemAnsi(h4);
        // From a char pointer.
        fixed (char* p = expected)
        {
            using var fromPointer = new SecureString(p, expected.Length);
            Check.Equal(expected.Length, fromPointer.Length, "SecureString(char*, length)");
            IntPtr b = Marshal.SecureStringToBSTR(fromPointer);
            Check.Equal(expected, Marshal.PtrToStringBSTR(b), "SecureString(char*, length) contents");
            Marshal.ZeroFreeBSTR(b);
        }

        secure.Dispose();
        try
        {
            secure.AppendChar('x');
            Check.That(false, "AppendChar on a disposed SecureString succeeded");
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private static IntPtr Convert(SecureString s, int kind, out IntPtr handle) => handle = kind switch
    {
        0 => Marshal.SecureStringToGlobalAllocUnicode(s),
        1 => Marshal.SecureStringToCoTaskMemUnicode(s),
        2 => Marshal.SecureStringToBSTR(s),
        3 => Marshal.SecureStringToGlobalAllocAnsi(s),
        _ => Marshal.SecureStringToCoTaskMemAnsi(s),
    };

    // ------------------------------------------------------------ BSTR, HRESULTs, sizes

    private static void Misc(ref FuzzInput input, byte flags)
    {
        int hr = input.Int32();
        Exception e = Marshal.GetExceptionForHR(hr);
        Check.That(hr >= 0 ? e is null : e is not null && e.HResult == hr, $"GetExceptionForHR(0x{hr:X8}) gave {e?.GetType().Name} with HResult 0x{e?.HResult:X8}");
        if (e is not null)
        {
            Check.Equal(hr, Marshal.GetHRForException(e), $"GetHRForException(GetExceptionForHR(0x{hr:X8}))");
            try
            {
                Marshal.ThrowExceptionForHR(hr);
                Check.That(false, $"ThrowExceptionForHR(0x{hr:X8}) didn't throw");
            }
            catch (Exception thrown) when (thrown is not ConsistencyException)
            {
                Check.Equal(e.GetType(), thrown.GetType(), $"ThrowExceptionForHR(0x{hr:X8}) type");
            }
        }
        else
        {
            Marshal.ThrowExceptionForHR(hr);
        }

        Check.Equal(hr, Marshal.GetHRForException(new ExternalException("x", hr)), "GetHRForException(ExternalException)");

        // BSTR with embedded NULs and the raw chars of the input.
        byte[] raw = input.Rest().ToArray();
        string s = new string(MemoryMarshal.Cast<byte, char>(raw.AsSpan(0, raw.Length & ~1)));
        IntPtr b = Marshal.StringToBSTR(s);
        Check.Equal(s, Marshal.PtrToStringBSTR(b), $"StringToBSTR / PtrToStringBSTR of {Check.Show(s)}");
        Check.Equal(s.Length * 2, Marshal.ReadInt32(b, -4), "BSTR byte length");
        IntPtr b2 = Marshal.StringToBSTR(s);
        Check.Equal(s, Marshal.PtrToStringBSTR(b2), "second BSTR");
        Marshal.FreeBSTR(b);
        Marshal.FreeBSTR(b2);
        // Sizes of boxed primitives.
        Check.Equal(4, Marshal.SizeOf((object)1), "SizeOf(boxed int)");
        Check.Equal(4, Marshal.SizeOf<bool>(), "SizeOf<bool>");
        Check.Equal(1, Marshal.SizeOf<char>(), "SizeOf<char>");
        Check.Equal(16, Marshal.SizeOf<decimal>(), "SizeOf<decimal>");
        Check.Equal(16, Marshal.SizeOf<Guid>(), "SizeOf<Guid>");
        Check.That(!Marshal.IsComObject(s), "IsComObject(string)");
    }
}
