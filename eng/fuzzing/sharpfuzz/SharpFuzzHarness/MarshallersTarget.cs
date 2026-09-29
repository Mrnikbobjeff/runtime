#nullable disable warnings
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SharpFuzzHarness;

/// <summary>
/// The public marshallers behind LibraryImport, called the way generated stubs call them, with the
/// caller-provided buffers placed against guard pages and sized from the input (the generated code
/// passes exactly BufferSize bytes; anything the marshaller writes past what it was given faults):
/// Utf8StringMarshaller / AnsiStringMarshaller / BStrStringMarshaller ManagedToUnmanagedIn,
/// Utf16StringMarshaller, ArrayMarshaller / PointerArrayMarshaller / SpanMarshaller /
/// ReadOnlySpanMarshaller (in and out shapes, element counts from the input), SafeHandleMarshaller
/// (in / out / ref state machines against SafeHandle reference counts), ComVariant Create / As /
/// CreateRaw round trips, and the exception marshallers.
/// </summary>
/// <remarks>
/// Input layout:
///   byte 0     operation; byte 1 flags; bytes 2-3 buffer size
///   rest       data
/// </remarks>
public static unsafe class MarshallersTarget
{
    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte op = input.Byte();
        byte flags = input.Byte();
        int bufferSize = input.UInt16();
        switch (op % 6)
        {
            case 0: Utf8(ref input, flags, bufferSize); break;
            case 1: Ansi(ref input, flags, bufferSize); break;
            case 2: Utf16AndBstr(ref input, flags, bufferSize); break;
            case 3: Arrays(ref input, flags, bufferSize); break;
            case 4: Handles(ref input, flags); break;
            default: Variants(ref input, flags); break;
        }
    }

    private static Span<byte> Buffer(int size, bool atStart) => new(Guarded.Allocate(size, atStart), size);

    /// <summary>Text from the input as the UTF-8 marshallers will produce it (lone surrogates become U+FFFD).</summary>
    private static string Text(ReadOnlySpan<byte> bytes) => Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(bytes)));

    private static void Utf8(ref FuzzInput input, byte flags, int bufferSize)
    {
        bool atStart = (flags & 1) != 0;
        string s = (flags & 2) != 0 ? null : Text(input.Rest());
        byte[] utf8 = s is null ? [] : Encoding.UTF8.GetBytes(s);
        int size = Math.Min(bufferSize, Utf8StringMarshaller.ManagedToUnmanagedIn.BufferSize + 64);
        Span<byte> buffer = Buffer(size, atStart);
        buffer.Fill(0xCC);
        string what = $"Utf8StringMarshaller.ManagedToUnmanagedIn of {Check.Show(s)} with a {size}-byte buffer";

        var marshaller = new Utf8StringMarshaller.ManagedToUnmanagedIn();
        marshaller.FromManaged(s, buffer);
        byte* p = marshaller.ToUnmanaged();
        try
        {
            if (s is null)
            {
                Check.That(p == null, $"{what}: null string gave a pointer");
                return;
            }

            Check.That(p != null, $"{what}: pointer is null");
            // Every byte of the UTF-8 plus the terminator, whether in the buffer or on the heap.
            var written = new ReadOnlySpan<byte>(p, utf8.Length + 1);
            Check.That(written.Slice(0, utf8.Length).SequenceEqual(utf8) && written[utf8.Length] == 0, $"{what}: bytes {Convert.ToHexString(written)} != {Convert.ToHexString(utf8)}+00");
            bool inBuffer = p >= (byte*)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer)) && p < (byte*)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer)) + size;
            Check.That(!inBuffer || utf8.Length + 1 <= size, $"{what}: used the buffer for {utf8.Length + 1} bytes");
            Check.That(inBuffer || utf8.Length + 1 > size || size == 0, $"{what}: heap allocated although the {utf8.Length + 1} bytes fit");
            string untilNul = s.IndexOf('\0') is var nulAt && nulAt >= 0 ? s.Substring(0, nulAt) : s;
            Check.Equal(untilNul, Utf8StringMarshaller.ConvertToManaged(p), $"{what}: ConvertToManaged");
            Check.Equal(untilNul, Marshal.PtrToStringUTF8((IntPtr)p), $"{what}: PtrToStringUTF8");
            if (s.Length > 0 && s.IndexOf('\0') < 0)
            {
                Check.Equal(utf8.Length, MemoryMarshal.CreateReadOnlySpanFromNullTerminated(p).Length, $"{what}: NUL-terminated length");
            }
        }
        finally
        {
            marshaller.Free();
        }

        // The static shape: ConvertToUnmanaged allocates; Free frees.
        byte* q = Utf8StringMarshaller.ConvertToUnmanaged(s);
        Check.Equal(s is null ? null : s.IndexOf('\0') is var nul2 && nul2 >= 0 ? s.Substring(0, nul2) : s, Utf8StringMarshaller.ConvertToManaged(q), $"Utf8StringMarshaller.ConvertToUnmanaged / ConvertToManaged of {Check.Show(s)}");
        Utf8StringMarshaller.Free(q);
    }

    private static void Ansi(ref FuzzInput input, byte flags, int bufferSize)
    {
        bool atStart = (flags & 1) != 0;
        string s = (flags & 2) != 0 ? null : Text(input.Rest());
        byte[] bytes = s is null ? [] : Encoding.UTF8.GetBytes(s); // ANSI is UTF-8 on Unix
        int size = Math.Min(bufferSize, AnsiStringMarshaller.ManagedToUnmanagedIn.BufferSize + 64);
        Span<byte> buffer = Buffer(size, atStart);
        buffer.Fill(0xCC);
        string what = $"AnsiStringMarshaller.ManagedToUnmanagedIn of {Check.Show(s)} with a {size}-byte buffer";

        var marshaller = new AnsiStringMarshaller.ManagedToUnmanagedIn();
        marshaller.FromManaged(s, buffer);
        byte* p = marshaller.ToUnmanaged();
        try
        {
            if (s is null)
            {
                Check.That(p == null, $"{what}: null string gave a pointer");
                return;
            }

            Check.That(p != null, $"{what}: pointer is null");
            var written = new ReadOnlySpan<byte>(p, bytes.Length + 1);
            Check.That(written.Slice(0, bytes.Length).SequenceEqual(bytes) && written[bytes.Length] == 0, $"{what}: bytes {Convert.ToHexString(written)} != {Convert.ToHexString(bytes)}+00");
            string untilNul = s.IndexOf('\0') is var nulAt && nulAt >= 0 ? s.Substring(0, nulAt) : s;
            Check.Equal(untilNul, AnsiStringMarshaller.ConvertToManaged(p), $"{what}: ConvertToManaged");
            Check.Equal(untilNul, Marshal.PtrToStringAnsi((IntPtr)p), $"{what}: PtrToStringAnsi");
        }
        finally
        {
            marshaller.Free();
        }

        byte* q = AnsiStringMarshaller.ConvertToUnmanaged(s);
        Check.Equal(s is null ? null : s.IndexOf('\0') is var nul2 && nul2 >= 0 ? s.Substring(0, nul2) : s, AnsiStringMarshaller.ConvertToManaged(q), $"AnsiStringMarshaller.ConvertToUnmanaged / ConvertToManaged of {Check.Show(s)}");
        AnsiStringMarshaller.Free(q);
    }

    private static void Utf16AndBstr(ref FuzzInput input, byte flags, int bufferSize)
    {
        bool atStart = (flags & 1) != 0;
        byte[] raw = input.Rest().ToArray();
        string s = (flags & 2) != 0 ? null : new string(MemoryMarshal.Cast<byte, char>(raw.AsSpan(0, raw.Length & ~1))); // any chars, lone surrogates included
        string what = $"UTF-16 marshallers of {Check.Show(s)}";

        // Utf16StringMarshaller: the pinnable reference is the string's first char; the unmanaged copy is a CoTaskMem copy.
        ref readonly char pin = ref Utf16StringMarshaller.GetPinnableReference(s);
        Check.That(s is null ? Unsafe.IsNullRef(in pin) : Unsafe.AreSame(in pin, in s.GetPinnableReference()), $"{what}: GetPinnableReference");
        ushort* u = Utf16StringMarshaller.ConvertToUnmanaged(s);
        try
        {
            if (s is null)
            {
                Check.That(u == null, $"{what}: null string gave a pointer");
            }
            else
            {
                Check.That(new ReadOnlySpan<char>(u, s.Length).SequenceEqual(s) && u[s.Length] == 0, $"{what}: Utf16StringMarshaller bytes");
                string back = Utf16StringMarshaller.ConvertToManaged(u);
                string expected = s.IndexOf('\0') is var nul && nul >= 0 ? s.Substring(0, nul) : s;
                Check.Equal(expected, back, $"{what}: Utf16StringMarshaller.ConvertToManaged");
            }
        }
        finally
        {
            Utf16StringMarshaller.Free(u);
        }

        // BStrStringMarshaller.ManagedToUnmanagedIn: a length-prefixed copy that keeps embedded NULs.
        int size = Math.Min(bufferSize, BStrStringMarshaller.ManagedToUnmanagedIn.BufferSize + 64);
        Span<byte> buffer = Buffer(size, atStart);
        buffer.Fill(0xCC);
        var marshaller = new BStrStringMarshaller.ManagedToUnmanagedIn();
        marshaller.FromManaged(s, buffer);
        ushort* b = marshaller.ToUnmanaged();
        try
        {
            if (s is null)
            {
                Check.That(b == null, $"{what}: BStr of null gave a pointer");
                return;
            }

            Check.That(b != null, $"{what}: BStr pointer is null");
            Check.Equal(s.Length * 2, *(int*)((byte*)b - 4), $"{what}: BSTR byte length prefix with a {size}-byte buffer");
            Check.That(new ReadOnlySpan<char>(b, s.Length).SequenceEqual(s) && b[s.Length] == 0, $"{what}: BSTR contents with a {size}-byte buffer");
            Check.Equal(s, BStrStringMarshaller.ConvertToManaged(b), $"{what}: BStrStringMarshaller.ConvertToManaged");
            Check.Equal(s, Marshal.PtrToStringBSTR((IntPtr)b), $"{what}: PtrToStringBSTR");
            bool inBuffer = (byte*)b >= (byte*)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer)) && (byte*)b < (byte*)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer)) + size;
            int needed = 4 + s.Length * 2 + 2;
            Check.That(!inBuffer || needed <= size, $"{what}: BSTR used a {size}-byte buffer for {needed} bytes");
        }
        finally
        {
            marshaller.Free();
        }

        ushort* c = BStrStringMarshaller.ConvertToUnmanaged(s);
        Check.Equal(s, BStrStringMarshaller.ConvertToManaged(c), $"{what}: BStrStringMarshaller.ConvertToUnmanaged / ConvertToManaged");
        BStrStringMarshaller.Free(c);
        // Marshal's own BSTR helpers agree.
        IntPtr m = Marshal.StringToBSTR(s);
        Check.Equal(s, Marshal.PtrToStringBSTR(m), $"{what}: StringToBSTR / PtrToStringBSTR");
        Check.Equal(s.Length * 2, Marshal.ReadInt32(m, -4), $"{what}: StringToBSTR length prefix");
        Marshal.FreeBSTR(m);
    }

    private static void Arrays(ref FuzzInput input, byte flags, int bufferSize)
    {
        bool atStart = (flags & 1) != 0;
        int count = input.UInt16() % 300;
        int size = Math.Min(bufferSize, 2048);
        switch ((flags >> 1) % 5)
        {
            case 0: ArrayOf<byte>(ref input, count, size, atStart); break;
            case 1: ArrayOf<int>(ref input, count, size, atStart); break;
            case 2: ArrayOf<long>(ref input, count, size, atStart); break;
            case 3: ArrayOf<Guid>(ref input, count, size, atStart); break;
            default: ArrayOf<decimal>(ref input, count, size, atStart); break;
        }
    }

    private static void ArrayOf<T>(ref FuzzInput input, int count, int size, bool atStart) where T : unmanaged
    {
        bool isNull = count == 299;
        T[] array = isNull ? null : new T[count];
        if (!isNull)
        {
            input.Bytes(count * sizeof(T)).CopyTo(MemoryMarshal.AsBytes(array.AsSpan()));
        }

        string what = $"ArrayMarshaller<{typeof(T).Name}, {typeof(T).Name}> of {(isNull ? "null" : count.ToString())} elements with a {size}-byte buffer";
        Span<byte> buffer = Buffer(size, atStart);
        buffer.Fill(0xCC);

        // ManagedToUnmanagedIn: the generated stub copies GetManagedValuesSource into GetUnmanagedValuesDestination, then calls with ToUnmanaged.
        Span<T> elementBuffer = MemoryMarshal.Cast<byte, T>(buffer);
        var inMarshaller = new ArrayMarshaller<T, T>.ManagedToUnmanagedIn();
        inMarshaller.FromManaged(array, elementBuffer);
        try
        {
            ReadOnlySpan<T> source = inMarshaller.GetManagedValuesSource();
            Span<T> destination = inMarshaller.GetUnmanagedValuesDestination();
            Check.Equal(isNull ? 0 : count, source.Length, $"{what}: GetManagedValuesSource length");
            Check.Equal(isNull ? 0 : count, destination.Length, $"{what}: GetUnmanagedValuesDestination length");
            source.CopyTo(destination);
            T* p = inMarshaller.ToUnmanaged();
            if (isNull)
            {
                Check.That(p == null, $"{what}: null array gave a pointer");
            }
            else
            {
                Check.That(count == 0 || p != null, $"{what}: pointer is null");
                Check.That(new ReadOnlySpan<T>(p, count).SequenceEqual(array), $"{what}: unmanaged contents");
                bool inBuffer = (byte*)p >= (byte*)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer)) && (byte*)p < (byte*)Unsafe.AsPointer(ref MemoryMarshal.GetReference(buffer)) + size;
                Check.That(!inBuffer || count * sizeof(T) <= size, $"{what}: used the buffer for {count * sizeof(T)} bytes");
                ref T pinned = ref inMarshaller.GetPinnableReference();
                Check.That(count == 0 || Unsafe.AreSame(ref pinned, ref *p), $"{what}: GetPinnableReference differs from ToUnmanaged");
            }
        }
        finally
        {
            inMarshaller.Free();
        }

        // The stateless shapes (the out / return path of generated stubs): allocate a container, fill it, read it back as a new array.
        T* container = ArrayMarshaller<T, T>.AllocateContainerForUnmanagedElements(array, out int numElements);
        try
        {
            Check.Equal(isNull ? 0 : count, numElements, $"{what}: AllocateContainerForUnmanagedElements count");
            Check.That(isNull ? container == null : count == 0 || container != null, $"{what}: AllocateContainerForUnmanagedElements pointer");
            ArrayMarshaller<T, T>.GetManagedValuesSource(array).CopyTo(ArrayMarshaller<T, T>.GetUnmanagedValuesDestination(container, numElements));
            T[] back = ArrayMarshaller<T, T>.AllocateContainerForManagedElements(container, numElements);
            Check.That(isNull ? back is null : back.Length == count, $"{what}: AllocateContainerForManagedElements");
            if (!isNull)
            {
                ArrayMarshaller<T, T>.GetUnmanagedValuesSource(container, numElements).CopyTo(ArrayMarshaller<T, T>.GetManagedValuesDestination(back));
                Check.That(back.SequenceEqual(array), $"{what}: round trip through the stateless marshaller");
            }
        }
        finally
        {
            ArrayMarshaller<T, T>.Free(container);
        }

        // Spans over guarded memory: the span marshallers must not touch anything beyond count elements.
        if (!isNull)
        {
            T* native = (T*)Guarded.Allocate((long)count * sizeof(T), !atStart);
            array.CopyTo(new Span<T>(native, count));
            // ReadOnlySpan out: the stateful shape owns the container it is handed, so it gets a CoTaskMem copy.
            T* co = (T*)Marshal.AllocCoTaskMem(Math.Max(1, count * sizeof(T)));
            array.CopyTo(new Span<T>(co, count));
            var roOut = new ReadOnlySpanMarshaller<T, T>.ManagedToUnmanagedOut();
            roOut.FromUnmanaged(co);
            roOut.GetUnmanagedValuesSource(count).CopyTo(roOut.GetManagedValuesDestination(count));
            ReadOnlySpan<T> ro = roOut.ToManaged();
            Check.Equal(count, ro.Length, $"{what}: ReadOnlySpanMarshaller.ManagedToUnmanagedOut length");
            Check.That(ro.SequenceEqual(array), $"{what}: ReadOnlySpanMarshaller.ManagedToUnmanagedOut round trip");
            roOut.Free();
            T* uo = ReadOnlySpanMarshaller<T, T>.UnmanagedToManagedOut.AllocateContainerForUnmanagedElements(array, out int uoCount);
            Check.Equal(count, uoCount, $"{what}: ReadOnlySpanMarshaller.UnmanagedToManagedOut count");
            ReadOnlySpanMarshaller<T, T>.UnmanagedToManagedOut.GetManagedValuesSource(array).CopyTo(ReadOnlySpanMarshaller<T, T>.UnmanagedToManagedOut.GetUnmanagedValuesDestination(uo, uoCount));
            Check.That(new ReadOnlySpan<T>(uo, uoCount).SequenceEqual(array), $"{what}: ReadOnlySpanMarshaller.UnmanagedToManagedOut contents");
            Marshal.FreeCoTaskMem((IntPtr)uo);
            Span<T> sp = SpanMarshaller<T, T>.AllocateContainerForManagedElements(native, count);
            Check.Equal(count, sp.Length, $"{what}: SpanMarshaller.AllocateContainerForManagedElements length");
            SpanMarshaller<T, T>.GetUnmanagedValuesSource(native, count).CopyTo(SpanMarshaller<T, T>.GetManagedValuesDestination(sp));
            Check.That(sp.SequenceEqual(array), $"{what}: SpanMarshaller round trip");
            T* spanContainer = SpanMarshaller<T, T>.AllocateContainerForUnmanagedElements(array, out int spanCount);
            Check.Equal(count, spanCount, $"{what}: SpanMarshaller.AllocateContainerForUnmanagedElements count");
            SpanMarshaller<T, T>.GetManagedValuesSource(array).CopyTo(SpanMarshaller<T, T>.GetUnmanagedValuesDestination(spanContainer, spanCount));
            Check.That(new ReadOnlySpan<T>(spanContainer, spanCount).SequenceEqual(array), $"{what}: SpanMarshaller unmanaged contents");
            SpanMarshaller<T, T>.Free(spanContainer);
            var spanIn = new SpanMarshaller<T, T>.ManagedToUnmanagedIn();
            spanIn.FromManaged(array, elementBuffer);
            spanIn.GetManagedValuesSource().CopyTo(spanIn.GetUnmanagedValuesDestination());
            Check.That(new ReadOnlySpan<T>(spanIn.ToUnmanaged(), count).SequenceEqual(array), $"{what}: SpanMarshaller.ManagedToUnmanagedIn contents");
            spanIn.Free();
            var roIn = new ReadOnlySpanMarshaller<T, T>.ManagedToUnmanagedIn();
            roIn.FromManaged(array, elementBuffer);
            roIn.GetManagedValuesSource().CopyTo(roIn.GetUnmanagedValuesDestination());
            Check.That(new ReadOnlySpan<T>(roIn.ToUnmanaged(), count).SequenceEqual(array), $"{what}: ReadOnlySpanMarshaller.ManagedToUnmanagedIn contents");
            roIn.Free();
        }

        // Pointer arrays: an array of T* marshalled element-wise.
        int pointerCount = Math.Min(count, 16);
        T*[] pointers = new T*[pointerCount];
        for (int i = 0; i < pointerCount; i++)
        {
            pointers[i] = (T*)(nint)(0x1000 * (i + 1));
        }

        nint* pc = PointerArrayMarshaller<T, nint>.AllocateContainerForUnmanagedElements(pointers, out int pn);
        Check.Equal(pointerCount, pn, $"{what}: PointerArrayMarshaller count");
        for (int i = 0; i < pointerCount; i++)
        {
            PointerArrayMarshaller<T, nint>.GetUnmanagedValuesDestination(pc, pn)[i] = (nint)pointers[i];
        }

        T*[] pointersBack = PointerArrayMarshaller<T, nint>.AllocateContainerForManagedElements(pc, pn);
        PointerArrayMarshaller<T, nint>.GetUnmanagedValuesSource(pc, pn).CopyTo(PointerArrayMarshaller<T, nint>.GetManagedValuesDestination(pointersBack));
        for (int i = 0; i < pointerCount; i++)
        {
            Check.That(pointersBack[i] == pointers[i], $"{what}: PointerArrayMarshaller element {i}");
        }

        PointerArrayMarshaller<T, nint>.Free(pc);
    }

    private static int s_files;

    [DllImport("libc")] private static extern int fcntl(int fd, int cmd);
    private static bool IsOpen(IntPtr fd) => fcntl((int)fd, 1 /* F_GETFD */) >= 0;

    private static void Handles(ref FuzzInput input, byte flags)
    {
        string path = $"/dev/shm/sharpfuzz-marshallers-{Environment.ProcessId}-{s_files++}";
        SafeFileHandle handle = File.OpenHandle(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None, FileOptions.DeleteOnClose);
        try
        {
            IntPtr raw = handle.DangerousGetHandle();
            // In: ToUnmanaged is the raw handle; the handle stays open while the marshaller holds a reference.
            var inMarshaller = new SafeHandleMarshaller<SafeFileHandle>.ManagedToUnmanagedIn();
            inMarshaller.FromManaged(handle);
            Check.Equal(raw, inMarshaller.ToUnmanaged(), "SafeHandleMarshaller.ManagedToUnmanagedIn.ToUnmanaged");
            handle.Dispose(); // the marshaller's reference keeps the descriptor open
            Check.That(IsOpen(raw), "descriptor closed while marshalled in");
            inMarshaller.Free();
            Check.That(!IsOpen(raw), "descriptor still open after Free");
            // Out: a fresh handle around a descriptor the callee returned.
            using SafeFileHandle second = File.OpenHandle(path + "b", FileMode.Create, FileAccess.ReadWrite, FileShare.None, FileOptions.DeleteOnClose);
            IntPtr fd = second.DangerousGetHandle();
            var outMarshaller = new SafeHandleMarshaller<SafeFileHandle>.ManagedToUnmanagedOut();
            outMarshaller.FromUnmanaged(fd);
            SafeFileHandle created = outMarshaller.ToManaged();
            Check.That(created is not null && created.DangerousGetHandle() == fd && !created.IsInvalid, "SafeHandleMarshaller.ManagedToUnmanagedOut.ToManaged");
            created.SetHandleAsInvalid(); // don't close 'second' twice
            // Ref: the original stays valid until the call; a new handle is produced when the callee changes the value.
            var refMarshaller = new SafeHandleMarshaller<SafeFileHandle>.ManagedToUnmanagedRef();
            refMarshaller.FromManaged(second);
            Check.Equal(fd, refMarshaller.ToUnmanaged(), "SafeHandleMarshaller.ManagedToUnmanagedRef.ToUnmanaged");
            IntPtr replacement = (flags & 1) != 0 ? fd : (IntPtr)(-1);
            refMarshaller.FromUnmanaged(replacement);
            SafeFileHandle result = refMarshaller.ToManagedFinally();
            refMarshaller.Free();
            if (replacement == fd)
            {
                Check.That(ReferenceEquals(result, second), "ManagedToUnmanagedRef with an unchanged handle should return the original");
            }
            else
            {
                Check.That(!ReferenceEquals(result, second) && result.DangerousGetHandle() == replacement, "ManagedToUnmanagedRef with a changed handle should return a new object");
                result.SetHandleAsInvalid();
            }

            // A closed handle can't be marshalled in.
            using var closed = new SafeFileHandle((IntPtr)(-1), ownsHandle: false);
            closed.Dispose();
            var closedIn = new SafeHandleMarshaller<SafeFileHandle>.ManagedToUnmanagedIn();
            try
            {
                closedIn.FromManaged(closed);
                Check.That(false, "FromManaged accepted a disposed handle");
            }
            catch (ObjectDisposedException)
            {
            }

            // Exception marshallers.
            var e = new InvalidOperationException("x");
            Check.Equal(0, ExceptionAsDefaultMarshaller<int>.ConvertToUnmanaged(e), "ExceptionAsDefaultMarshaller<int>");
            Check.That(double.IsNaN(ExceptionAsNaNMarshaller<double>.ConvertToUnmanaged(e)), "ExceptionAsNaNMarshaller<double>");
            Check.Equal(e.HResult, ExceptionAsHResultMarshaller<int>.ConvertToUnmanaged(e), "ExceptionAsHResultMarshaller<int>");
            ExceptionAsVoidMarshaller.ConvertToUnmanaged(e);
        }
        finally
        {
            handle.Dispose();
        }
    }

    private static void Variants(ref FuzzInput input, byte flags)
    {
        long l = (long)input.Int32() << 32 | (uint)input.Int32();
        double d = BitConverter.Int64BitsToDouble(l);
        string s = Encoding.UTF8.GetString(input.SegmentBytes());
        string what = $"ComVariant of {l} / {d:R} / {Check.Show(s)}";
        switch (flags % 12)
        {
            case 0: RoundTrip((byte)l, VarEnum.VT_UI1, what); break;
            case 1: RoundTrip((sbyte)l, VarEnum.VT_I1, what); break;
            case 2: RoundTrip((short)l, VarEnum.VT_I2, what); break;
            case 3: RoundTrip((ushort)l, VarEnum.VT_UI2, what); break;
            case 4: RoundTrip((int)l, VarEnum.VT_I4, what); break;
            case 5: RoundTrip((uint)l, VarEnum.VT_UI4, what); break;
            case 6: RoundTrip(l, VarEnum.VT_I8, what); break;
            case 7: RoundTrip((ulong)l, VarEnum.VT_UI8, what); break;
            case 8: RoundTrip(BitConverter.Int32BitsToSingle((int)l), VarEnum.VT_R4, what); break;
            case 9: RoundTrip(d, VarEnum.VT_R8, what); break;
            case 10: RoundTrip((l & 1) != 0, VarEnum.VT_BOOL, what); break;
            default:
                using (ComVariant v = ComVariant.Create(s))
                {
                    Check.Equal(VarEnum.VT_BSTR, v.VarType, $"{what}: VarType of a string");
                    Check.Equal(s, v.As<string>(), $"{what}: As<string>");
                }

                decimal dec = new decimal((int)l, (int)(l >> 32), (int)(l >> 16), (l & 1) != 0, (byte)(flags % 29));
                using (ComVariant v = ComVariant.Create(dec))
                {
                    Check.Equal(VarEnum.VT_DECIMAL, v.VarType, $"{what}: VarType of a decimal");
                    Check.That(decimal.GetBits(dec).SequenceEqual(decimal.GetBits(v.As<decimal>())), $"{what}: As<decimal>");
                }

                using (ComVariant v = ComVariant.CreateRaw(VarEnum.VT_I4, (int)l))
                {
                    Check.Equal(VarEnum.VT_I4, v.VarType, $"{what}: CreateRaw VarType");
                    Check.Equal((int)l, v.GetRawDataRef<int>(), $"{what}: GetRawDataRef<int>");
                    Check.Equal((int)l, v.As<int>(), $"{what}: CreateRaw / As<int>");
                }

                // As<T> with the wrong T is rejected, never reinterpreted.
                using (ComVariant v = ComVariant.Create(l))
                {
                    try
                    {
                        v.As<double>();
                        Check.That(false, $"{what}: As<double> on VT_I8 succeeded");
                    }
                    catch (Exception e) when (e is InvalidOperationException or ArgumentException)
                    {
                    }
                }

                Check.Equal(VarEnum.VT_EMPTY, default(ComVariant).VarType, "default ComVariant");
                Check.Equal(VarEnum.VT_NULL, ComVariant.Null.VarType, "ComVariant.Null");
                break;
        }
    }

    private static void RoundTrip<T>(T value, VarEnum expected, string what) where T : unmanaged
    {
        using ComVariant v = ComVariant.Create(value);
        Check.Equal(expected, v.VarType, $"{what}: VarType of {typeof(T).Name}");
        T back = v.As<T>();
        Check.That(MemoryMarshal.AsBytes(new ReadOnlySpan<T>(in value)).SequenceEqual(MemoryMarshal.AsBytes(new ReadOnlySpan<T>(in back))), $"{what}: As<{typeof(T).Name}> gave {back}");
        if (typeof(T) != typeof(bool)) // VT_BOOL holds VARIANT_TRUE (-1), not the managed bool
        {
            Check.That(MemoryMarshal.AsBytes(new ReadOnlySpan<T>(in value)).SequenceEqual(MemoryMarshal.AsBytes(new ReadOnlySpan<T>(in v.GetRawDataRef<T>()))), $"{what}: GetRawDataRef<{typeof(T).Name}>");
        }
    }
}
