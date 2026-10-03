// Finding: UnmanagedMemoryAccessor.WriteArray<T> ignores the accessor's Capacity. Every other writer on the
// accessor enforces it - the primitive Write(long, byte/int/...) overloads throw once the write would cross
// Capacity, Write<T>(long, ref T) checks `position > _capacity - sizeOfT`, and ReadArray<T> clamps `count` to
// what fits in Capacity - but WriteArray<T> only checks `position >= Capacity` and then hands `count` straight
// to the backing SafeBuffer, so the write is bounded by the SafeBuffer's allocation, not by the accessor's
// Capacity. An accessor that is a sub-window of a larger SafeBuffer can therefore write past its own declared
// Capacity into the rest of the buffer. The over-write stays inside the SafeBuffer's allocation, so it is not an
// out-of-bounds access past the mapped region (a MemoryMappedViewAccessor, whose backing length equals its own
// capacity, is not affected); it is a missing bounds check that breaks window isolation between accessors over a
// shared buffer. This is the write-side counterpart of ReadArray, which clamps.
// Run: dotnet run 60-UnmanagedMemoryAccessor-WriteArrayIgnoresCapacity.cs
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;

int pageSize = Environment.SystemPageSize;

// One SafeBuffer (the MMF view handle), ByteLength == pageSize.
using var mmf = MemoryMappedFile.CreateNew(null, pageSize);
using var full = mmf.CreateViewAccessor(0, pageSize, MemoryMappedFileAccess.ReadWrite);
SafeBuffer buffer = full.SafeMemoryMappedViewHandle; // _numBytes == pageSize

// Canary in [16, 64): inside the buffer but OUTSIDE the sub-window created below.
for (int i = 16; i < 64; i++) full.Write(i, (byte)0xCC);

// A sub-window accessor with Capacity = 16 over the same buffer.
using var sub = new UnmanagedMemoryAccessor(buffer, offset: 0, capacity: 16, FileAccess.ReadWrite);
Console.WriteLine($"sub.Capacity = {sub.Capacity}");

bool primitiveThrew = false;
try { sub.Write(20, (byte)1); } catch { primitiveThrew = true; }
Console.WriteLine($"sub.Write(position=20) past capacity threw: {primitiveThrew} (primitive writers enforce Capacity)");

int readClamped = sub.ReadArray(0, new byte[pageSize], 0, pageSize);
Console.WriteLine($"sub.ReadArray(count={pageSize}) returned {readClamped} (ReadArray clamps to Capacity)");

// The bug: WriteArray writes 48 bytes though Capacity is only 16 and position 0 < Capacity.
byte[] payload = new byte[48];
Array.Fill(payload, (byte)0xAB);

bool writeArrayThrew = false;
try { sub.WriteArray<byte>(0, payload, 0, 48); }
catch (Exception e) { writeArrayThrew = true; Console.WriteLine($"sub.WriteArray threw {e.GetType().Name}"); }

int clobbered = 0;
for (int i = 16; i < 48; i++)
    if (full.ReadByte(i) == 0xAB) clobbered++;

Console.WriteLine($"WriteArray threw            : {writeArrayThrew} (expected True: count exceeds Capacity)");
Console.WriteLine($"bytes written past Cap = 16 : {clobbered} (expected 0: writes must stay within Capacity)");

Console.WriteLine(!writeArrayThrew && clobbered > 0
    ? $"REPRODUCED (WriteArray wrote {clobbered} bytes past the accessor's Capacity into another window of the buffer)"
    : "NOT REPRODUCED");
