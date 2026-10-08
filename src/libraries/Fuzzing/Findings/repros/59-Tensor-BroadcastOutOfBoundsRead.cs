#:package System.Numerics.Tensors@11.0.0-rc.1.26425.128
#:property AllowUnsafeBlocks=true
#pragma warning disable SYSLIB5001
// Finding (memory safety): the two-operand, no-destination tensor operations read past the end of an
// operand for a legal bidirectional broadcast. Tensor.Dot / Tensor.Distance / Tensor.CosineSimilarity and the
// comparison family (EqualsAll/Any, GreaterThan*/LessThan* All/Any) pick their iteration shape as whichever
// operand has the larger FlattenedLength, then walk BOTH operands over that shape. When the *other* operand has
// a longer inner dimension, TensorShape.AdjustToNextIndex runs its carry (linearOffset -= stride * length) and
// returns an out-of-range (negative) offset, so Unsafe.Add(ref operand._reference, offset) reads before the
// operand's storage. This is the release-mode memory-safety consequence of the shape-selection bug behind
// findings 6/7 (which report only wrong results / a Debug assert), and it additionally covers the
// Dot/Distance/CosineSimilarity reductions, which are not comparisons.
//
// Two symptoms:
//   * Memory disclosure: with x = [4,1] and y = [1,3] (both individually in bounds), the engine walks y to
//     linear offsets 0, -2, -4, -6, reading the heap in front of y's 3-element array. Tensor.Dot returns
//     attacker-unknown heap bytes instead of the broadcast dot product.
//   * Memory safety: the same over-read against an unmapped page is an AccessViolationException that crashes
//     the process.
// Run: dotnet run 59-Tensor-BroadcastOutOfBoundsRead.cs   (prints REPRODUCED for the disclosure, then crashes)
using System.Numerics.Tensors;
using System.Runtime.InteropServices;

// 1. The safe, observable symptom: heap disclosure through the array-backed public API.
int[] xs = [2, 3, 5, 7];   // column, shape [4,1], FlattenedLength 4
int[] ys = [11, 13, 17];   // row,    shape [1,3], FlattenedLength 3, backed by exactly 3 ints
var x = new ReadOnlyTensorSpan<int>(xs, [4, 1], default);
var y = new ReadOnlyTensorSpan<int>(ys, [1, 3], default);

long expected = 0;
foreach (int xi in xs)
    foreach (int yj in ys)
        expected += (long)xi * yj; // correct broadcast [4,3] dot product = 697

int dot = Tensor.Dot(x, y);
Console.WriteLine($"x FlattenedLength {x.FlattenedLength} (shape [4,1]), y FlattenedLength {y.FlattenedLength} (shape [1,3], 3 ints of storage)");
Console.WriteLine($"Tensor.Dot(x, y) = {dot}, expected broadcast [4,3] dot = {expected}");
Console.WriteLine("(the engine iterates x's shape [4,1] and walks y to linear offsets 0, -2, -4, -6; the negatives read before y's array)");
Console.WriteLine(dot != expected ? "REPRODUCED (Dot read y out of bounds and returned heap bytes)" : "NOT REPRODUCED");

// 2. The memory-safety symptom: the same over-read against an unmapped page.
unsafe
{
    nuint pageSize = 4096;
    if (posix_memalign(out nint region, pageSize, pageSize * 2) != 0) { Console.WriteLine("posix_memalign failed; skipping the guard-page part"); return; }
    if (mprotect(region, pageSize, 0) != 0) { Console.WriteLine("mprotect failed; skipping the guard-page part"); return; }

    // y's 3 floats sit at the very start of the readable second page, so y[-1], y[-2], ... fall in the guard page.
    float* yptr = (float*)(region + (nint)pageSize);
    yptr[0] = 1f; yptr[1] = 1f; yptr[2] = 1f;
    float* xptr = (float*)(region + (nint)pageSize + 64);
    xptr[0] = 5f; xptr[1] = 5f; xptr[2] = 5f; xptr[3] = 5f;

    var xf = new ReadOnlyTensorSpan<float>(xptr, 4, [4, 1]); // larger FlattenedLength, chosen as the iteration shape
    var yf = new ReadOnlyTensorSpan<float>(yptr, 3, [1, 3]);
    Console.WriteLine("Now calling Tensor.Dot with y placed against an unmapped page (AccessViolation on an affected runtime)...");
    Console.Out.Flush();

    float result = Tensor.Dot(xf, yf);
    Console.WriteLine($"Tensor.Dot returned {result} (no out-of-bounds read on this runtime)");
}

[DllImport("libc", SetLastError = true)] static extern int posix_memalign(out nint memptr, nuint alignment, nuint size);
[DllImport("libc", SetLastError = true)] static extern int mprotect(nint addr, nuint len, int prot);
