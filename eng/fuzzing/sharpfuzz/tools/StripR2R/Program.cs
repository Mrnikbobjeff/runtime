// Rewrites a ReadyToRun (mixed-mode) framework assembly as a plain IL-only
// assembly so that SharpFuzz is willing to instrument it. The IL of every
// method is still present in R2R images; we only drop the precompiled code.
//
//   StripR2R --list-types <assembly.dll>
//     Prints the full names of all top-level types, one per line (used to build
//     the SharpFuzz prefix list for System.Private.CoreLib).
using dnlib.DotNet;
using dnlib.DotNet.MD;
using dnlib.DotNet.Writer;

if (args.Length == 2 && args[0] == "--list-types")
{
    using var listed = ModuleDefMD.Load(args[1]);
    foreach (TypeDef type in listed.Types)
    {
        Console.WriteLine(type.FullName);
    }
    return 0;
}

if (args.Length == 2 && args[0] == "--thread-static-trace")
{
    return MakePrevLocationThreadStatic(args[1]);
}

if (args.Length != 2)
{
    Console.Error.WriteLine("usage: StripR2R <input.dll> <output.dll> | StripR2R --list-types <assembly.dll> | StripR2R --thread-static-trace <instrumented System.Private.CoreLib.dll>");
    return 1;
}

using var module = ModuleDefMD.Load(args[0]);
bool wasR2R = module.Metadata.ImageCor20Header.ManagedNativeHeader.VirtualAddress != 0;

module.Cor20HeaderFlags &= ~ComImageFlags.ILLibrary;
module.Cor20HeaderFlags |= ComImageFlags.ILOnly;

var options = new ModuleWriterOptions(module);
// Keep metadata tokens stable and don't try to re-sign with a key we don't have.
options.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
options.Cor20HeaderOptions.Flags = module.Cor20HeaderFlags;
options.StrongNameKey = null;
// R2R images use an OS-specific machine value (e.g. AMD64 ^ 0x7B79 on Linux), which the
// runtime rejects for IL-only images. Emit a plain AnyCPU PE32 image instead.
options.PEHeadersOptions.Machine = dnlib.PE.Machine.I386;
options.Cor20HeaderOptions.Flags &= ~(ComImageFlags.Bit32Required | ComImageFlags.Bit32Preferred);
options.Cor20HeaderOptions.Flags &= ~ComImageFlags.StrongNameSigned;

module.Write(args[1], options);
Console.WriteLine($"{Path.GetFileName(args[0])}: machine={module.Machine} R2R={wasR2R} -> IL-only AnyCPU written to {args[1]}");
return 0;

// sharpfuzz embeds its own SharpFuzz.Common.Trace type in an instrumented CoreLib. Its
// PrevLocation (the previous basic block, XOR-ed into each edge id) is one static shared by all
// threads, so CoreLib code running on a background thread (SharpFuzz's parent-process watchdog,
// the finalizer) produces edges mixed with the fuzzing thread's blocks: effectively random map
// entries that wreck AFL's stability. With [ThreadStatic] each thread traces its own edges, so
// background activity adds only a small, fixed set of edges.
static int MakePrevLocationThreadStatic(string path)
{
    byte[] image = File.ReadAllBytes(path);
    using var module = ModuleDefMD.Load(image);
    TypeDef? trace = module.Types.FirstOrDefault(t => t.FullName == "SharpFuzz.Common.Trace");
    FieldDef? prevLocation = trace?.Fields.FirstOrDefault(f => f.Name == "PrevLocation");
    TypeDef? threadStatic = module.Find("System.ThreadStaticAttribute", isReflectionName: false);
    if (prevLocation is null || threadStatic is null)
    {
        Console.Error.WriteLine($"{path}: no SharpFuzz.Common.Trace.PrevLocation / System.ThreadStaticAttribute found");
        return 1;
    }

    if (prevLocation.CustomAttributes.Any(a => a.AttributeType == threadStatic))
    {
        Console.WriteLine($"{Path.GetFileName(path)}: Trace.PrevLocation is already [ThreadStatic]");
        return 0;
    }

    MethodDef ctor = threadStatic.FindDefaultConstructor();
    prevLocation.CustomAttributes.Add(new CustomAttribute(ctor));
    var writerOptions = new ModuleWriterOptions(module);
    writerOptions.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
    module.Write(path, writerOptions);
    Console.WriteLine($"{Path.GetFileName(path)}: Trace.PrevLocation is now [ThreadStatic]");
    return 0;
}
