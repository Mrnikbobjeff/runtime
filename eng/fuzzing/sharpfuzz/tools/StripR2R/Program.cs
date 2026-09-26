// Rewrites a ReadyToRun (mixed-mode) framework assembly as a plain IL-only
// assembly so that SharpFuzz is willing to instrument it. The IL of every
// method is still present in R2R images; we only drop the precompiled code.
using dnlib.DotNet;
using dnlib.DotNet.MD;
using dnlib.DotNet.Writer;

if (args.Length != 2)
{
    Console.Error.WriteLine("usage: StripR2R <input.dll> <output.dll>");
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
