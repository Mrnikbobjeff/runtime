#nullable disable warnings
using System.Collections.Immutable;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

namespace SharpFuzzHarness;

/// <summary>Fuzzes System.Reflection.Metadata: PEReader, MetadataReader, signature and attribute decoding.</summary>
/// <remarks>
/// Input: the bytes of a PE file (seeds are small compiled assemblies). The whole object model is
/// walked: headers, sections, debug directory, every table, names, signatures (decoded with
/// SignatureDecoder), method bodies and exception regions, custom attributes (DecodeValue), blobs
/// and user strings. Malformed input may only throw BadImageFormatException. A MetadataReader over the
/// raw metadata block must see the same tables as the one PEReader creates.
/// </remarks>
public static class MetadataTarget
{
    private const int MaxItems = 512;

    public static void Run(ReadOnlySpan<byte> data)
    {
        if (data.Length > 1 << 17)
        {
            return;
        }

        byte[] image = data.ToArray();
        using var pe = new PEReader(ImmutableArray.Create(image));

        // Each part is checked on its own, so a malformed debug directory doesn't hide the metadata.
        Guard(() => Headers(pe));
        bool hasMetadata = false;
        Guard(() => hasMetadata = pe.HasMetadata);
        if (!hasMetadata)
        {
            return;
        }

        string viaPe = null;
        Guard(() =>
        {
            MetadataReader md = pe.GetMetadataReader();
            viaPe = Walk(md);
            Bodies(md, pe);
        });
        if (viaPe is null)
        {
            return;
        }

        // The same metadata read directly from its bytes must look the same.
        byte[] block = pe.GetMetadata().GetContent().ToArray();
        string viaBlock = null;
        Guard(() =>
        {
            unsafe
            {
                fixed (byte* p = block)
                {
                    viaBlock = Walk(new MetadataReader(p, block.Length));
                }
            }
        });
        Check.That(viaBlock == viaPe, $"MetadataReader over the metadata block differs from PEReader's:\n  block: {viaBlock}\n  PE:    {viaPe}");
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    /// <summary>Runs a part of the walk, allowing BadImageFormatException (documented) and the known issues.</summary>
    private static void Guard(Action part)
    {
        try
        {
            part();
        }
        catch (BadImageFormatException)
        {
        }
        catch (Exception e) when (!s_reportKnownIssues && IsKnown(e))
        {
        }
    }

    // Known (METADATA-1..4, see FINDINGS-CORELIB.md): malformed metadata makes MetadataReader throw
    // NullReferenceException (nested types map) or OverflowException (stream headers), the signature
    // and custom attribute decoders allocate builders sized by untrusted counts, and a corrupt embedded
    // portable PDB surfaces InvalidDataException from the inflater.
    private static bool IsKnown(Exception e)
    {
        string trace = e.StackTrace ?? "";
        return e switch
        {
            NullReferenceException => trace.Contains("InitializeNestedTypesMap", StringComparison.Ordinal),
            OverflowException => trace.Contains("ReadStreamHeaders", StringComparison.Ordinal),
            OutOfMemoryException => trace.Contains("SignatureDecoder", StringComparison.Ordinal) || trace.Contains("CustomAttributeDecoder", StringComparison.Ordinal),
            System.IO.InvalidDataException => trace.Contains("ReadEmbeddedPortablePdbDebugDirectoryData", StringComparison.Ordinal),
            _ => false,
        };
    }

    private static void Headers(PEReader pe)
    {
        PEHeaders headers = pe.PEHeaders;
        _ = (headers.IsDll, headers.IsExe, headers.IsConsoleApplication, headers.MetadataSize, headers.MetadataStartOffset, headers.CorHeaderStartOffset);
        foreach (SectionHeader section in headers.SectionHeaders.Take(MaxItems))
        {
            _ = (section.Name, section.VirtualAddress, section.SizeOfRawData);
            if (section.VirtualAddress >= 0)
            {
                _ = pe.GetSectionData(section.VirtualAddress).Length;
            }
        }

        if (headers.PEHeader is { } peHeader)
        {
            _ = pe.ReadDebugDirectory().Take(MaxItems).Select(entry => (entry.Type, entry.DataSize, entry.IsPortableCodeView)).ToArray();
            foreach (DebugDirectoryEntry entry in pe.ReadDebugDirectory().Take(8))
            {
                if (entry.Type == DebugDirectoryEntryType.CodeView)
                {
                    _ = pe.ReadCodeViewDebugDirectoryData(entry).Path;
                }
                else if (entry.Type == DebugDirectoryEntryType.PdbChecksum)
                {
                    _ = pe.ReadPdbChecksumDebugDirectoryData(entry).AlgorithmName;
                }
                else if (entry.Type == DebugDirectoryEntryType.EmbeddedPortablePdb)
                {
                    using MetadataReaderProvider provider = pe.ReadEmbeddedPortablePdbDebugDirectoryData(entry);
                    _ = provider.GetMetadataReader().Documents.Count;
                }
            }

            _ = peHeader.CertificateTableDirectory.Size;
        }
    }

    /// <summary>Walks the metadata and returns a summary that two readers of the same metadata must agree on.</summary>
    private static string Walk(MetadataReader md)
    {
        var provider = new StringProvider();
        var summary = new System.Text.StringBuilder();
        summary.Append($"{md.MetadataKind} {md.MetadataVersion} types={md.TypeDefinitions.Count} methods={md.MethodDefinitions.Count} fields={md.FieldDefinitions.Count} ");
        if (md.IsAssembly)
        {
            AssemblyDefinition assembly = md.GetAssemblyDefinition();
            summary.Append($"{md.GetString(assembly.Name)} {assembly.Version} ");
            // AssemblyName.CultureName needs a real culture: under invariant globalization (the harness)
            // any non-empty culture name throws CultureNotFoundException.
            _ = Outcome<System.Reflection.AssemblyName>.Of(assembly.GetAssemblyName, e => e is System.Globalization.CultureNotFoundException);
        }

        foreach (TypeDefinitionHandle th in md.TypeDefinitions.Take(MaxItems))
        {
            TypeDefinition type = md.GetTypeDefinition(th);
            summary.Append(md.GetString(type.Namespace)).Append('.').Append(md.GetString(type.Name)).Append(';');
            _ = (type.Attributes, type.GetDeclaringType(), type.GetLayout(), type.GetGenericParameters().Count, type.GetInterfaceImplementations().Count, type.GetNestedTypes().Length);
            if (!type.BaseType.IsNil)
            {
                _ = Describe(md, type.BaseType, provider);
            }

            foreach (MethodDefinitionHandle mh in type.GetMethods().Take(MaxItems))
            {
                MethodDefinition method = md.GetMethodDefinition(mh);
                summary.Append(md.GetString(method.Name)).Append('(');
                MethodSignature<string> sig = method.DecodeSignature(provider, null);
                summary.Append(string.Join(",", sig.ParameterTypes)).Append(')').Append(sig.ReturnType).Append(';');
                foreach (ParameterHandle ph in method.GetParameters().Take(MaxItems))
                {
                    _ = md.GetString(md.GetParameter(ph).Name);
                }

            }

            foreach (FieldDefinitionHandle fh in type.GetFields().Take(MaxItems))
            {
                FieldDefinition field = md.GetFieldDefinition(fh);
                summary.Append(md.GetString(field.Name)).Append(':').Append(field.DecodeSignature(provider, null)).Append(';');
                if (!field.GetDefaultValue().IsNil)
                {
                    _ = md.GetBlobBytes(md.GetConstant(field.GetDefaultValue()).Value).Length;
                }
            }

            foreach (PropertyDefinitionHandle ph in type.GetProperties().Take(MaxItems))
            {
                PropertyDefinition property = md.GetPropertyDefinition(ph);
                _ = (md.GetString(property.Name), property.DecodeSignature(provider, null).ReturnType, property.GetAccessors().Getter);
            }
        }

        foreach (CustomAttributeHandle ch in md.CustomAttributes.Take(MaxItems))
        {
            CustomAttribute attribute = md.GetCustomAttribute(ch);
            summary.Append(Describe(md, attribute.Constructor, provider)).Append('[');
            CustomAttributeValue<string> value = attribute.DecodeValue(provider);
            summary.Append(string.Join(",", value.FixedArguments.Select(a => a.Value?.ToString()))).Append('|');
            summary.Append(string.Join(",", value.NamedArguments.Select(a => a.Name + "=" + a.Value)));

            summary.Append("];");
        }

        foreach (TypeReferenceHandle rh in md.TypeReferences.Take(MaxItems))
        {
            TypeReference reference = md.GetTypeReference(rh);
            summary.Append(md.GetString(reference.Namespace)).Append('.').Append(md.GetString(reference.Name)).Append(';');
        }

        foreach (MemberReferenceHandle mh in md.MemberReferences.Take(MaxItems))
        {
            MemberReference member = md.GetMemberReference(mh);
            summary.Append(md.GetString(member.Name)).Append(':');
            summary.Append(member.GetKind() == MemberReferenceKind.Method ? string.Join(",", member.DecodeMethodSignature(provider, null).ParameterTypes) : member.DecodeFieldSignature(provider, null)).Append(';');
        }

        foreach (AssemblyReferenceHandle ah in md.AssemblyReferences.Take(MaxItems))
        {
            AssemblyReference reference = md.GetAssemblyReference(ah);
            summary.Append(md.GetString(reference.Name)).Append(reference.Version).Append(';');
        }

        foreach (ManifestResourceHandle rh in md.ManifestResources.Take(MaxItems))
        {
            summary.Append(md.GetString(md.GetManifestResource(rh).Name)).Append(';');
        }

        UserStringHandle us = MetadataTokens.UserStringHandle(1);
        for (int i = 0; i < MaxItems && !us.IsNil; i++)
        {
            summary.Append(md.GetUserString(us).Length).Append(',');
            us = md.GetNextHandle(us);
        }

        foreach (TableIndex table in Enum.GetValues<TableIndex>())
        {
            summary.Append(md.GetTableRowCount(table)).Append(',').Append(md.GetTableRowSize(table)).Append(' ');
        }

        return summary.ToString();
    }

    private static void Bodies(MetadataReader md, PEReader pe)
    {
        var provider = new StringProvider();
        foreach (MethodDefinitionHandle mh in md.MethodDefinitions.Take(MaxItems))
        {
            MethodDefinition method = md.GetMethodDefinition(mh);
            if (method.RelativeVirtualAddress <= 0)
            {
                continue;
            }

            Guard(() =>
            {
                MethodBodyBlock body = pe.GetMethodBody(method.RelativeVirtualAddress);
                _ = (body.Size, body.MaxStack, body.LocalVariablesInitialized, body.GetILBytes()?.Length);
                foreach (ExceptionRegion region in body.ExceptionRegions)
                {
                    _ = (region.Kind, region.TryOffset, region.HandlerLength, region.CatchType.IsNil);
                }

                if (!body.LocalSignature.IsNil)
                {
                    _ = md.GetStandaloneSignature(body.LocalSignature).DecodeLocalSignature(provider, null).Length;
                }
            });
        }
    }

    private static string Describe(MetadataReader md, EntityHandle handle, StringProvider provider) => handle.Kind switch
    {
        HandleKind.TypeDefinition => provider.GetTypeFromDefinition(md, (TypeDefinitionHandle)handle, 0),
        HandleKind.TypeReference => provider.GetTypeFromReference(md, (TypeReferenceHandle)handle, 0),
        HandleKind.TypeSpecification => provider.GetTypeFromSpecification(md, null, (TypeSpecificationHandle)handle, 0),
        HandleKind.MethodDefinition => md.GetString(md.GetMethodDefinition((MethodDefinitionHandle)handle).Name),
        HandleKind.MemberReference => md.GetString(md.GetMemberReference((MemberReferenceHandle)handle).Name),
        _ => handle.Kind.ToString(),
    };

    /// <summary>Decodes types to strings, for signatures and custom attribute values.</summary>
    private sealed class StringProvider : ISignatureTypeProvider<string, object>, ICustomAttributeTypeProvider<string>
    {
        public string GetPrimitiveType(PrimitiveTypeCode typeCode) => typeCode.ToString();
        public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) => reader.GetString(reader.GetTypeDefinition(handle).Name);
        public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) => reader.GetString(reader.GetTypeReference(handle).Name);
        public string GetTypeFromSpecification(MetadataReader reader, object genericContext, TypeSpecificationHandle handle, byte rawTypeKind) =>
            reader.GetTypeSpecification(handle).DecodeSignature(this, genericContext);
        public string GetSZArrayType(string elementType) => elementType + "[]";
        public string GetArrayType(string elementType, ArrayShape shape) => elementType + "[" + shape.Rank + "]";
        public string GetByReferenceType(string elementType) => elementType + "&";
        public string GetPointerType(string elementType) => elementType + "*";
        public string GetPinnedType(string elementType) => elementType + " pinned";
        public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments) => genericType + "<" + string.Join(",", typeArguments) + ">";
        public string GetGenericMethodParameter(object genericContext, int index) => "!!" + index;
        public string GetGenericTypeParameter(object genericContext, int index) => "!" + index;
        public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => unmodifiedType + (isRequired ? " modreq(" : " modopt(") + modifier + ")";
        public string GetFunctionPointerType(MethodSignature<string> signature) => "fnptr";
        public string GetSystemType() => "System.Type";
        public bool IsSystemType(string type) => type is "Type" or "System.Type";
        public string GetTypeFromSerializedName(string name) => name;
        public PrimitiveTypeCode GetUnderlyingEnumType(string type) => PrimitiveTypeCode.Int32;
    }
}
