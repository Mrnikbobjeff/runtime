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
        try
        {
            using var pe = new PEReader(ImmutableArray.Create(image));
            Headers(pe);
            if (!pe.HasMetadata)
            {
                return;
            }

            MetadataReader md = pe.GetMetadataReader();
            string viaPe = Walk(md, pe);

            // The same metadata read directly from its bytes must look the same.
            byte[] block = pe.GetMetadata().GetContent().ToArray();
            unsafe
            {
                fixed (byte* p = block)
                {
                    var direct = new MetadataReader(p, block.Length);
                    string viaBlock = Walk(direct, null);
                    Check.That(viaBlock == viaPe, $"MetadataReader over the metadata block differs from PEReader's: {viaBlock} vs {viaPe}");
                }
            }
        }
        catch (BadImageFormatException)
        {
        }
    }

    private static void Headers(PEReader pe)
    {
        PEHeaders headers = pe.PEHeaders;
        _ = (headers.IsDll, headers.IsExe, headers.IsConsoleApplication, headers.MetadataSize, headers.MetadataStartOffset, headers.CorHeaderStartOffset);
        foreach (SectionHeader section in headers.SectionHeaders.Take(MaxItems))
        {
            _ = (section.Name, section.VirtualAddress, section.SizeOfRawData);
            PEMemoryBlock block = pe.GetSectionData(section.VirtualAddress);
            _ = block.Length;
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
    private static string Walk(MetadataReader md, PEReader pe)
    {
        var provider = new StringProvider();
        var summary = new System.Text.StringBuilder();
        summary.Append($"{md.MetadataKind} {md.MetadataVersion} types={md.TypeDefinitions.Count} methods={md.MethodDefinitions.Count} fields={md.FieldDefinitions.Count} ");
        if (md.IsAssembly)
        {
            AssemblyDefinition assembly = md.GetAssemblyDefinition();
            summary.Append($"{md.GetString(assembly.Name)} {assembly.Version} ");
            _ = assembly.GetAssemblyName();
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

                if (pe is not null && method.RelativeVirtualAddress != 0)
                {
                    MethodBodyBlock body = pe.GetMethodBody(method.RelativeVirtualAddress);
                    summary.Append(body.Size).Append(':').Append(body.MaxStack).Append(':').Append(body.ExceptionRegions.Length).Append(';');
                    _ = body.GetILBytes()?.Length;
                    if (!body.LocalSignature.IsNil)
                    {
                        _ = md.GetStandaloneSignature(body.LocalSignature).DecodeLocalSignature(provider, null).Length;
                    }
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
