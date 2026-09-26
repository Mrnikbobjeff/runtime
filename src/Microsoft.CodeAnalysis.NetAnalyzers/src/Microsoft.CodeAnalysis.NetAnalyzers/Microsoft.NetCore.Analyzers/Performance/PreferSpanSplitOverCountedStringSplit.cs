// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Analyzer.Utilities;
using Analyzer.Utilities.Extensions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Microsoft.NetCore.Analyzers.Performance
{
    using static MicrosoftNetCoreAnalyzersResources;

    /// <summary>
    /// CA1881: <inheritdoc cref="PreferSpanSplitOverCountedStringSplitTitle"/>
    /// </summary>
    /// <remarks>
    /// Only calls that pass a count are reported: the length of the <c>Span&lt;Range&gt;</c> destination
    /// plays the role of the count, so the span-based overloads are an exact analogue.
    /// </remarks>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class PreferSpanSplitOverCountedStringSplitAnalyzer : DiagnosticAnalyzer
    {
        internal const string RuleId = "CA1881";

        private const string SplitMethodName = "Split";
        private const string SplitAnyMethodName = "SplitAny";

        internal static readonly DiagnosticDescriptor Rule = DiagnosticDescriptorHelper.Create(
            RuleId,
            CreateLocalizableResourceString(nameof(PreferSpanSplitOverCountedStringSplitTitle)),
            CreateLocalizableResourceString(nameof(PreferSpanSplitOverCountedStringSplitMessage)),
            DiagnosticCategory.Performance,
            RuleLevel.IdeSuggestion,
            description: CreateLocalizableResourceString(nameof(PreferSpanSplitOverCountedStringSplitDescription)),
            isPortedFxCopRule: false,
            isDataflowRule: false);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } = ImmutableArray.Create(Rule);

        public override void Initialize(AnalysisContext context)
        {
            context.EnableConcurrentExecution();
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.RegisterCompilationStartAction(OnCompilationStart);
        }

        private static void OnCompilationStart(CompilationStartAnalysisContext context)
        {
            var compilation = context.Compilation;
            if (!compilation.TryGetOrCreateTypeByMetadataName(WellKnownTypeNames.SystemMemoryExtensions, out var memoryExtensionsType) ||
                !compilation.TryGetOrCreateTypeByMetadataName(WellKnownTypeNames.SystemReadOnlySpan1, out var readOnlySpanType) ||
                !compilation.TryGetOrCreateTypeByMetadataName(WellKnownTypeNames.SystemSpan1, out var spanType) ||
                !compilation.TryGetOrCreateTypeByMetadataName(WellKnownTypeNames.SystemRange, out var rangeType) ||
                !compilation.TryGetOrCreateTypeByMetadataName(WellKnownTypeNames.SystemStringSplitOptions, out var stringSplitOptionsType))
            {
                return;
            }

            var charType = compilation.GetSpecialType(SpecialType.System_Char);
            var intType = compilation.GetSpecialType(SpecialType.System_Int32);
            var stringType = compilation.GetSpecialType(SpecialType.System_String);
            var readOnlySpanOfChar = readOnlySpanType.Construct(charType);
            var readOnlySpanOfString = readOnlySpanType.Construct(stringType);
            var spanOfRange = spanType.Construct(rangeType);

            // Look up the span-based analogues: MemoryExtensions.Split/SplitAny(ReadOnlySpan<char>, Span<Range>, <separator>, StringSplitOptions).
            bool hasSplitChar = HasSpanSplitMethod(SplitMethodName, charType);
            bool hasSplitSpan = HasSpanSplitMethod(SplitMethodName, readOnlySpanOfChar);
            bool hasSplitAnyChars = HasSpanSplitMethod(SplitAnyMethodName, readOnlySpanOfChar);
            bool hasSplitAnyStrings = HasSpanSplitMethod(SplitAnyMethodName, readOnlySpanOfString);

            // Map each counted string.Split overload to the name of its span-based analogue.
            var builder = ImmutableDictionary.CreateBuilder<IMethodSymbol, string>(SymbolEqualityComparer.Default);
            foreach (var method in stringType.GetMembers(SplitMethodName).OfType<IMethodSymbol>())
            {
                if (method.IsStatic || method.Parameters.Length is not (2 or 3))
                {
                    continue;
                }

                var parameters = method.Parameters;
                if (!SymbolEqualityComparer.Default.Equals(parameters[1].Type, intType) ||
                    (parameters.Length == 3 && !SymbolEqualityComparer.Default.Equals(parameters[2].Type, stringSplitOptionsType)))
                {
                    continue;
                }

                var separatorType = parameters[0].Type;
                string? replacement = separatorType switch
                {
                    // string.Split(char, int, StringSplitOptions) => MemoryExtensions.Split(..., char, ...)
                    _ when SymbolEqualityComparer.Default.Equals(separatorType, charType) => hasSplitChar ? SplitMethodName : null,
                    // string.Split(string, int, StringSplitOptions) => MemoryExtensions.Split(..., ReadOnlySpan<char>, ...)
                    _ when SymbolEqualityComparer.Default.Equals(separatorType, stringType) => hasSplitSpan ? SplitMethodName : null,
                    // string.Split(char[], int[, StringSplitOptions]) => MemoryExtensions.SplitAny(..., ReadOnlySpan<char>, ...)
                    IArrayTypeSymbol { Rank: 1, ElementType.SpecialType: SpecialType.System_Char } => hasSplitAnyChars ? SplitAnyMethodName : null,
                    // string.Split(string[], int, StringSplitOptions) => MemoryExtensions.SplitAny(..., ReadOnlySpan<string>, ...)
                    IArrayTypeSymbol { Rank: 1, ElementType.SpecialType: SpecialType.System_String } => hasSplitAnyStrings ? SplitAnyMethodName : null,
                    _ => null,
                };

                if (replacement is not null)
                {
                    builder.Add(method, replacement);
                }
            }

            if (builder.Count == 0)
            {
                return;
            }

            var countedSplitMethods = builder.ToImmutable();
            var linqExpressionType = compilation.GetOrCreateTypeByMetadataName(WellKnownTypeNames.SystemLinqExpressionsExpression1);

            context.RegisterOperationAction(context =>
            {
                var invocation = (IInvocationOperation)context.Operation;
                if (!countedSplitMethods.TryGetValue(invocation.TargetMethod, out var replacement))
                {
                    return;
                }

                // Spans can't be used in expression trees, nor (before C# 13) as locals in async methods or iterators.
                if (invocation.IsWithinExpressionTree(linqExpressionType) ||
                    IsInAsyncMethodOrIterator(invocation, context.ContainingSymbol))
                {
                    return;
                }

                context.ReportDiagnostic(invocation.CreateDiagnostic(Rule, replacement));
            }, OperationKind.Invocation);

            bool HasSpanSplitMethod(string name, ITypeSymbol separatorType)
            {
                foreach (var member in memoryExtensionsType.GetMembers(name))
                {
                    if (member is IMethodSymbol { IsStatic: true, IsGenericMethod: false, Parameters.Length: 4 } method &&
                        method.ReturnType.SpecialType == SpecialType.System_Int32 &&
                        SymbolEqualityComparer.Default.Equals(method.Parameters[0].Type, readOnlySpanOfChar) &&
                        SymbolEqualityComparer.Default.Equals(method.Parameters[1].Type, spanOfRange) &&
                        SymbolEqualityComparer.Default.Equals(method.Parameters[2].Type, separatorType) &&
                        SymbolEqualityComparer.Default.Equals(method.Parameters[3].Type, stringSplitOptionsType))
                    {
                        return true;
                    }
                }

                return false;
            }
        }

        private static bool IsInAsyncMethodOrIterator(IOperation operation, ISymbol containingSymbol)
        {
            IMethodSymbol? containingMethod;
            IOperation? body;
            if (operation.IsWithinLambdaOrLocalFunction(out var lambdaOrLocalFunction))
            {
                (containingMethod, body) = lambdaOrLocalFunction switch
                {
                    // Lambdas can't be iterators, so there is no body to search for 'yield'.
                    IAnonymousFunctionOperation anonymousFunction => (anonymousFunction.Symbol, null),
                    ILocalFunctionOperation localFunction => (localFunction.Symbol, localFunction),
                    _ => (null, null),
                };
            }
            else
            {
                containingMethod = containingSymbol as IMethodSymbol;
                body = operation.GetRoot();
            }

            if (containingMethod is null)
            {
                return false;
            }

            if (containingMethod.IsAsync)
            {
                return true;
            }

            // IMethodSymbol.IsIterator isn't available in the Roslyn version these analyzers build against,
            // so recognize a (synchronous) iterator by its return type and a 'yield' in its own body.
            return body is not null &&
                containingMethod.ReturnType.OriginalDefinition.SpecialType is
                    SpecialType.System_Collections_IEnumerable or
                    SpecialType.System_Collections_Generic_IEnumerable_T or
                    SpecialType.System_Collections_IEnumerator or
                    SpecialType.System_Collections_Generic_IEnumerator_T &&
                ContainsYield(body);
        }

        private static bool ContainsYield(IOperation body)
        {
            var stack = new Stack<IOperation>();
            stack.Push(body);
            while (stack.Count > 0)
            {
                foreach (var child in stack.Pop().ChildOperations)
                {
                    switch (child.Kind)
                    {
                        case OperationKind.YieldReturn or OperationKind.YieldBreak:
                            return true;

                        // A 'yield' in a nested function makes that function the iterator, not this one.
                        case OperationKind.AnonymousFunction or OperationKind.LocalFunction:
                            continue;

                        default:
                            stack.Push(child);
                            break;
                    }
                }
            }

            return false;
        }
    }
}
