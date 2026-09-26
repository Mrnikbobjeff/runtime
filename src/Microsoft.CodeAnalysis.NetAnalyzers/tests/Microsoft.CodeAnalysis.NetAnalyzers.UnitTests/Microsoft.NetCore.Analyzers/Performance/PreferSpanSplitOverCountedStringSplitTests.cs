// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Threading.Tasks;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Testing;
using VerifyCS = Test.Utilities.CSharpCodeFixVerifier<
    Microsoft.NetCore.Analyzers.Performance.PreferSpanSplitOverCountedStringSplitAnalyzer,
    Microsoft.CodeAnalysis.Testing.EmptyCodeFixProvider>;

namespace Microsoft.NetCore.Analyzers.Performance.UnitTests
{
    [TestClass]
    public class PreferSpanSplitOverCountedStringSplitTests
    {
        [TestMethod]
        [DataRow("s.Split(',', 2)", "Split")]
        [DataRow("s.Split(',', 2, StringSplitOptions.RemoveEmptyEntries)", "Split")]
        [DataRow("s.Split(new[] { ',', ';' }, 3)", "SplitAny")]
        [DataRow("s.Split(new[] { ',', ';' }, 3, StringSplitOptions.TrimEntries)", "SplitAny")]
        [DataRow("s.Split((char[])null, 3)", "SplitAny")]
        [DataRow("s.Split(\", \", 2, StringSplitOptions.None)", "Split")]
        [DataRow("s.Split(\", \", 2)", "Split")]
        [DataRow("s.Split(new[] { \", \", \"; \" }, 2, StringSplitOptions.None)", "SplitAny")]
        public async Task CountedSplit_Diagnostic(string call, string replacement)
        {
            // lang=C#-test
            string source = $$"""
                using System;

                class C
                {
                    string[] M(string s) => {|#0:{{call}}|};
                }
                """;

            await VerifyAsync(source, VerifyCS.Diagnostic().WithLocation(0).WithArguments(replacement));
        }

        [TestMethod]
        public async Task NonConstantCount_Diagnostic()
        {
            string source = """
                using System;

                class C
                {
                    void M(string s, int count)
                    {
                        var parts = [|s.Split(':', count)|];
                        Console.WriteLine(parts.Length);
                    }
                }
                """;

            await VerifyAsync(source);
        }

        [TestMethod]
        public async Task NamedAndReorderedArguments_Diagnostic()
        {
            string source = """
                using System;

                class C
                {
                    string[] M(string s) => [|s.Split(options: StringSplitOptions.None, count: 2, separator: '=')|];
                }
                """;

            await VerifyAsync(source);
        }

        [TestMethod]
        public async Task NestedInAnotherExpression_Diagnostic()
        {
            string source = """
                using System;

                class C
                {
                    void M(string s)
                    {
                        Console.WriteLine([|s.Split('=', 2)|][0]);
                        Console.WriteLine([|[|s.Split('=', 2)|][1].Split(',', 3)|].Length);
                    }
                }
                """;

            await VerifyAsync(source);
        }

        [TestMethod]
        public async Task LambdaAndNonAsyncLocalFunction_Diagnostic()
        {
            string source = """
                using System;
                using System.Threading.Tasks;

                class C
                {
                    async Task M(string s)
                    {
                        await Task.Yield();
                        Func<string, string[]> f = x => [|x.Split(',', 2)|];
                        Console.WriteLine(Local(s).Length + f(s).Length);

                        static string[] Local(string x) => [|x.Split(',', 2)|];
                    }
                }
                """;

            await VerifyAsync(source);
        }

        [TestMethod]
        [DataRow("s.Split(',')")]
        [DataRow("s.Split(',', ';')")]
        [DataRow("s.Split(new[] { ',', ';' })")]
        [DataRow("s.Split(',', StringSplitOptions.RemoveEmptyEntries)")]
        [DataRow("s.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries)")]
        [DataRow("s.Split(\", \")")]
        [DataRow("s.Split(\", \", StringSplitOptions.None)")]
        [DataRow("s.Split(new[] { \", \" }, StringSplitOptions.None)")]
        public async Task UncountedSplit_NoDiagnostic(string call)
        {
            // lang=C#-test
            string source = $$"""
                using System;

                class C
                {
                    string[] M(string s) => {{call}};
                }
                """;

            await VerifyAsync(source);
        }

        [TestMethod]
        public async Task SpanSplitNotAvailable_NoDiagnostic()
        {
            string source = """
                using System;

                class C
                {
                    string[] M(string s) => s.Split(',', 2, StringSplitOptions.None);
                }
                """;

            await new VerifyCS.Test
            {
                ReferenceAssemblies = ReferenceAssemblies.Net.Net70,
                LanguageVersion = LanguageVersion.CSharp11,
                TestCode = source,
            }.RunAsync();
        }

        [TestMethod]
        public async Task ExpressionTree_NoDiagnostic()
        {
            string source = """
                using System;
                using System.Linq.Expressions;

                class C
                {
                    Expression<Func<string, string[]>> M() => s => s.Split(',', 2, StringSplitOptions.None);
                }
                """;

            await VerifyAsync(source);
        }

        [TestMethod]
        public async Task AsyncMethod_NoDiagnostic()
        {
            string source = """
                using System.Threading.Tasks;

                class C
                {
                    async Task<string> M(string s)
                    {
                        await Task.Yield();
                        return s.Split(',', 2)[0];
                    }
                }
                """;

            await VerifyAsync(source);
        }

        [TestMethod]
        public async Task AsyncLambdaAndLocalFunction_NoDiagnostic()
        {
            string source = """
                using System;
                using System.Threading.Tasks;

                class C
                {
                    void M(string s)
                    {
                        Func<Task<int>> f = async () =>
                        {
                            await Task.Yield();
                            return s.Split(',', 2).Length;
                        };

                        async Task<int> Local()
                        {
                            await Task.Yield();
                            return s.Split(',', 2).Length;
                        }

                        _ = f;
                        _ = Local();
                    }
                }
                """;

            await VerifyAsync(source);
        }

        [TestMethod]
        public async Task Iterator_NoDiagnostic()
        {
            string source = """
                using System.Collections.Generic;

                class C
                {
                    IEnumerable<string> M(string s)
                    {
                        yield return s.Split(',', 2)[0];
                    }
                }
                """;

            await VerifyAsync(source);
        }

        [TestMethod]
        public async Task OtherSplitMethods_NoDiagnostic()
        {
            string source = """
                using System.Text.RegularExpressions;

                class C
                {
                    string[] M(string s, Splitter splitter)
                    {
                        _ = splitter.Split(',', 2);
                        _ = s.Split(2, ',');
                        return Regex.Split(s, ",");
                    }
                }

                class Splitter
                {
                    public string[] Split(char separator, int count) => null;
                }

                static class StringExtensions
                {
                    public static string[] Split(this string s, int count, char separator) => null;
                }
                """;

            await VerifyAsync(source);
        }

        private static Task VerifyAsync(string source, params DiagnosticResult[] expected)
        {
            var test = new VerifyCS.Test
            {
                ReferenceAssemblies = ReferenceAssemblies.Net.Net80,
                LanguageVersion = LanguageVersion.CSharp12,
                TestCode = source,
            };

            test.ExpectedDiagnostics.AddRange(expected);
            return test.RunAsync();
        }
    }
}
