// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Text;
using Xunit;

namespace System.Tests
{
    internal static class NumberFormatTestHelper
    {
        private static readonly string[] s_shortestFormats = [null, "", "G", "g", "R", "r"];

        // The shortest round-trip formats take a direct writer when the signs are "+"/"-" and the decimal separator is
        // "."; any other separator takes the general NumberToString path. Checks that both agree apart from the separator,
        // for ToString and for UTF-16 and UTF-8 TryFormat (including destinations that are one element too short).
        internal static void VerifyShortestInvariantMatchesGeneralPath<T>(IEnumerable<T> values) where T : IFloatingPoint<T>
        {
            NumberFormatInfo general = (NumberFormatInfo)NumberFormatInfo.InvariantInfo.Clone();
            general.NumberDecimalSeparator = ",";

            foreach (T value in values)
            {
                if (!T.IsFinite(value))
                {
                    continue;
                }

                foreach (string format in s_shortestFormats)
                {
                    string expected = value.ToString(format, general).Replace(',', '.');
                    Assert.Equal(expected, value.ToString(format, CultureInfo.InvariantCulture));
                    TryFormatNumberTest(value, format, CultureInfo.InvariantCulture, expected, formatCasingMatchesOutput: false);
                }
            }
        }

        internal static void TryFormatNumberTest<T>(T i, string format, IFormatProvider provider, string expected, bool formatCasingMatchesOutput = true) where T : ISpanFormattable, IUtf8SpanFormattable
        {
            // UTF16
            {
                char[] actual;
                int charsWritten;

                // Just right and longer than needed
                for (int additional = 0; additional < 2; additional++)
                {
                    actual = new char[expected.Length + additional];
                    Assert.True(i.TryFormat(actual.AsSpan(), out charsWritten, format, provider));
                    Assert.Equal(expected.Length, charsWritten);
                    Assert.Equal(expected, new string(actual.AsSpan(0, charsWritten)));
                }

                // Too short
                if (expected.Length > 0)
                {
                    actual = new char[expected.Length - 1];
                    Assert.False(i.TryFormat(actual.AsSpan(), out charsWritten, format, provider));
                    Assert.Equal(0, charsWritten);
                }

                if (formatCasingMatchesOutput && format != null)
                {
                    // Upper format
                    actual = new char[expected.Length];
                    Assert.True(i.TryFormat(actual.AsSpan(), out charsWritten, format.ToUpperInvariant(), provider));
                    Assert.Equal(expected.Length, charsWritten);
                    Assert.Equal(expected.ToUpperInvariant(), new string(actual));

                    // Lower format
                    actual = new char[expected.Length];
                    Assert.True(i.TryFormat(actual.AsSpan(), out charsWritten, format.ToLowerInvariant(), provider));
                    Assert.Equal(expected.Length, charsWritten);
                    Assert.Equal(expected.ToLowerInvariant(), new string(actual));
                }
            }

            // UTF8
            {
                byte[] actual;
                int charsWritten;
                int expectedLength = Encoding.UTF8.GetByteCount(expected);

                // Just right and longer than needed
                for (int additional = 0; additional < 2; additional++)
                {
                    actual = new byte[expectedLength + additional];
                    Assert.True(i.TryFormat(actual.AsSpan(), out charsWritten, format, provider));
                    Assert.Equal(expectedLength, charsWritten);
                    Assert.Equal(expected, Encoding.UTF8.GetString(actual.AsSpan(0, charsWritten)));
                }

                // Too short
                if (expectedLength > 0)
                {
                    actual = new byte[expectedLength - 1];
                    Assert.False(i.TryFormat(actual.AsSpan(), out charsWritten, format, provider));
                    Assert.Equal(0, charsWritten);
                }

                if (formatCasingMatchesOutput && format != null)
                {
                    // Upper format
                    actual = new byte[expectedLength];
                    Assert.True(i.TryFormat(actual.AsSpan(), out charsWritten, format.ToUpperInvariant(), provider));
                    Assert.Equal(expectedLength, charsWritten);
                    Assert.Equal(expected.ToUpperInvariant(), Encoding.UTF8.GetString(actual.AsSpan(0, charsWritten)));

                    // Lower format
                    actual = new byte[expectedLength];
                    Assert.True(i.TryFormat(actual.AsSpan(), out charsWritten, format.ToLowerInvariant(), provider));
                    Assert.Equal(expectedLength, charsWritten);
                    Assert.Equal(expected.ToLowerInvariant(), Encoding.UTF8.GetString(actual.AsSpan(0, charsWritten)));
                }
            }
        }
    }
}
