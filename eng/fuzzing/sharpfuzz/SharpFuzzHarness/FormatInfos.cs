using System.Globalization;

namespace SharpFuzzHarness;

/// <summary>
/// Builds NumberFormatInfo / DateTimeFormatInfo instances whose symbols and patterns come from
/// the fuzz input. The harness runs with invariant globalization, so this is how culture-specific
/// code paths (multi-char and non-ASCII separators, odd patterns, ...) get exercised.
/// </summary>
internal static class FormatInfos
{
    /// <summary>Invariant info, or (when <paramref name="custom"/>) a clone with fuzzed fields.</summary>
    public static NumberFormatInfo Number(ref FuzzInput input, bool custom)
    {
        if (!custom)
        {
            return NumberFormatInfo.InvariantInfo;
        }

        var nfi = (NumberFormatInfo)NumberFormatInfo.InvariantInfo.Clone();
        byte fields = input.Byte();
        byte patterns = input.Byte();
        byte groups = input.Byte();

        if ((fields & 0x01) != 0) { string s = input.Segment(); Try(() => nfi.NegativeSign = s); }
        if ((fields & 0x02) != 0) { string s = input.Segment(); Try(() => nfi.PositiveSign = s); }
        if ((fields & 0x04) != 0) { string s = input.Segment(); Try(() => nfi.NumberDecimalSeparator = s); }
        if ((fields & 0x08) != 0) { string s = input.Segment(); Try(() => nfi.NumberGroupSeparator = s); }
        if ((fields & 0x10) != 0) { string s = input.Segment(); Try(() => nfi.CurrencySymbol = s); }
        if ((fields & 0x20) != 0)
        {
            string s = input.Segment();
            Try(() => nfi.CurrencyDecimalSeparator = s);
            string t = input.Segment();
            Try(() => nfi.CurrencyGroupSeparator = t);
        }

        if ((fields & 0x40) != 0)
        {
            string s = input.Segment();
            Try(() => nfi.NaNSymbol = s);
            string t = input.Segment();
            Try(() => nfi.PositiveInfinitySymbol = t);
            string u = input.Segment();
            Try(() => nfi.NegativeInfinitySymbol = u);
        }

        if ((fields & 0x80) != 0)
        {
            string s = input.Segment();
            Try(() => nfi.PercentSymbol = s);
            string t = input.Segment();
            Try(() => nfi.PerMilleSymbol = t);
            string u = input.Segment();
            Try(() => nfi.PercentDecimalSeparator = u);
        }

        nfi.NumberNegativePattern = patterns % 5;
        nfi.CurrencyPositivePattern = (patterns >> 3) % 4;
        nfi.CurrencyNegativePattern = patterns % 17;
        nfi.PercentPositivePattern = (patterns >> 5) % 4;
        nfi.PercentNegativePattern = patterns % 12;
        nfi.NumberDecimalDigits = groups % 16;
        nfi.CurrencyDecimalDigits = (groups >> 4) % 8;

        if ((groups & 0x80) != 0)
        {
            int[] sizes = [input.Byte() % 10, input.Byte() % 10];
            Try(() => nfi.NumberGroupSizes = sizes);
            Try(() => nfi.CurrencyGroupSizes = sizes);
        }

        return NumberFormatInfo.ReadOnly(nfi);
    }

    /// <summary>Invariant info, or (when <paramref name="custom"/>) a clone with fuzzed fields.</summary>
    public static DateTimeFormatInfo DateTime(ref FuzzInput input, bool custom)
    {
        if (!custom)
        {
            return DateTimeFormatInfo.InvariantInfo;
        }

        var dtfi = (DateTimeFormatInfo)DateTimeFormatInfo.InvariantInfo.Clone();
        byte fields = input.Byte();
        byte more = input.Byte();

        if ((fields & 0x01) != 0)
        {
            string am = input.Segment(), pm = input.Segment();
            Try(() => dtfi.AMDesignator = am);
            Try(() => dtfi.PMDesignator = pm);
        }

        if ((fields & 0x02) != 0) { string s = input.Segment(); Try(() => dtfi.DateSeparator = s); }
        if ((fields & 0x04) != 0) { string s = input.Segment(); Try(() => dtfi.TimeSeparator = s); }
        if ((fields & 0x08) != 0)
        {
            string s = input.Segment(), l = input.Segment();
            Try(() => dtfi.ShortDatePattern = s);
            Try(() => dtfi.LongDatePattern = l);
        }

        if ((fields & 0x10) != 0)
        {
            string s = input.Segment(), l = input.Segment();
            Try(() => dtfi.ShortTimePattern = s);
            Try(() => dtfi.LongTimePattern = l);
        }

        if ((fields & 0x20) != 0)
        {
            string f = input.Segment(), m = input.Segment(), y = input.Segment();
            Try(() => dtfi.FullDateTimePattern = f);
            Try(() => dtfi.MonthDayPattern = m);
            Try(() => dtfi.YearMonthPattern = y);
        }

        // Names are given as one '|'-separated segment; missing entries keep their invariant value.
        if ((fields & 0x40) != 0)
        {
            string[] months = Names(input.Segment(), dtfi.MonthNames);
            string[] abbreviated = Names(input.Segment(), dtfi.AbbreviatedMonthNames);
            Try(() => dtfi.MonthNames = months);
            Try(() => dtfi.AbbreviatedMonthNames = abbreviated);
            Try(() => dtfi.MonthGenitiveNames = (more & 0x10) != 0 ? abbreviated : months);
        }

        if ((fields & 0x80) != 0)
        {
            string[] days = Names(input.Segment(), dtfi.DayNames);
            string[] abbreviated = Names(input.Segment(), dtfi.AbbreviatedDayNames);
            Try(() => dtfi.DayNames = days);
            Try(() => dtfi.AbbreviatedDayNames = abbreviated);
        }

        dtfi.FirstDayOfWeek = (DayOfWeek)(more % 7);
        dtfi.CalendarWeekRule = (CalendarWeekRule)((more >> 3) % 3);
        return DateTimeFormatInfo.ReadOnly(dtfi);
    }

    private static string[] Names(string segment, string[] defaults)
    {
        string[] names = (string[])defaults.Clone();
        string[] given = segment.Split('|');
        for (int i = 0; i < names.Length && i < given.Length; i++)
        {
            if (given[i].Length != 0)
            {
                names[i] = given[i];
            }
        }

        return names;
    }

    private static void Try(Action set)
    {
        try
        {
            set();
        }
        catch (ArgumentException)
        {
            // Rejected value (empty separator, bad group sizes, ...): keep the invariant one.
        }
    }
}
