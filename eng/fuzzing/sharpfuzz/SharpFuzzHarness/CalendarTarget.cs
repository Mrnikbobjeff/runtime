#nullable disable warnings
using System.Globalization;

namespace SharpFuzzHarness;

/// <summary>Fuzzes the System.Globalization calendars (Hebrew, Hijri, UmAlQura, Persian, lunisolar, Japanese, ...).</summary>
/// <remarks>
/// Input layout:
///   byte 0     calendar; byte 1 Hijri adjustment / week rule
///   rest       instants within the calendar's supported range, and day / month offsets
/// Checks: a date's year / month / day / era convert back with ToDateTime; month and day are within
/// GetMonthsInYear / GetDaysInMonth; GetDayOfYear and GetDaysInYear agree with the month lengths;
/// GetDayOfWeek matches DateTime; AddDays matches DateTime.AddDays; AddMonths lands on the expected
/// calendar month with the day clamped; out-of-range results throw ArgumentOutOfRangeException.
/// </remarks>
public static class CalendarTarget
{
    private static readonly Func<Calendar>[] s_calendars =
    [
        () => new GregorianCalendar(),
        () => new GregorianCalendar(GregorianCalendarTypes.Arabic),
        () => new HebrewCalendar(),
        () => new HijriCalendar(),
        () => new UmAlQuraCalendar(),
        () => new JulianCalendar(),
        () => new PersianCalendar(),
        () => new ThaiBuddhistCalendar(),
        () => new ChineseLunisolarCalendar(),
        () => new JapaneseLunisolarCalendar(),
        // JapaneseCalendar, KoreanCalendar and TaiwanCalendar can't be constructed in invariant
        // globalization mode (the harness): their type initializers look up ja-JP / ko-KR / zh-TW.
        () => new KoreanLunisolarCalendar(),
        () => new TaiwanLunisolarCalendar(),
    ];

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        Calendar calendar = s_calendars[input.Byte() % s_calendars.Length]();
        byte settings = input.Byte();
        if (calendar is HijriCalendar hijri)
        {
            hijri.HijriAdjustment = settings % 5 - 2;
        }

        long min = calendar.MinSupportedDateTime.Ticks, max = calendar.MaxSupportedDateTime.Ticks;
        for (int i = 0; i < 4 && input.Remaining > 0; i++)
        {
            ulong r = (ulong)(uint)input.Int32() << 32 | (uint)input.Int32();
            long ticks = (input.Byte() % 4) switch
            {
                0 => min + (long)(r % 1000) * TimeSpan.TicksPerDay,
                1 => max - (long)(r % 1000) * TimeSpan.TicksPerDay,
                _ => min + (long)(r % (ulong)(max - min)),
            };
            ticks = Math.Clamp(ticks, min, max);
            var date = new DateTime(ticks - ticks % TimeSpan.TicksPerMillisecond);
            if (date.Ticks < min)
            {
                continue;
            }

            Check(calendar, date, (sbyte)input.Byte() * 37, (sbyte)input.Byte(), settings);
        }
    }

    private static void Check(Calendar cal, DateTime d, int days, int months, byte settings)
    {
        string what = $"{cal.GetType().Name}{(cal is HijriCalendar h ? $" (adjustment {h.HijriAdjustment})" : "")} {d:O}";
        // Known (CAL-HIJRI-1): with a HijriAdjustment, GetYear / GetMonth / GetDayOfMonth throw
        // ArgumentOutOfRangeException for supported dates near the ends of the range.
        var parts = Outcome<(int, int, int, int)>.Of(() => (cal.GetYear(d), cal.GetMonth(d), cal.GetDayOfMonth(d), cal.GetEra(d)),
            e => !s_reportKnownIssues && e is ArgumentOutOfRangeException && cal is HijriCalendar { HijriAdjustment: not 0 });
        if (!parts.Ok)
        {
            return;
        }

        (int year, int month, int day, int era) = parts.Value;
        what += $" = {year}/{month}/{day} era {era}";
        // Known (CAL-YEAR-1): near the ends of their range some calendars return a year from GetYear that
        // their own GetMonthsInYear rejects; (CAL-LUNI-1) KoreanLunisolarCalendar puts 952-12-25 and later
        // into month 13 of lunar year 952, which has 12 months.
        var months12 = Outcome<int>.Of(() => cal.GetMonthsInYear(year, era), e => !s_reportKnownIssues && e is ArgumentOutOfRangeException);
        if (!months12.Ok)
        {
            return;
        }

        int monthsInYear = months12.Value;
        if (!s_reportKnownIssues && month > monthsInYear && cal is EastAsianLunisolarCalendar)
        {
            return;
        }

        SharpFuzzHarness.Check.That(1 <= month && month <= monthsInYear, $"month outside 1..{monthsInYear}: {what}");
        int daysInMonth = cal.GetDaysInMonth(year, month, era);
        SharpFuzzHarness.Check.That(1 <= day && day <= daysInMonth, $"day outside 1..{daysInMonth}: {what}");

        DateTime back = cal.ToDateTime(year, month, day, d.Hour, d.Minute, d.Second, d.Millisecond, era);
        SharpFuzzHarness.Check.Equal(d, back, $"ToDateTime(year, month, day, ...) for {what}");
        SharpFuzzHarness.Check.Equal(d.DayOfWeek, cal.GetDayOfWeek(d), $"GetDayOfWeek for {what}");

        // Month lengths: the days before this month, and the year's total. (The last supported year can be
        // partial: Hijri 9666 supports four months although GetMonthsInYear says 12.)
        int before = 0, total = 0;
        bool partial = false;
        for (int m = 1; m <= monthsInYear; m++)
        {
            int mm = m;
            var monthLength = Outcome<int>.Of(() => cal.GetDaysInMonth(year, mm, era), e => e is ArgumentOutOfRangeException);
            if (!monthLength.Ok)
            {
                partial = true;
                break;
            }

            int length = monthLength.Value;
            SharpFuzzHarness.Check.That(length is >= 1 and <= 35, $"GetDaysInMonth({year}, {m}) = {length}: {what}");
            before += m < month ? length : 0;
            total += length;
        }

        SharpFuzzHarness.Check.Equal(before + day, cal.GetDayOfYear(d), $"GetDayOfYear for {what}");
        if (!partial)
        {
            SharpFuzzHarness.Check.Equal(total, cal.GetDaysInYear(year, era), $"GetDaysInYear({year}) vs month lengths for {what}");
        }
        _ = (cal.IsLeapYear(year, era), cal.IsLeapMonth(year, month, era), cal.IsLeapDay(year, month, day, era), cal.GetLeapMonth(year, era));
        // Known (CAL-WEEK-1): GetWeekOfYear looks at days before MinSupportedDateTime (or outside DateTime)
        // for dates near the ends of the range and throws ArgumentOutOfRangeException.
        var week = Outcome<int>.Of(() => cal.GetWeekOfYear(d, (CalendarWeekRule)(settings % 3), (DayOfWeek)(settings / 3 % 7)),
            e => !s_reportKnownIssues && e is ArgumentOutOfRangeException);
        SharpFuzzHarness.Check.That(!week.Ok || week.Value is >= 1 and <= 56, $"GetWeekOfYear = {week}: {what}");

        // AddDays is plain day arithmetic.
        var added = Outcome<DateTime>.Of(() => cal.AddDays(d, days), e => e is ArgumentOutOfRangeException or ArgumentException);
        var expected = Outcome<DateTime>.Of(() => d.AddDays(days), e => e is ArgumentOutOfRangeException);
        if (expected.Ok && expected.Value >= cal.MinSupportedDateTime && expected.Value <= cal.MaxSupportedDateTime)
        {
            SharpFuzzHarness.Check.That(added.Ok && added.Value == expected.Value, $"AddDays({days}) = {added}, expected {expected.Value:O}: {what}");
        }

        // AddMonths moves by calendar months (years have GetMonthsInYear months) and clamps the day.
        var moved = Outcome<DateTime>.Of(() => cal.AddMonths(d, months), e => e is ArgumentOutOfRangeException or ArgumentException);
        // Lunisolar AddMonths steps over leap months in ways this model doesn't follow.
        if (moved.Ok && cal.Eras.Length == 1 && cal is not EastAsianLunisolarCalendar)
        {
            try
            {
                ExpectMonths(cal, d, moved.Value, year, month, day, era, months, what);
            }
            catch (ArgumentOutOfRangeException)
            {
                // The model stepped outside the supported range.
            }
        }

        _ = Outcome<DateTime>.Of(() => cal.AddYears(d, months), e => e is ArgumentOutOfRangeException or ArgumentException);
        _ = Outcome<int>.Of(() => cal.ToFourDigitYear(year % 100), e => e is ArgumentOutOfRangeException);
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    private static void ExpectMonths(Calendar cal, DateTime d, DateTime moved, int year, int month, int day, int era, int months, string what)
    {
        {
            int y = year, m = month + months;
            while (m > cal.GetMonthsInYear(y, era))
            {
                m -= cal.GetMonthsInYear(y, era);
                y++;
            }

            while (m < 1)
            {
                y--;
                m += cal.GetMonthsInYear(y, era);
            }

            int dd = Math.Min(day, cal.GetDaysInMonth(y, m, era));
            string got = $"{cal.GetYear(moved)}/{cal.GetMonth(moved)}/{cal.GetDayOfMonth(moved)}";
            SharpFuzzHarness.Check.That(got == $"{y}/{m}/{dd}" && moved.TimeOfDay == d.TimeOfDay,
                $"AddMonths({months}) = {moved:O} ({got}), expected {y}/{m}/{dd}: {what}");
        }
    }
}
