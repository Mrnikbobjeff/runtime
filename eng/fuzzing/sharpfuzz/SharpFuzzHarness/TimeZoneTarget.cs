#nullable disable warnings
using System.Globalization;
using System.Runtime.Serialization;

namespace SharpFuzzHarness;

/// <summary>Fuzzes TimeZoneInfo: FromSerializedString and conversions through custom adjustment rules.</summary>
/// <remarks>
/// Input layout:
///   byte 0     0x01: parse the rest as a serialized time zone; otherwise build a custom zone
///   custom     base offset, then up to 3 rules (date range, delta, base offset delta, two
///              transition times), then instants to convert
/// Checks: FromSerializedString only throws SerializationException / ArgumentException /
/// InvalidTimeZoneException, and a zone's ToSerializedString parses back to a zone with the same
/// rules; converting a UTC instant to local time and back gives the instant again (unless the local
/// time is ambiguous), the local time is never "invalid", GetUtcOffset matches the conversion, and
/// ConvertTime on DateTimeOffset agrees.
/// </remarks>
public static class TimeZoneTarget
{
    private static readonly long s_minTicks = DateTime.MinValue.AddDays(3).Ticks;
    private static readonly long s_maxTicks = DateTime.MaxValue.AddDays(-3).Ticks;

    public static void Run(ReadOnlySpan<byte> data)
    {
        var input = new FuzzInput(data);
        byte mode = input.Byte();
        TimeZoneInfo zone;
        string what;
        if ((mode & 1) != 0)
        {
            string text = input.Segment();
            what = $"FromSerializedString({Check.Show(text)})";
            try
            {
                zone = TimeZoneInfo.FromSerializedString(text);
            }
            catch (Exception e) when (e is SerializationException or ArgumentException or InvalidTimeZoneException)
            {
                return;
            }
        }
        else
        {
            zone = Custom(ref input, out what);
            if (zone is null)
            {
                return;
            }
        }

        string serialized = zone.ToSerializedString();
        what += $" -> {Check.Show(serialized)}";
        var again = Outcome<TimeZoneInfo>.Of(() => TimeZoneInfo.FromSerializedString(serialized), e => e is SerializationException or ArgumentException or InvalidTimeZoneException);
        Check.That(again.Ok, $"ToSerializedString doesn't parse back ({again}): {what}");
        Check.That(zone.HasSameRules(again.Value) && again.Value.Id == zone.Id && again.Value.BaseUtcOffset == zone.BaseUtcOffset,
            $"ToSerializedString parses back to a different zone: {what}");
        Check.Equal(serialized, again.Value.ToSerializedString(), $"serializing again: {what}");

        for (int i = 0; i < 6 && input.Remaining > 0; i++)
        {
            long ticks = s_minTicks + (long)(((ulong)(uint)input.Int32() << 32 | (uint)input.Int32()) % (ulong)(s_maxTicks - s_minTicks));
            if (i % 2 == 1)
            {
                ticks -= ticks % TimeSpan.TicksPerHour; // near transitions, which are usually on the hour
                ticks += (input.Byte() - 128) * TimeSpan.TicksPerMinute;
            }

            try
            {
                Convert(zone, new DateTime(ticks, DateTimeKind.Utc), what);
            }
            catch (Exception e) when (e is not ConsistencyException && Report(e, $"{new DateTime(ticks):O} in {what}"))
            {
            }
        }
    }

    private static readonly bool s_reportKnownIssues = Environment.GetEnvironmentVariable("SHARPFUZZ_REPORT_KNOWN_ISSUES") is not null;

    /// <summary>Prints the context of an unexpected exception (for --repro) and lets it propagate, unless it's a known issue.</summary>
    private static bool Report(Exception e, string what)
    {
        // Known (TZ-RULE-1, .NET 11 regression): FindRuleForYear adds the zone's offset to the previous
        // rule's DateEnd, which underflows for a rule ending 0001-01-01 under a negative offset.
        // Known (TZ-DTO-1): CreateCustomTimeZone / FromSerializedString accept rules whose
        // BaseUtcOffsetDelta takes the offset past +-14 hours, which ConvertTime(DateTimeOffset) can't represent.
        string trace = e.StackTrace ?? "";
        if (!s_reportKnownIssues && e is ArgumentOutOfRangeException &&
            (trace.Contains("FindRuleForYear", StringComparison.Ordinal) || trace.Contains("ValidateOffset", StringComparison.Ordinal)))
        {
            return true;
        }

        Console.Error.WriteLine($"{e.GetType().Name} converting {what}");
        return false;
    }

    private static void Convert(TimeZoneInfo zone, DateTime utc, string what)
    {
        what = $"{utc:O} in {what}";
        TimeSpan offset = zone.GetUtcOffset(utc);
        DateTime local = TimeZoneInfo.ConvertTimeFromUtc(utc, zone);
        Check.Equal(offset, local - utc, $"ConvertTimeFromUtc {local:O} vs GetUtcOffset {offset}: {what}");
        Check.Equal(offset, zone.GetUtcOffset(new DateTimeOffset(utc)), $"GetUtcOffset(DateTimeOffset): {what}");
        DateTimeOffset converted = TimeZoneInfo.ConvertTime(new DateTimeOffset(utc), zone);
        Check.That(converted.Offset == offset && converted.UtcDateTime == utc, $"ConvertTime(DateTimeOffset) = {converted:O}: {what}");

        bool invalid = zone.IsInvalidTime(local);
        Check.That(!invalid, $"local time {local:O} (offset {offset}) of a real instant is IsInvalidTime: {what}");
        bool ambiguous = zone.IsAmbiguousTime(local);
        if (ambiguous)
        {
            TimeSpan[] offsets = zone.GetAmbiguousTimeOffsets(local);
            Check.That(offsets.Contains(offset), $"ambiguous local time {local:O}: offsets [{string.Join(", ", offsets)}] don't include {offset}: {what}");
        }
        else
        {
            DateTime back = TimeZoneInfo.ConvertTimeToUtc(local, zone);
            Check.Equal(utc, back, $"ConvertTimeToUtc(local {local:O}, offset {offset}): {what}");
            Check.Equal(offset, zone.GetUtcOffset(local), $"GetUtcOffset(local {local:O}): {what}");
        }

        _ = zone.IsDaylightSavingTime(utc);
        _ = zone.IsDaylightSavingTime(local);
    }

    private static TimeZoneInfo Custom(ref FuzzInput input, out string what)
    {
        var baseOffset = TimeSpan.FromMinutes((sbyte)input.Byte() * 7 % (14 * 60));
        var rules = new List<TimeZoneInfo.AdjustmentRule>();
        int count = input.Byte() % 4;
        what = $"custom zone {baseOffset}";
        for (int i = 0; i < count; i++)
        {
            int year = 1 + input.UInt16() % 9999;
            DateTime start = new DateTime(Math.Min(year, 9998), 1 + input.Byte() % 12, 1);
            DateTime end = new DateTime(Math.Min(start.Ticks + input.UInt16() % 20000 * TimeSpan.TicksPerDay, DateTime.MaxValue.Date.Ticks));
            TimeSpan delta = TimeSpan.FromMinutes((sbyte)input.Byte() * 5 % 14 * 30);
            TimeSpan baseDelta = TimeSpan.FromMinutes((sbyte)input.Byte() % 5 * 30);
            TimeZoneInfo.TransitionTime t1 = Transition(ref input), t2 = Transition(ref input);
            what += $" [{start:yyyy-MM-dd}..{end:yyyy-MM-dd} delta {delta} base {baseDelta} {Show(t1)} -> {Show(t2)}]";
            try
            {
                rules.Add(TimeZoneInfo.AdjustmentRule.CreateAdjustmentRule(start, end, delta, t1, t2, baseDelta));
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        try
        {
            return TimeZoneInfo.CreateCustomTimeZone("Fuzz/Zone", baseOffset, "Fuzz", "Fuzz Standard", "Fuzz Daylight", rules.ToArray());
        }
        catch (Exception e) when (e is ArgumentException or InvalidTimeZoneException)
        {
            return null;
        }
    }

    private static string Show(TimeZoneInfo.TransitionTime t) => t.IsFixedDateRule
        ? $"fixed {t.Month}/{t.Day} {t.TimeOfDay:HH:mm}"
        : $"floating {t.Month} week {t.Week} {t.DayOfWeek} {t.TimeOfDay:HH:mm}";

    private static TimeZoneInfo.TransitionTime Transition(ref FuzzInput input)
    {
        byte kind = input.Byte();
        var timeOfDay = new DateTime(1, 1, 1, input.Byte() % 24, (kind & 0x80) != 0 ? 30 : 0, 0);
        int month = 1 + input.Byte() % 12;
        return (kind & 1) != 0
            ? TimeZoneInfo.TransitionTime.CreateFixedDateRule(timeOfDay, month, 1 + kind / 2 % 31 % DateTime.DaysInMonth(2001, month))
            : TimeZoneInfo.TransitionTime.CreateFloatingDateRule(timeOfDay, month, 1 + kind / 2 % 5, (DayOfWeek)(kind / 16 % 7));
    }
}
