using System.Globalization;
using System.Text.RegularExpressions;
using IronTrace.Contracts.Hardware;

namespace IronTrace.Hardware.Parsing;

public static partial class UsbHardwareIdParser
{
    [GeneratedRegex(
        @"USB\\VID_(?<vid>[0-9A-Fa-f]{4})&PID_(?<pid>[0-9A-Fa-f]{4})(?:&REV_(?<rev>[0-9A-Fa-f]{4}))?",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex HardwareIdRegex();

    public static UsbDeviceIdentity? ParseFirst(IEnumerable<string> ids)
    {
        foreach (var id in ids)
        {
            if (TryParse(id, out var identity))
            {
                return identity;
            }
        }

        return null;
    }

    public static bool TryParse(string? hardwareId, out UsbDeviceIdentity identity)
    {
        identity = default!;
        if (string.IsNullOrWhiteSpace(hardwareId))
        {
            return false;
        }

        var match = HardwareIdRegex().Match(hardwareId.Trim());
        if (!match.Success)
        {
            return false;
        }

        if (!ushort.TryParse(match.Groups["vid"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var vid) ||
            !ushort.TryParse(match.Groups["pid"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var pid))
        {
            return false;
        }

        ushort? rev = null;
        if (match.Groups["rev"].Success &&
            ushort.TryParse(match.Groups["rev"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var r))
        {
            rev = r;
        }

        identity = new UsbDeviceIdentity(vid, pid, rev);
        return true;
    }
}
