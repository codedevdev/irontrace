using System.Globalization;
using System.Text.RegularExpressions;
using IronTrace.Contracts.Hardware;

namespace IronTrace.Hardware.Parsing;

public static partial class PciHardwareIdParser
{
    [GeneratedRegex(
        @"PCI\\VEN_(?<ven>[0-9A-Fa-f]{4})(?:&DEV_(?<dev>[0-9A-Fa-f]{4}))?(?:&SUBSYS_(?<subsys>[0-9A-Fa-f]{8}))?(?:&REV_(?<rev>[0-9A-Fa-f]{2}))?",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex HardwareIdRegex();

    [GeneratedRegex(
        @"CC_(?<cc>[0-9A-Fa-f]{2})(?<sc>[0-9A-Fa-f]{2})(?<pi>[0-9A-Fa-f]{2})?",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex ClassCodeRegex();

    public static bool TryParse(string? hardwareId, out PciDeviceIdentity identity)
    {
        identity = default!;
        if (string.IsNullOrWhiteSpace(hardwareId))
        {
            return false;
        }

        var trimmed = hardwareId.Trim();
        var match = HardwareIdRegex().Match(trimmed);
        if (!match.Success || !match.Groups["ven"].Success || !match.Groups["dev"].Success)
        {
            return false;
        }

        // Reject truncated/malformed optional segments that the regex may skip.
        if (trimmed.Contains("&SUBSYS_", StringComparison.OrdinalIgnoreCase) && !match.Groups["subsys"].Success)
        {
            return false;
        }

        if (trimmed.Contains("&REV_", StringComparison.OrdinalIgnoreCase) && !match.Groups["rev"].Success)
        {
            return false;
        }

        if (!TryParseUShort(match.Groups["ven"].Value, out var vendorId) ||
            !TryParseUShort(match.Groups["dev"].Value, out var deviceId))
        {
            return false;
        }

        ushort? subVen = null;
        ushort? subDev = null;
        if (match.Groups["subsys"].Success)
        {
            var subsys = match.Groups["subsys"].Value;
            if (subsys.Length != 8 ||
                !TryParseUShort(subsys[..4], out var sd) ||
                !TryParseUShort(subsys[4..], out var sv))
            {
                return false;
            }

            // Windows SUBSYS is encoded as SSDD + SSVV (device then vendor) in many IDs:
            // SUBSYS_87D71043 => subdevice 87D7, subvendor 1043
            subDev = sd;
            subVen = sv;
        }

        byte? revision = null;
        if (match.Groups["rev"].Success)
        {
            if (!TryParseByte(match.Groups["rev"].Value, out var rev))
            {
                return false;
            }

            revision = rev;
        }

        identity = new PciDeviceIdentity(
            vendorId,
            deviceId,
            subVen,
            subDev,
            revision,
            ClassCode: null,
            Subclass: null,
            ProgrammingInterface: null);
        return true;
    }

    public static bool TryParseClassCode(string? compatibleOrHardwareId, out byte classCode, out byte? subclass, out byte? progIf)
    {
        classCode = 0;
        subclass = null;
        progIf = null;
        if (string.IsNullOrWhiteSpace(compatibleOrHardwareId))
        {
            return false;
        }

        var match = ClassCodeRegex().Match(compatibleOrHardwareId);
        if (!match.Success)
        {
            return false;
        }

        if (!TryParseByte(match.Groups["cc"].Value, out classCode))
        {
            return false;
        }

        if (match.Groups["sc"].Success && TryParseByte(match.Groups["sc"].Value, out var sc))
        {
            subclass = sc;
        }

        if (match.Groups["pi"].Success && match.Groups["pi"].Length > 0 &&
            TryParseByte(match.Groups["pi"].Value, out var pi))
        {
            progIf = pi;
        }

        return true;
    }

    public static PciDeviceIdentity? ParseFirst(IEnumerable<string> hardwareIds)
    {
        foreach (var id in hardwareIds)
        {
            if (TryParse(id, out var identity))
            {
                return identity;
            }
        }

        return null;
    }

    public static PciDeviceIdentity WithClass(PciDeviceIdentity identity, byte? classCode, byte? subclass, byte? progIf)
        => identity with
        {
            ClassCode = classCode,
            Subclass = subclass,
            ProgrammingInterface = progIf
        };

    private static bool TryParseUShort(string hex, out ushort value)
        => ushort.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);

    private static bool TryParseByte(string hex, out byte value)
        => byte.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
}
