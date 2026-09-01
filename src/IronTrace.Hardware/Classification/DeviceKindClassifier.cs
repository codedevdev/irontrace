using IronTrace.Contracts.Enums;

namespace IronTrace.Hardware.Classification;

public sealed record DeviceKindClassification(DeviceKind Kind, string? Reason);

public static class DeviceKindClassifier
{
    private static readonly string[] VirtualServices =
    [
        "vmbus", "netvsc", "vmswitch", "vmicheartbeat", "vmicshutdown", "vmicexchange",
        "vboxnet", "vboxnetadp", "vboxnetflt", "vmnetadapter", "vmxnet", "vmxnet3",
        "wireguard", "wintun", "tap0901", "tap0801", "npcap", "ndiswan", "rasl2tp",
        "softether", "nordvpn", "zerotier"
    ];

    private static readonly string[] VirtualIdPrefixes =
    [
        @"ROOT\", @"SWD\", @"UMB\", @"VMBUS\", @"HV_", @"VIRTUAL\"
    ];

    private static readonly string[] VirtualHints =
    [
        "hyper-v", "vpn", "tap-windows", "wintun", "wireguard",
        "vmware", "virtualbox", "parallels", "npcap", "loopback", "softether",
        "cisco anyconnect", "nordlynx", "zerotier", "vmbus", "netvsc"
    ];

    /// <summary>
    /// Marketing word "virtual" alone is not enough — requires service/prefix/strong hint.
    /// </summary>
    public static DeviceKindClassification Classify(
        string? instanceId,
        string? service,
        string? description,
        string? friendlyName,
        string? manufacturer,
        IReadOnlyList<string>? hardwareIds)
    {
        if (!string.IsNullOrWhiteSpace(service))
        {
            var svc = service.Trim();
            foreach (var known in VirtualServices)
            {
                if (svc.Equals(known, StringComparison.OrdinalIgnoreCase) ||
                    svc.StartsWith(known, StringComparison.OrdinalIgnoreCase))
                {
                    return new DeviceKindClassification(DeviceKind.VirtualOrSoftware, $"service={svc}");
                }
            }
        }

        foreach (var id in EnumerateIds(instanceId, hardwareIds))
        {
            foreach (var prefix in VirtualIdPrefixes)
            {
                if (id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    return new DeviceKindClassification(DeviceKind.VirtualOrSoftware, $"idPrefix={prefix.TrimEnd('\\')}");
                }
            }
        }

        var blob = string.Join(' ',
            description,
            friendlyName,
            manufacturer,
            service,
            string.Join(' ', hardwareIds ?? Array.Empty<string>())).ToLowerInvariant();

        foreach (var hint in VirtualHints)
        {
            if (blob.Contains(hint, StringComparison.Ordinal))
            {
                return new DeviceKindClassification(DeviceKind.VirtualOrSoftware, $"hint={hint}");
            }
        }

        // Ambiguous marketing "virtual" without corroboration → Physical (avoid FP)
        return new DeviceKindClassification(DeviceKind.Physical, null);
    }

    private static IEnumerable<string> EnumerateIds(string? instanceId, IReadOnlyList<string>? hardwareIds)
    {
        if (!string.IsNullOrWhiteSpace(instanceId))
        {
            yield return instanceId;
        }

        if (hardwareIds is null)
        {
            yield break;
        }

        foreach (var id in hardwareIds)
        {
            if (!string.IsNullOrWhiteSpace(id))
            {
                yield return id;
            }
        }
    }
}
