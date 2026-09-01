using IronTrace.Contracts.Driver;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Hardware;
using IronTrace.Core.Scanning;
using Microsoft.Extensions.Logging;

namespace IronTrace.Windows.Driver;

public sealed class KernelEvidenceCollector : IKernelEvidenceCollector
{
    private static readonly string[] BarTypeNames = ["Unknown", "Io", "Memory32", "Memory64", "MemoryPrefetch"];

    private readonly IIronTraceDriverClient _client;
    private readonly ILogger<KernelEvidenceCollector> _logger;

    public KernelEvidenceCollector(
        IIronTraceDriverClient client,
        ILogger<KernelEvidenceCollector> logger)
    {
        _client = client;
        _logger = logger;
    }

    public Task<KernelEvidenceSnapshot> CollectAsync(
        IReadOnlyList<PciDevice> pciDevices,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var availability = _client.TryOpen();
        if (availability == KernelDriverAvailability.Unavailable)
        {
            return Task.FromResult(new KernelEvidenceSnapshot(
                KernelDriverAvailability.Unavailable,
                CapabilityStatus.Unsupported,
                null,
                null,
                null,
                "IronTrace.Driver is not installed or not accessible. Kernel PCI evidence was skipped.",
                Array.Empty<KernelPciDeviceEvidence>()));
        }

        if (availability == KernelDriverAvailability.Unsupported)
        {
            return Task.FromResult(new KernelEvidenceSnapshot(
                KernelDriverAvailability.Unsupported,
                CapabilityStatus.Unsupported,
                null,
                null,
                null,
                "IronTrace.Driver protocol version is incompatible with this client.",
                Array.Empty<KernelPciDeviceEvidence>()));
        }

        var info = _client.GetProtocolInfo();
        var devices = new List<KernelPciDeviceEvidence>();
        var anyPartial = availability == KernelDriverAvailability.Partial;

        foreach (var pci in pciDevices)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (pci.Bus is null || pci.DeviceNumber is null || pci.Function is null)
                continue;

            if (pci.Bus is < 0 or > 255 ||
                pci.DeviceNumber is < 0 or > 31 ||
                pci.Function is < 0 or > 7)
            {
                continue;
            }

            var bdf = new IronTraceBdf((byte)pci.Bus.Value, (byte)pci.DeviceNumber.Value, (byte)pci.Function.Value);
            try
            {
                devices.Add(CollectDevice(pci, bdf, ref anyPartial));
            }
            catch (Exception ex)
            {
                anyPartial = true;
                _logger.LogDebug(ex, "Kernel evidence failed for BDF {Bus:X2}:{Dev:X2}.{Fn}", bdf.Bus, bdf.Device, bdf.Function);
                devices.Add(new KernelPciDeviceEvidence(
                    pci.InstanceId,
                    bdf.Bus,
                    bdf.Device,
                    bdf.Function,
                    null, null, null, null, null, null,
                    Array.Empty<KernelPciCapability>(),
                    Array.Empty<KernelPciBar>(),
                    null,
                    ["Collection failed for this BDF; treated as unknown."]));
            }
        }

        var runtimeStatus = anyPartial ? CapabilityStatus.Partial : CapabilityStatus.Supported;
        var finalAvailability = anyPartial ? KernelDriverAvailability.Partial : KernelDriverAvailability.Available;

        return Task.FromResult(new KernelEvidenceSnapshot(
            finalAvailability,
            runtimeStatus,
            info?.ProtocolVersion,
            info?.CapabilityFlags,
            info?.MaxConfigReadLength,
            anyPartial
                ? "Kernel driver opened; some PCI evidence operations were incomplete."
                : "Kernel PCI evidence collected via IronTrace.Driver.",
            devices));
    }

    private KernelPciDeviceEvidence CollectDevice(PciDevice pci, IronTraceBdf bdf, ref bool anyPartial)
    {
        var notes = new List<string>();
        ushort? vend = null, dev = null;
        byte? rev = null, cls = null, sub = null, prog = null;

        var header = _client.ReadPciConfig(bdf, 0, 16);
        if (header is { Length: >= 16 })
        {
            vend = (ushort)(header[0] | (header[1] << 8));
            dev = (ushort)(header[2] | (header[3] << 8));
            rev = header[8];
            prog = header[9];
            sub = header[10];
            cls = header[11];
        }
        else
        {
            anyPartial = true;
            notes.Add("Config-space header read unavailable.");
        }

        var caps = _client.EnumerateCapabilities(bdf)
            .Select(c => new KernelPciCapability(c.CapabilityId, c.Offset, c.IsExtended != 0))
            .ToList();

        var bars = new List<KernelPciBar>();
        var barResp = _client.QueryBarLayout(bdf);
        if (barResp is null)
        {
            anyPartial = true;
            notes.Add("BAR layout query unavailable.");
        }
        else
        {
            foreach (var bar in EnumerateBars(barResp.Value))
            {
                var typeName = bar.BarType < BarTypeNames.Length ? BarTypeNames[bar.BarType] : "Unknown";
                bars.Add(new KernelPciBar(
                    bar.Index,
                    typeName,
                    bar.BaseAddress == 0 && bar.BarType == 0 ? null : bar.BaseAddress,
                    bar.Size == 0 ? null : bar.Size));
            }
        }

        KernelPciExpressCaps? express = null;
        var expressResp = _client.QueryExpressCaps(bdf);
        if (expressResp is null)
        {
            anyPartial = true;
            notes.Add("Express capability query unavailable.");
        }
        else
        {
            var f = expressResp.Value.Flags;
            express = new KernelPciExpressCaps(
                (f & DriverProtocol.ExpressHasPcie) != 0,
                (f & DriverProtocol.ExpressHasAer) != 0,
                (f & DriverProtocol.ExpressHasAcs) != 0,
                (f & DriverProtocol.ExpressHasAts) != 0,
                (f & DriverProtocol.ExpressHasSriov) != 0,
                (f & DriverProtocol.ExpressSupportsFlr) != 0,
                expressResp.Value.DeviceControl,
                expressResp.Value.LinkStatus,
                expressResp.Value.MaxPayloadSupported,
                expressResp.Value.MaxReadRequest);
        }

        string? dsnHex = null;
        var dsnCap = caps.FirstOrDefault(c => c.IsExtended && c.CapabilityId == 0x0003);
        if (dsnCap is not null)
        {
            // PCIe DSN extended capability: serial number at offset+4 (8 bytes).
            var dsnBytes = _client.ReadPciConfig(bdf, (ushort)(dsnCap.Offset + 4), 8);
            if (dsnBytes is { Length: >= 8 })
            {
                dsnHex = Convert.ToHexString(dsnBytes.AsSpan(0, 8)).ToLowerInvariant();
            }
            else
            {
                anyPartial = true;
                notes.Add("DSN extended capability present but read failed.");
            }
        }

        return new KernelPciDeviceEvidence(
            pci.InstanceId,
            bdf.Bus,
            bdf.Device,
            bdf.Function,
            vend,
            dev,
            rev,
            cls,
            sub,
            prog,
            caps,
            bars,
            express,
            notes,
            dsnHex);
    }

    private static IEnumerable<IronTraceBarInfo> EnumerateBars(IronTraceQueryBarResponse response)
    {
        var count = Math.Min(response.BarCount, (byte)DriverProtocol.MaxBars);
        if (count > 0) yield return response.Bar0;
        if (count > 1) yield return response.Bar1;
        if (count > 2) yield return response.Bar2;
        if (count > 3) yield return response.Bar3;
        if (count > 4) yield return response.Bar4;
        if (count > 5) yield return response.Bar5;
    }
}
