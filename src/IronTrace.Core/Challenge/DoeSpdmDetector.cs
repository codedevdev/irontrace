using IronTrace.Contracts.Challenge;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Hardware;

namespace IronTrace.Core.Challenge;

/// <summary>
/// PCIe Data Object Exchange extended capability ID (PCI Express Base Spec).
/// </summary>
public static class DoeSpdmConstants
{
    public const ushort DoeExtendedCapabilityId = 0x002E;
}

public interface IDoeSpdmDetector
{
    SpdmEvidenceSnapshot Detect(KernelEvidenceSnapshot? kernelEvidence);
}

/// <summary>
/// Detection-only: flags DOE extended capability when kernel evidence enumerated it.
/// Does not run SPDM messages or libspdm.
/// </summary>
public sealed class DoeSpdmDetector : IDoeSpdmDetector
{
    public SpdmEvidenceSnapshot Detect(KernelEvidenceSnapshot? kernelEvidence)
    {
        if (kernelEvidence is null ||
            kernelEvidence.Availability is KernelDriverAvailability.Unavailable
                or KernelDriverAvailability.Unsupported)
        {
            return new SpdmEvidenceSnapshot(
                CapabilityStatus.Unknown,
                "Kernel capability enumeration unavailable — DOE/SPDM presence unknown (not suspicious).",
                Array.Empty<SpdmDeviceEvidence>());
        }

        var devices = new List<SpdmDeviceEvidence>();
        var anyDoe = false;

        foreach (var d in kernelEvidence.Devices)
        {
            var doe = d.Capabilities.Any(c =>
                c.IsExtended && c.CapabilityId == DoeSpdmConstants.DoeExtendedCapabilityId);
            if (doe)
                anyDoe = true;

            devices.Add(new SpdmDeviceEvidence(
                d.Bus,
                d.Device,
                d.Function,
                doe,
                SpdmStackStatus.NotIntegrated,
                doe
                    ? "DOE extended capability present; SPDM stack not integrated."
                    : "No DOE extended capability observed on this BDF."));
        }

        if (!anyDoe)
        {
            return new SpdmEvidenceSnapshot(
                CapabilityStatus.Unsupported,
                "No PCIe DOE (0x2E) capability observed. Consumer devices rarely expose SPDM; Unsupported ≠ suspicious.",
                devices);
        }

        return new SpdmEvidenceSnapshot(
            CapabilityStatus.Partial,
            "DOE capability detected on one or more devices; SPDM protocol stack not integrated in this release.",
            devices);
    }
}
