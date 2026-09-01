using IronTrace.Contracts.Challenge;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Hardware;

namespace IronTrace.Core.Challenge;

/// <summary>
/// Usermode source of truth for safe-challenge policy. Never executes reset/FLR.
/// Critical deny list mirrors docs/architecture/DRIVER_BOUNDARY.md.
/// </summary>
public interface ISafeChallengePolicyEngine
{
    ChallengeEvidenceSnapshot Evaluate(
        IReadOnlyList<PciDevice> pciDevices,
        KernelEvidenceSnapshot? kernelEvidence);
}

public sealed class SafeChallengePolicyEngine : ISafeChallengePolicyEngine
{
    // PCIe base class codes (PCI Local Bus Spec).
    private const byte ClassMassStorage = 0x01;
    private const byte ClassNetwork = 0x02;
    private const byte ClassDisplay = 0x03;
    private const byte ClassMultimedia = 0x04;
    private const byte ClassBridge = 0x06;
    private const byte ClassInput = 0x09;
    private const byte ClassSerialBus = 0x0C;
    private const byte SubclassUsb = 0x03;

    public ChallengeEvidenceSnapshot Evaluate(
        IReadOnlyList<PciDevice> pciDevices,
        KernelEvidenceSnapshot? kernelEvidence)
    {
        var kernelByBdf = IndexKernel(kernelEvidence);
        var decisions = new List<ChallengeDeviceDecision>(pciDevices.Count);

        foreach (var device in pciDevices)
        {
            if (device.Kind == DeviceKind.VirtualOrSoftware)
            {
                decisions.Add(new ChallengeDeviceDecision(
                    device.Bus,
                    device.DeviceNumber,
                    device.Function,
                    device.Identity.ClassCode,
                    device.Identity.Subclass,
                    ChallengePolicyDecision.DenyDefault,
                    "VirtualOrSoftware device — challenge not applicable.",
                    SupportsFlr: null));
                continue;
            }

            var classCode = device.Identity.ClassCode;
            var subclass = device.Identity.Subclass;
            bool? supportsFlr = null;

            if (TryGetKernel(device, kernelByBdf, out var ke))
            {
                classCode ??= ke.ConfigClassCode;
                subclass ??= ke.ConfigSubclass;
                supportsFlr = ke.Express?.SupportsFlr;
            }

            var (decision, reason) = Classify(classCode, subclass);
            decisions.Add(new ChallengeDeviceDecision(
                device.Bus,
                device.DeviceNumber,
                device.Function,
                classCode,
                subclass,
                decision,
                reason,
                supportsFlr));
        }

        return new ChallengeEvidenceSnapshot(
            CapabilityStatus.Partial,
            "Safe challenge policy evaluated; CapSafeDeviceReset unset — no reset/FLR executed.",
            decisions);
    }

    public static (ChallengePolicyDecision Decision, string Reason) Classify(byte? classCode, byte? subclass)
    {
        if (classCode is null)
        {
            return (ChallengePolicyDecision.Unsupported,
                "Class code unavailable — cannot classify for challenge.");
        }

        switch (classCode.Value)
        {
            case ClassMassStorage:
                return (ChallengePolicyDecision.DenyCritical,
                    "Mass storage (boot storage class) — critical deny list.");
            case ClassNetwork:
                return (ChallengePolicyDecision.DenyCritical,
                    "Network adapter — critical deny list.");
            case ClassDisplay:
                return (ChallengePolicyDecision.DenyCritical,
                    "Display/GPU — critical deny list.");
            case ClassBridge:
                return (ChallengePolicyDecision.DenyCritical,
                    "System bridge — critical deny list.");
            case ClassSerialBus when subclass == SubclassUsb:
                return (ChallengePolicyDecision.DenyCritical,
                    "USB host controller — critical deny list.");
            case ClassMultimedia:
                return (ChallengePolicyDecision.AllowListedEligible,
                    "Multimedia endpoint allow-listed; challenge execution not enabled (ExecutionNotEnabled).");
            case ClassInput:
                return (ChallengePolicyDecision.AllowListedEligible,
                    "Input device allow-listed; challenge execution not enabled (ExecutionNotEnabled).");
            default:
                return (ChallengePolicyDecision.DenyDefault,
                    "Default deny — not on Phase 5 allow-list.");
        }
    }

    private static Dictionary<(int Bus, int Dev, int Fn), KernelPciDeviceEvidence> IndexKernel(
        KernelEvidenceSnapshot? kernel)
    {
        var map = new Dictionary<(int, int, int), KernelPciDeviceEvidence>();
        if (kernel?.Devices is null)
            return map;

        foreach (var d in kernel.Devices)
            map[(d.Bus, d.Device, d.Function)] = d;

        return map;
    }

    private static bool TryGetKernel(
        PciDevice device,
        Dictionary<(int Bus, int Dev, int Fn), KernelPciDeviceEvidence> map,
        out KernelPciDeviceEvidence evidence)
    {
        evidence = null!;
        if (device.Bus is null || device.DeviceNumber is null || device.Function is null)
            return false;

        return map.TryGetValue(
            (device.Bus.Value, device.DeviceNumber.Value, device.Function.Value),
            out evidence!);
    }
}
