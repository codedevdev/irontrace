using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Forensics;
using IronTrace.Contracts.Scanning;
using IronTrace.Forensics.Signatures;
using Microsoft.Extensions.Logging;

namespace IronTrace.Forensics.Collectors;

public interface IAiVisionInputDeviceCollector
{
    Task<AiVisionInputDeviceSnapshot> CollectAsync(
        ScanProfile profile,
        ExecutionArtifactsSnapshot? execution,
        ProcessServiceSnapshot? processService,
        CancellationToken cancellationToken);
}

public sealed class AiVisionInputDeviceCollector : IAiVisionInputDeviceCollector
{
    private readonly ISignatureMatcher _matcher;
    private readonly ILogger<AiVisionInputDeviceCollector> _logger;

    private static readonly string[] AiFilePatterns = [".onnx", ".pt", ".pth"];
    private static readonly string[] AiPythonMarkers = ["ultralytics", "torch", "pyautogui", "mss", "opencv"];
    private static readonly string[] ArduinoMarkers = [".ino", "keyboard.h", "hid"];

    public AiVisionInputDeviceCollector(ISignatureMatcher matcher, ILogger<AiVisionInputDeviceCollector> logger)
    {
        _matcher = matcher;
        _logger = logger;
    }

    public Task<AiVisionInputDeviceSnapshot> CollectAsync(
        ScanProfile profile,
        ExecutionArtifactsSnapshot? execution,
        ProcessServiceSnapshot? processService,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var inputHits = new List<SignatureMatchHit>();
        var consoleHits = new List<SignatureMatchHit>();
        var aiSignals = new List<AiVisionSignal>();

        if (execution is not null)
        {
            foreach (var hit in execution.Hits)
            {
                if (hit.Category.Equals("input_devices", StringComparison.OrdinalIgnoreCase))
                    inputHits.Add(hit);
                if (profile == ScanProfile.SelfAuditConsoleRig &&
                    hit.Category.Equals("console_rig", StringComparison.OrdinalIgnoreCase))
                    consoleHits.Add(hit);
            }
        }

        if (processService is not null)
        {
            inputHits.AddRange(processService.ProcessKeywordHits
                .Where(h => h.Category.Equals("input_devices", StringComparison.OrdinalIgnoreCase)));
        }

        try
        {
            ScanAiVisionFiles(aiSignals, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "AI vision file scan failed");
        }

        return Task.FromResult(new AiVisionInputDeviceSnapshot(
            ForensicAvailability.Available,
            $"InputHits={inputHits.Count}, AiSignals={aiSignals.Count}",
            inputHits,
            aiSignals,
            consoleHits));
    }

    private void ScanAiVisionFiles(List<AiVisionSignal> signals, CancellationToken ct)
    {
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads")
        };

        var onnxFound = false;
        var pythonMarkers = 0;
        var arduinoFound = false;

        foreach (var root in roots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(root))
                continue;

            foreach (var file in Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                if (signals.Count >= 50)
                    break;

                var ext = Path.GetExtension(file).ToLowerInvariant();
                var name = Path.GetFileName(file).ToLowerInvariant();

                if (AiFilePatterns.Contains(ext))
                {
                    if (ext == ".onnx")
                        onnxFound = true;
                    signals.Add(new AiVisionSignal(
                        "model_file",
                        ForensicHashHelper.HashText(file),
                        $"Model file: {Path.GetFileName(file)}",
                        FindingSeverity.Information));
                }

                if (AiPythonMarkers.Any(m => name.Contains(m, StringComparison.OrdinalIgnoreCase)))
                    pythonMarkers++;

                if (ArduinoMarkers.Any(m => name.Contains(m, StringComparison.OrdinalIgnoreCase)))
                    arduinoFound = true;

                var brandHits = _matcher.MatchFileName(name, "AiVisionFile");
                foreach (var hit in brandHits.Where(h => h.Category.Equals("ai_vision", StringComparison.OrdinalIgnoreCase)))
                {
                    signals.Add(new AiVisionSignal(
                        "brand_exe",
                        ForensicHashHelper.HashText(file),
                        hit.Keyword,
                        hit.EffectiveSeverity));
                }
            }
        }

        if (onnxFound && pythonMarkers >= 3)
        {
            signals.Add(new AiVisionSignal(
                "ai_stack_combo",
                ForensicHashHelper.HashText("onnx+python"),
                "ONNX model with multiple aimbot-typical Python libraries nearby.",
                FindingSeverity.Medium));
        }

        if (onnxFound && arduinoFound)
        {
            signals.Add(new AiVisionSignal(
                "ai_arduino_combo",
                ForensicHashHelper.HashText("onnx+arduino"),
                "ONNX model with Arduino/HID sketch nearby.",
                FindingSeverity.High));
        }
    }
}

public interface IAnticheatContextCollector
{
    Task<AnticheatContextSnapshot> CollectAsync(CancellationToken cancellationToken);
}

public sealed class AnticheatContextCollector : IAnticheatContextCollector
{
    private readonly ISignatureMatcher _matcher;

    public AnticheatContextCollector(ISignatureMatcher matcher)
    {
        _matcher = matcher;
    }

    public Task<AnticheatContextSnapshot> CollectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var products = new List<AnticheatProductEntry>();

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        foreach (var root in new[] { programFiles, programFilesX86 })
        {
            if (!Directory.Exists(root))
                continue;

            foreach (var dir in Directory.EnumerateDirectories(root))
            {
                var name = Path.GetFileName(dir);
                var hits = _matcher.Match(name, "InstalledSoftware")
                    .Where(h => h.Category.Equals("anticheat_products", StringComparison.OrdinalIgnoreCase));
                foreach (var hit in hits)
                {
                    products.Add(new AnticheatProductEntry(
                        hit.Keyword,
                        "InstalledSoftware",
                        name));
                }
            }
        }

        foreach (var proc in System.Diagnostics.Process.GetProcesses())
        {
            try
            {
                var hits = _matcher.Match(proc.ProcessName, "RunningProcess")
                    .Where(h => h.Category.Equals("anticheat_products", StringComparison.OrdinalIgnoreCase));
                foreach (var hit in hits)
                {
                    products.Add(new AnticheatProductEntry(
                        hit.Keyword,
                        "RunningProcess",
                        proc.ProcessName));
                }
            }
            finally
            {
                proc.Dispose();
            }
        }

        return Task.FromResult(new AnticheatContextSnapshot(
            ForensicAvailability.Available,
            products.DistinctBy(p => p.Product + p.DetectionSource).ToList()));
    }
}
