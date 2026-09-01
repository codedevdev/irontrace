using IronTrace.Contracts.Forensics;
using IronTrace.Forensics.Collectors;
using IronTrace.Forensics.Signatures;
using Microsoft.Extensions.DependencyInjection;

namespace IronTrace.Forensics.DependencyInjection;

public static class ForensicsServiceCollectionExtensions
{
    public static IServiceCollection AddIronTraceForensics(
        this IServiceCollection services,
        string? cheatSignaturesPath = null)
    {
        if (!string.IsNullOrWhiteSpace(cheatSignaturesPath))
        {
            services.AddSingleton<ICheatSignatureProvider>(sp =>
                new FileCheatSignatureProvider(
                    cheatSignaturesPath,
                    sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<FileCheatSignatureProvider>>()));
        }
        else
        {
            services.AddSingleton<ICheatSignatureProvider, FileCheatSignatureProvider>();
        }

        services.AddSingleton<ISignatureMatcher, SignatureMatcher>();
        services.AddSingleton<IExecutionArtifactsCollector, ExecutionArtifactsCollector>();
        services.AddSingleton<IProcessServiceCollector, ProcessServiceCollector>();
        services.AddSingleton<IPersistenceCollector, PersistenceCollector>();
        services.AddSingleton<IByovdDeepCollector, ByovdDeepCollector>();
        services.AddSingleton<IHwidForensicCollector, HwidForensicCollector>();
        services.AddSingleton<IMemoryIntegrityCollector, MemoryIntegrityCollector>();
        services.AddSingleton<IOverlayAuditCollector, OverlayAuditCollector>();
        services.AddSingleton<IAiVisionInputDeviceCollector, AiVisionInputDeviceCollector>();
        services.AddSingleton<IAnticheatContextCollector, AnticheatContextCollector>();
        services.AddSingleton<IForensicScanPipeline, ForensicScanPipeline>();
        return services;
    }
}
