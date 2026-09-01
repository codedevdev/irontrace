using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Hardware;

namespace IronTrace.Contracts.Reference;

public interface IUsbReferenceProvider
{
    string Name { get; }

    Task<UsbResolvedIdentity?> ResolveAsync(UsbDeviceIdentity identity, CancellationToken cancellationToken);

    Task<ReferenceDbInfo?> GetInfoAsync(CancellationToken cancellationToken);
}

public interface ILolDriversProvider
{
    string Name { get; }

    Task<VulnerableDriverMatch?> MatchBySha256Async(string sha256Hex, CancellationToken cancellationToken);

    Task<VulnerableDriverMatch?> MatchByFileNameAsync(string fileName, CancellationToken cancellationToken);

    Task<ReferenceDbInfo?> GetInfoAsync(CancellationToken cancellationToken);
}
