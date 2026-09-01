using IronTrace.Contracts.Driver;
using IronTrace.Contracts.Hardware;

namespace IronTrace.Windows.Driver;

public interface IIronTraceDriverClient : IDisposable
{
    KernelDriverAvailability TryOpen();

    IronTraceProtocolInfo? GetProtocolInfo();

    byte[]? ReadPciConfig(IronTraceBdf bdf, ushort offset, ushort length);

    IReadOnlyList<IronTraceCapabilityEntry> EnumerateCapabilities(IronTraceBdf bdf, ushort maxEntries = DriverProtocol.MaxCapabilityEntries);

    IronTraceQueryBarResponse? QueryBarLayout(IronTraceBdf bdf);

    IronTraceQueryExpressResponse? QueryExpressCaps(IronTraceBdf bdf);
}
