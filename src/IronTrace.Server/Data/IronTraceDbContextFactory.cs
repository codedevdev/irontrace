using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace IronTrace.Server.Data;

public sealed class IronTraceDbContextFactory : IDesignTimeDbContextFactory<IronTraceDbContext>
{
    public IronTraceDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<IronTraceDbContext>()
            .UseNpgsql("Host=localhost;Port=5432;Database=irontrace;Username=irontrace;Password=irontrace")
            .Options;
        return new IronTraceDbContext(options);
    }
}
