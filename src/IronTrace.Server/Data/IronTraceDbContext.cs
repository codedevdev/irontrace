using Microsoft.EntityFrameworkCore;

namespace IronTrace.Server.Data;

public sealed class IronTraceDbContext : DbContext
{
    public IronTraceDbContext(DbContextOptions<IronTraceDbContext> options) : base(options)
    {
    }

    public DbSet<ApiKeyEntity> ApiKeys => Set<ApiKeyEntity>();
    public DbSet<ChallengeEntity> Challenges => Set<ChallengeEntity>();
    public DbSet<ScanSubmissionEntity> Scans => Set<ScanSubmissionEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ApiKeyEntity>(e =>
        {
            e.ToTable("api_keys");
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.KeyHash).IsUnique();
            e.HasIndex(x => x.KeyPrefix);
            e.Property(x => x.Name).HasMaxLength(128).IsRequired();
            e.Property(x => x.KeyPrefix).HasMaxLength(32).IsRequired();
            e.Property(x => x.KeyHash).HasMaxLength(64).IsRequired();
        });

        modelBuilder.Entity<ChallengeEntity>(e =>
        {
            e.ToTable("challenges");
            e.HasKey(x => x.SessionId);
            e.HasIndex(x => x.Nonce);
            e.Property(x => x.Nonce).HasMaxLength(128).IsRequired();
        });

        modelBuilder.Entity<ScanSubmissionEntity>(e =>
        {
            e.ToTable("scan_submissions");
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.SessionId).IsUnique();
            e.HasIndex(x => x.ReceivedAt);
            e.HasIndex(x => x.ReviewStatus);
            e.Property(x => x.ReportSchemaVersion).HasMaxLength(32).IsRequired();
            e.Property(x => x.ApplicationVersion).HasMaxLength(32).IsRequired();
            e.Property(x => x.Verdict).HasMaxLength(64);
            e.Property(x => x.HostMachineNameHash).HasMaxLength(128);
            e.Property(x => x.PayloadJson).IsRequired();
        });
    }
}
