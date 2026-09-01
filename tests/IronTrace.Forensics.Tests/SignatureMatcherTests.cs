using FluentAssertions;
using IronTrace.Contracts.Enums;
using IronTrace.Forensics.Signatures;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IronTrace.Forensics.Tests;

public class SignatureMatcherTests
{
    [Fact]
    public void Match_FindsCheatBrandKeyword()
    {
        var db = new CheatSignatureDatabase(1, 180,
        [
            new CheatSignatureCategory("cheat_brands", FindingSeverity.Medium, FindingSeverity.High,
                ["engineowning"])
        ], [], []);

        var matcher = new SignatureMatcher(new InlineProvider(db));
        var hits = matcher.Match(@"C:\Users\x\Downloads\EngineOwning_setup.exe", "Prefetch");
        hits.Should().NotBeEmpty();
        hits[0].Category.Should().Be("cheat_brands");
    }

    [Fact]
    public void Match_DemotesOldArtifacts()
    {
        var db = new CheatSignatureDatabase(1, 180,
        [
            new CheatSignatureCategory("cheat_brands", FindingSeverity.Medium, FindingSeverity.High,
                ["engineowning"])
        ], [], []);

        var matcher = new SignatureMatcher(new InlineProvider(db));
        var old = DateTimeOffset.UtcNow.AddDays(-200);
        var hits = matcher.Match("engineowning.exe", "BAM", old);
        hits.Should().ContainSingle(h => h.RecencyDemoted && h.EffectiveSeverity == FindingSeverity.Medium);
    }

    private sealed class InlineProvider(CheatSignatureDatabase db) : ICheatSignatureProvider
    {
        public CheatSignatureDatabase Database { get; } = db;
    }
}
