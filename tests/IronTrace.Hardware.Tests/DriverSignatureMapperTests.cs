using FluentAssertions;
using IronTrace.Contracts.Enums;
using IronTrace.Hardware.Signing;

namespace IronTrace.Hardware.Tests;

public class DriverSignatureMapperTests
{
    [Fact]
    public void FromVerification_TrustedMicrosoft_IsMicrosoftSigned()
    {
        var info = DriverSignatureMapper.FromVerification(
            @"C:\Windows\System32\drivers\example.sys",
            embedded: null,
            new WinTrustResult(WinTrustStatus.Trusted, 0, ViaCatalog: true));

        // without cert, still AuthenticodeSigned/Catalog path — Microsoft detection needs subject
        info.Status.Should().Be(DriverSignatureStatus.CatalogSigned);
        info.AnalysisSummary.Should().ContainEquivalentOf("signed");
    }

    [Fact]
    public void FromVerification_Nosignature_IsUnsigned_WithSafeWording()
    {
        var info = DriverSignatureMapper.FromVerification(
            @"C:\temp\foo.sys",
            embedded: null,
            new WinTrustResult(WinTrustStatus.Unsigned, unchecked((int)0x800B0100), false));

        info.Status.Should().Be(DriverSignatureStatus.Unsigned);
        info.AnalysisSummary.Should().Contain("not prove malicious");
    }

    [Fact]
    public void ShortSubject_ExtractsCn()
    {
        DriverSignatureMapper.ShortSubject("CN=Contoso Driver Publishing, O=Contoso")
            .Should().Be("Contoso Driver Publishing");
    }

    [Theory]
    [InlineData("CN=Microsoft Windows", "CN=Microsoft Code Signing PCA", true)]
    [InlineData("CN=Acme Inc", "CN=DigiCert", false)]
    public void IsMicrosoftPublisher_DetectsMicrosoft(string subject, string issuer, bool expected)
    {
        DriverSignatureMapper.IsMicrosoftPublisher(subject, issuer).Should().Be(expected);
    }

    [Fact]
    public void Create_Unknown_DoesNotSoundLikeBan()
    {
        var info = DriverSignatureMapper.Create(
            DriverSignatureStatus.Unknown,
            "Signature status could not be determined. Unknown is not treated as unsigned or suspicious.",
            "n/a",
            null);

        info.AnalysisSummary.Should().Contain("not treated as unsigned");
    }
}
