using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Hardware;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace IronTrace.Hardware.Signing;

public interface IDriverSignatureAnalyzer
{
    DriverSignatureInfo Analyze(string? imagePath, string? infPath);
}

public sealed class DriverSignatureAnalyzer : IDriverSignatureAnalyzer
{
    private readonly ILogger<DriverSignatureAnalyzer> _logger;

    public DriverSignatureAnalyzer(ILogger<DriverSignatureAnalyzer> logger) => _logger = logger;

    public DriverSignatureInfo Analyze(string? imagePath, string? infPath)
    {
        try
        {
            var path = ResolveExistingPath(imagePath) ?? ResolveExistingPath(infPath);
            if (path is null)
            {
                return DriverSignatureMapper.Create(
                    DriverSignatureStatus.Unknown,
                    analysis: "Driver file path could not be resolved. Signature status is Unknown — not treated as unsigned.",
                    technical: "No ImagePath/InfPath on disk.",
                    filePath: null);
            }

            var embedded = TryReadEmbeddedAuthenticode(path);
            var trust = WinTrustNative.VerifyFile(path);

            return DriverSignatureMapper.FromVerification(path, embedded, trust);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Driver signature analysis failed for {Image} / {Inf}", imagePath, infPath);
            return DriverSignatureMapper.Create(
                DriverSignatureStatus.Error,
                analysis: "IronTrace could not complete signature analysis for this driver. The device is left unverified rather than marked suspicious.",
                technical: ex.GetType().Name + ": " + ex.Message,
                filePath: imagePath ?? infPath);
        }
    }

    private static string? ResolveExistingPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var expanded = Environment.ExpandEnvironmentVariables(path.Trim().Trim('"'));
        // Service ImagePath often starts with \SystemRoot\...
        if (expanded.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            expanded = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                expanded["\\SystemRoot\\".Length..]);
        }
        else if (expanded.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            expanded = expanded[4..];
        }
        else if (expanded.StartsWith("System32\\", StringComparison.OrdinalIgnoreCase) ||
                 expanded.StartsWith(@"System32/", StringComparison.OrdinalIgnoreCase))
        {
            expanded = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), expanded[9..]);
        }

        return File.Exists(expanded) ? expanded : null;
    }

    private static X509Certificate2? TryReadEmbeddedAuthenticode(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            return new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
        }
        catch
        {
            return null;
        }
    }
}

public static class DriverSignatureMapper
{
    public static DriverSignatureInfo Create(
        DriverSignatureStatus status,
        string analysis,
        string? technical,
        string? filePath,
        string? subject = null,
        string? issuer = null,
        string? thumbprint = null,
        string? algorithm = null,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
        => new(
            status,
            subject,
            issuer,
            thumbprint,
            algorithm,
            notBefore,
            notAfter,
            filePath,
            analysis,
            technical);

    public static DriverSignatureInfo FromVerification(
        string path,
        X509Certificate2? embedded,
        WinTrustResult trust)
    {
        var subject = embedded?.Subject;
        var issuer = embedded?.Issuer;
        var thumb = embedded?.Thumbprint;
        var alg = embedded?.SignatureAlgorithm?.FriendlyName;
        DateTimeOffset? nb = embedded is null ? null : new DateTimeOffset(embedded.NotBefore.ToUniversalTime());
        DateTimeOffset? na = embedded is null ? null : new DateTimeOffset(embedded.NotAfter.ToUniversalTime());

        var microsoft = IsMicrosoftPublisher(subject, issuer);

        if (trust.Status == WinTrustStatus.Trusted)
        {
            var status = microsoft ? DriverSignatureStatus.MicrosoftSigned :
                trust.ViaCatalog ? DriverSignatureStatus.CatalogSigned : DriverSignatureStatus.AuthenticodeSigned;

            var who = ShortSubject(subject) ?? (microsoft ? "Microsoft" : "third-party publisher");
            var channel = trust.ViaCatalog ? "Windows driver catalog" : "embedded Authenticode";
            return Create(
                status,
                analysis: microsoft
                    ? $"Signed by Microsoft ({channel}). Catalog/Authenticode trust verification succeeded."
                    : $"Signed by {who} ({channel}). Trust verification succeeded. This indicates a signed driver package, not device authenticity by itself.",
                technical: $"WinVerifyTrust=Trusted; ViaCatalog={trust.ViaCatalog}; HRESULT=0x{trust.HResult:X8}",
                filePath: path,
                subject: subject,
                issuer: issuer,
                thumbprint: thumb,
                algorithm: alg,
                notBefore: nb,
                notAfter: na);
        }

        if (trust.Status == WinTrustStatus.Unsigned ||
            trust.HResult is unchecked((int)0x800B0100) /* TRUST_E_NOSIGNATURE */)
        {
            return Create(
                DriverSignatureStatus.Unsigned,
                analysis: "No Authenticode or catalog signature was found for this driver file. Unsigned does not prove malicious DMA hardware — treat as low-severity evidence for review.",
                technical: $"WinVerifyTrust=Unsigned; HRESULT=0x{trust.HResult:X8}",
                filePath: path,
                subject: subject,
                issuer: issuer,
                thumbprint: thumb,
                algorithm: alg,
                notBefore: nb,
                notAfter: na);
        }

        if (trust.Status == WinTrustStatus.Expired ||
            trust.HResult is unchecked((int)0x800B0101) /* TRUST_E_CERT_SIGNATURE? */ or
                unchecked((int)0x800B0105) /* CERT_E_EXPIRED-ish */ or
                unchecked((int)0x800B010C))
        {
            return Create(
                DriverSignatureStatus.Expired,
                analysis: "A signature was present but appears expired or time-invalid. Informational/review — not automatic proof of cheating.",
                technical: $"WinVerifyTrust=ExpiredOrTime; HRESULT=0x{trust.HResult:X8}",
                filePath: path,
                subject: subject,
                issuer: issuer,
                thumbprint: thumb,
                algorithm: alg,
                notBefore: nb,
                notAfter: na);
        }

        if (embedded is not null && trust.Status == WinTrustStatus.Untrusted)
        {
            return Create(
                DriverSignatureStatus.Untrusted,
                analysis: $"A signature/certificate was found ({ShortSubject(subject) ?? "unknown publisher"}) but Windows trust verification did not succeed. This may be a revoked, untrusted, or test-signed chain. Review recommended — not an automatic ban signal.",
                technical: $"WinVerifyTrust=Untrusted; HRESULT=0x{trust.HResult:X8}",
                filePath: path,
                subject: subject,
                issuer: issuer,
                thumbprint: thumb,
                algorithm: alg,
                notBefore: nb,
                notAfter: na);
        }

        if (embedded is not null)
        {
            // Cert readable but trust ambiguous → AuthenticodeSigned with caveat
            return Create(
                microsoft ? DriverSignatureStatus.MicrosoftSigned : DriverSignatureStatus.AuthenticodeSigned,
                analysis: $"Certificate present ({ShortSubject(subject) ?? "unknown"}) but full trust result was inconclusive (HRESULT 0x{trust.HResult:X8}). Treat confidence as limited.",
                technical: $"EmbeddedCert=yes; WinVerifyTrust HRESULT=0x{trust.HResult:X8}",
                filePath: path,
                subject: subject,
                issuer: issuer,
                thumbprint: thumb,
                algorithm: alg,
                notBefore: nb,
                notAfter: na);
        }

        return Create(
            DriverSignatureStatus.Unknown,
            analysis: "Signature status could not be determined. Unknown is not treated as unsigned or suspicious.",
            technical: $"WinVerifyTrust HRESULT=0x{trust.HResult:X8}; Status={trust.Status}",
            filePath: path);
    }

    public static string? ShortSubject(string? subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            return null;
        }

        // CN=Foo, O=Bar → Foo
        foreach (var part in subject.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (part.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                return part[3..].Trim().Trim('"');
            }
        }

        return subject.Length > 80 ? subject[..80] + "…" : subject;
    }

    public static bool IsMicrosoftPublisher(string? subject, string? issuer)
    {
        static bool Hit(string? s) =>
            !string.IsNullOrEmpty(s) &&
            (s.Contains("Microsoft Windows", StringComparison.OrdinalIgnoreCase) ||
             s.Contains("Microsoft Corporation", StringComparison.OrdinalIgnoreCase) ||
             s.Contains("Microsoft Code Signing PCA", StringComparison.OrdinalIgnoreCase) ||
             s.Contains("Microsoft Windows Production PCA", StringComparison.OrdinalIgnoreCase));

        return Hit(subject) || Hit(issuer);
    }
}

public enum WinTrustStatus
{
    Trusted,
    Unsigned,
    Untrusted,
    Expired,
    Error
}

public readonly record struct WinTrustResult(WinTrustStatus Status, int HResult, bool ViaCatalog);

internal static class WinTrustNative
{
    private const int WTD_UI_NONE = 2;
    private const int WTD_REVOKE_NONE = 0;
    private const int WTD_CHOICE_FILE = 1;
    private const int WTD_STATEACTION_VERIFY = 1;
    private const int WTD_STATEACTION_CLOSE = 2;
    private const int WTD_REVOCATION_CHECK_NONE = 0x00000010;
    private const int WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);

    public static WinTrustResult VerifyFile(string filePath)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwStateAction = WTD_STATEACTION_VERIFY,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL,
                dwUIContext = 0
            };

            var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            var hr = WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            // Close state
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            return MapHResult(hr);
        }
        catch
        {
            return new WinTrustResult(WinTrustStatus.Error, -1, false);
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    private static WinTrustResult MapHResult(int hr)
    {
        if (hr == 0)
        {
            // Catalog vs embedded is not perfectly distinguished here; treat as trusted Authenticode/catalog path.
            return new WinTrustResult(WinTrustStatus.Trusted, hr, ViaCatalog: false);
        }

        if (hr == TRUST_E_NOSIGNATURE)
        {
            return new WinTrustResult(WinTrustStatus.Unsigned, hr, false);
        }

        // CERT_E_EXPIRED
        if (hr == unchecked((int)0x800B0101) || hr == unchecked((int)0x800B0105))
        {
            return new WinTrustResult(WinTrustStatus.Expired, hr, false);
        }

        return new WinTrustResult(WinTrustStatus.Untrusted, hr, false);
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }
}

public static class DriverPathResolver
{
    public static string? ResolveServiceImagePath(string? service)
    {
        if (string.IsNullOrWhiteSpace(service))
        {
            return null;
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + service);
            var image = key?.GetValue("ImagePath") as string;
            return string.IsNullOrWhiteSpace(image) ? null : image;
        }
        catch
        {
            return null;
        }
    }

    public static string? ResolveInfFullPath(string? infFileName)
    {
        if (string.IsNullOrWhiteSpace(infFileName))
        {
            return null;
        }

        // Often just "oemXX.inf" — search DriverStore FileRepository
        var infName = Path.GetFileName(infFileName);
        var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var candidates = new[]
        {
            Path.Combine(windir, "INF", infName),
            Path.Combine(windir, "System32", "DriverStore", "FileRepository")
        };

        if (File.Exists(candidates[0]))
        {
            return candidates[0];
        }

        try
        {
            var repo = candidates[1];
            if (Directory.Exists(repo))
            {
                foreach (var dir in Directory.EnumerateDirectories(repo))
                {
                    var path = Path.Combine(dir, infName);
                    if (File.Exists(path))
                    {
                        return path;
                    }
                }
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }
}
