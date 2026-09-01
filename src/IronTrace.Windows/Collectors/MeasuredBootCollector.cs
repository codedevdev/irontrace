using System.Runtime.InteropServices;
using IronTrace.Contracts.Challenge;
using IronTrace.Contracts.Enums;
using IronTrace.Contracts.Platform;
using IronTrace.Core.Scanning;
using Microsoft.Extensions.Logging;

namespace IronTrace.Windows.Collectors;

/// <summary>
/// Best-effort TPM PCR 0–7 snapshot via TBS. Absence/failure → Unknown, not suspicious.
/// Does not claim the scan report is attested.
/// </summary>
public sealed class MeasuredBootCollector : IMeasuredBootEvidenceCollector
{
    private const uint TbsSuccess = 0;
    private const uint TpmAlgSha256 = 0x000B;
    private const uint TpmCcPcrRead = 0x0000017E;
    private const ushort TpmStNoSessions = 0x8001;

    private readonly ILogger<MeasuredBootCollector> _logger;

    public MeasuredBootCollector(ILogger<MeasuredBootCollector> logger)
        => _logger = logger;

    public Task<MeasuredBootEvidenceSnapshot> CollectAsync(
        PlatformSecurityState? platformSecurity,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var tpm = platformSecurity?.Tpm;
        bool? tpmPresent = tpm?.State switch
        {
            SecurityFeatureState.Unsupported => false,
            SecurityFeatureState.Enabled or SecurityFeatureState.SupportedButDisabled or SecurityFeatureState.Disabled
                => true,
            _ => null
        };
        var spec = ExtractSpec(tpm?.Detail);

        if (tpmPresent == false)
        {
            return Task.FromResult(new MeasuredBootEvidenceSnapshot(
                CapabilityStatus.Unsupported,
                false,
                spec,
                null,
                Array.Empty<PcrDigestEntry>(),
                "TPM not present. Measured Boot PCR snapshot unsupported (not suspicious)."));
        }

        try
        {
            var pcrs = TryReadPcrSha256Bank();
            if (pcrs.Count == 0)
            {
                return Task.FromResult(new MeasuredBootEvidenceSnapshot(
                    CapabilityStatus.Unknown,
                    tpmPresent,
                    spec,
                    null,
                    Array.Empty<PcrDigestEntry>(),
                    "TPM PCR read returned no digests (TBS unavailable or command failed). Unknown, not suspicious."));
            }

            var completeness = pcrs.Count >= 8 ? CapabilityStatus.Supported : CapabilityStatus.Partial;
            return Task.FromResult(new MeasuredBootEvidenceSnapshot(
                completeness,
                tpmPresent ?? true,
                spec,
                "sha256",
                pcrs,
                completeness == CapabilityStatus.Supported
                    ? "PCR 0–7 SHA-256 snapshot via TBS (evidence only; report is not attested)."
                    : $"Partial PCR SHA-256 snapshot ({pcrs.Count}/8 indexes). Evidence only; report is not attested."));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Measured Boot / PCR collection failed");
            return Task.FromResult(new MeasuredBootEvidenceSnapshot(
                CapabilityStatus.Unknown,
                tpmPresent,
                spec,
                null,
                Array.Empty<PcrDigestEntry>(),
                "Measured Boot PCR collection failed. Unknown, not suspicious."));
        }
    }

    private static string? ExtractSpec(string? detail)
    {
        if (string.IsNullOrWhiteSpace(detail))
            return null;
        // Detail like "TPM present (2.0)."
        var start = detail.IndexOf('(');
        var end = detail.IndexOf(')');
        if (start >= 0 && end > start)
            return detail[(start + 1)..end];
        return null;
    }

    private List<PcrDigestEntry> TryReadPcrSha256Bank()
    {
        var result = new List<PcrDigestEntry>();
        var contextParams = new NativeMethods.ContextParams
        {
            Version = 2,
            Parameters = 1u << 2 // TPM_VERSION_20
        };

        var ctxResult = NativeMethods.Tbsi_Context_Create(ref contextParams, out var context);
        if (ctxResult != TbsSuccess || context == IntPtr.Zero)
        {
            _logger.LogDebug("Tbsi_Context_Create failed: {Code}", ctxResult);
            return result;
        }

        try
        {
            var command = BuildPcrReadCommandSha256_0_7();
            var response = new byte[512];
            uint responseSize = (uint)response.Length;
            var submit = NativeMethods.Tbsip_Submit_Command(
                context,
                0,
                NativeMethods.TbsCommandPriorityNormal,
                command,
                (uint)command.Length,
                response,
                ref responseSize);

            if (submit != TbsSuccess || responseSize < 10)
            {
                _logger.LogDebug("Tbsip_Submit_Command PCR_Read failed: {Code}", submit);
                return result;
            }

            ParsePcrReadResponse(response.AsSpan(0, (int)responseSize), result);
            return result;
        }
        finally
        {
            NativeMethods.Tbsip_Context_Close(context);
        }
    }

    /// <summary>
    /// TPM2_PCR_Read for SHA-256 bank, PCR select bits 0–7.
    /// </summary>
    public static byte[] BuildPcrReadCommandSha256_0_7()
    {
        var cmd = new byte[20];
        WriteUInt16Be(cmd, 0, TpmStNoSessions);
        WriteUInt32Be(cmd, 2, 20);
        WriteUInt32Be(cmd, 6, TpmCcPcrRead);
        WriteUInt32Be(cmd, 10, 1);
        WriteUInt16Be(cmd, 14, (ushort)TpmAlgSha256);
        cmd[16] = 3;
        cmd[17] = 0xFF;
        cmd[18] = 0x00;
        cmd[19] = 0x00;
        return cmd;
    }

    public static void ParsePcrReadResponse(ReadOnlySpan<byte> response, List<PcrDigestEntry> into)
    {
        if (response.Length < 14)
            return;

        var offset = 10;
        if (offset + 4 > response.Length)
            return;
        offset += 4;

        if (offset + 4 > response.Length)
            return;
        var selCount = ReadUInt32Be(response, offset);
        offset += 4;
        for (var i = 0; i < selCount && i < 16; i++)
        {
            if (offset + 3 > response.Length)
                return;
            offset += 2;
            var sizeofSelect = response[offset];
            offset += 1;
            if (offset + sizeofSelect > response.Length)
                return;
            offset += sizeofSelect;
        }

        if (offset + 4 > response.Length)
            return;
        var digestCount = ReadUInt32Be(response, offset);
        offset += 4;

        for (var i = 0; i < digestCount && i < 24; i++)
        {
            if (offset + 2 > response.Length)
                return;
            var size = ReadUInt16Be(response, offset);
            offset += 2;
            if (size == 0 || offset + size > response.Length)
                return;
            var hex = Convert.ToHexString(response.Slice(offset, size)).ToLowerInvariant();
            offset += size;
            into.Add(new PcrDigestEntry(i, hex));
        }
    }

    private static void WriteUInt16Be(byte[] buf, int offset, ushort value)
    {
        buf[offset] = (byte)(value >> 8);
        buf[offset + 1] = (byte)value;
    }

    private static void WriteUInt32Be(byte[] buf, int offset, uint value)
    {
        buf[offset] = (byte)(value >> 24);
        buf[offset + 1] = (byte)(value >> 16);
        buf[offset + 2] = (byte)(value >> 8);
        buf[offset + 3] = (byte)value;
    }

    private static ushort ReadUInt16Be(ReadOnlySpan<byte> buf, int offset)
        => (ushort)((buf[offset] << 8) | buf[offset + 1]);

    private static uint ReadUInt32Be(ReadOnlySpan<byte> buf, int offset)
        => ((uint)buf[offset] << 24) | ((uint)buf[offset + 1] << 16) |
           ((uint)buf[offset + 2] << 8) | buf[offset + 3];

    private static class NativeMethods
    {
        public const uint TbsCommandPriorityNormal = 200;

        [StructLayout(LayoutKind.Sequential)]
        public struct ContextParams
        {
            public uint Version;
            public uint Parameters;
        }

        [DllImport("tbs.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern uint Tbsi_Context_Create(
            ref ContextParams pContextParams,
            out IntPtr phContext);

        [DllImport("tbs.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern uint Tbsip_Context_Close(IntPtr hContext);

        [DllImport("tbs.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern uint Tbsip_Submit_Command(
            IntPtr hContext,
            uint locality,
            uint priority,
            byte[] pCommandBuf,
            uint commandBufLen,
            byte[] pResultBuf,
            ref uint pResultBufLen);
    }
}
