#include "precomp.h"

BOOLEAN
IronTraceBdfIsValid(
    _In_ const IRONTRACE_BDF* Bdf
    )
{
    return Bdf != NULL && Bdf->Device <= 31 && Bdf->Function <= 7;
}

static
ULONG
IronTraceSlotNumber(
    _In_ const IRONTRACE_BDF* Bdf
    )
{
    return ((ULONG)Bdf->Device << 3) | (ULONG)Bdf->Function;
}

NTSTATUS
IronTraceReadPciConfig(
    _In_ const IRONTRACE_BDF* Bdf,
    _In_ USHORT Offset,
    _In_ USHORT Length,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _Out_ PUSHORT BytesRead
    )
{
    ULONG got;

    *BytesRead = 0;

    if (!IronTraceBdfIsValid(Bdf) || Length == 0 || Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((ULONG)Offset + (ULONG)Length > IRONTRACE_MAX_CONFIG_READ_EXTENDED) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * Scoped config-space read via HAL bus data for the ROOT control-device topology.
     * No SetBusData / MMIO / physical memory mapping.
     */
    got = HalGetBusDataByOffset(
        PCIConfiguration,
        Bdf->Bus,
        IronTraceSlotNumber(Bdf),
        Buffer,
        Offset,
        Length);

    if (got == 0 || got == 2) {
        return STATUS_NO_SUCH_DEVICE;
    }

    *BytesRead = (USHORT)got;
    return STATUS_SUCCESS;
}

static
NTSTATUS
IronTraceWritePciConfig32(
    _In_ const IRONTRACE_BDF* Bdf,
    _In_ USHORT Offset,
    _In_ ULONG Value
    )
{
    ULONG written;

    if (!IronTraceBdfIsValid(Bdf)) {
        return STATUS_INVALID_PARAMETER;
    }

    written = HalSetBusDataByOffset(
        PCIConfiguration,
        Bdf->Bus,
        IronTraceSlotNumber(Bdf),
        &Value,
        Offset,
        sizeof(Value));

    if (written != sizeof(Value)) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/*
 * BAR size write-probe deny list: storage / GPU / bridges / USB host.
 * Network (0x02) is allowed — stock DMA CFW often presents as Ethernet.
 */
static
BOOLEAN
IronTraceBarProbeDenied(
    _In_ UCHAR ClassCode,
    _In_ UCHAR Subclass
    )
{
    if (ClassCode == 0x01 || ClassCode == 0x03 || ClassCode == 0x06) {
        return TRUE;
    }
    if (ClassCode == 0x0C && Subclass == 0x03) {
        return TRUE;
    }
    return FALSE;
}

static
UINT64
IronTraceDecodeBarSizeFromProbe(
    _In_ ULONG ProbeLow,
    _In_ BOOLEAN IsIo,
    _In_ BOOLEAN IsMem64,
    _In_ ULONG ProbeHigh
    )
{
    UINT64 mask;
    UINT64 size;

    if (IsIo) {
        mask = (UINT64)(ProbeLow & 0xFFFFFFFCu);
        if (mask == 0) {
            return 0;
        }
        size = (~mask + 1ull) & 0xFFFFFFFFull;
        return size;
    }

    if (IsMem64) {
        mask = (((UINT64)ProbeHigh << 32) | (ProbeLow & 0xFFFFFFF0u));
        if (mask == 0) {
            return 0;
        }
        size = (~mask) + 1ull;
        return size;
    }

    mask = (UINT64)(ProbeLow & 0xFFFFFFF0u);
    if (mask == 0) {
        return 0;
    }
    size = (~mask + 1ull) & 0xFFFFFFFFull;
    return size;
}

static
UCHAR
IronTraceReadConfig8(
    _In_ const IRONTRACE_BDF* Bdf,
    _In_ USHORT Offset
    )
{
    UCHAR value = 0;
    USHORT got = 0;
    (void)IronTraceReadPciConfig(Bdf, Offset, 1, &value, &got);
    return value;
}

static
USHORT
IronTraceReadConfig16(
    _In_ const IRONTRACE_BDF* Bdf,
    _In_ USHORT Offset
    )
{
    USHORT value = 0;
    USHORT got = 0;
    (void)IronTraceReadPciConfig(Bdf, Offset, 2, &value, &got);
    return value;
}

static
ULONG
IronTraceReadConfig32(
    _In_ const IRONTRACE_BDF* Bdf,
    _In_ USHORT Offset
    )
{
    ULONG value = 0;
    USHORT got = 0;
    (void)IronTraceReadPciConfig(Bdf, Offset, 4, &value, &got);
    return value;
}

NTSTATUS
IronTraceEnumerateCapabilities(
    _In_ const IRONTRACE_BDF* Bdf,
    _In_ USHORT MaxEntries,
    _Out_writes_(MaxEntries) IRONTRACE_CAPABILITY_ENTRY* Entries,
    _Out_ PUSHORT Count
    )
{
    UCHAR status;
    UCHAR ptr;
    USHORT n = 0;
    ULONG guard;

    *Count = 0;

    if (!IronTraceBdfIsValid(Bdf) || Entries == NULL || MaxEntries == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = IronTraceReadConfig8(Bdf, 0x06);
    if ((status & 0x10) == 0) {
        return STATUS_SUCCESS;
    }

    ptr = IronTraceReadConfig8(Bdf, 0x34);
    ptr &= 0xFC;

    for (guard = 0; ptr != 0 && n < MaxEntries && guard < 48; ++guard) {
        UCHAR id = IronTraceReadConfig8(Bdf, ptr);
        UCHAR next = IronTraceReadConfig8(Bdf, (USHORT)(ptr + 1));

        Entries[n].CapabilityId = id;
        Entries[n].Offset = ptr;
        Entries[n].IsExtended = 0;
        Entries[n].Reserved[0] = 0;
        Entries[n].Reserved[1] = 0;
        Entries[n].Reserved[2] = 0;
        ++n;

        if (id == 0xFF) {
            break;
        }

        ptr = next & 0xFC;
    }

    /* Extended config space capability walk (when 4K space readable). */
    {
        ULONG header = IronTraceReadConfig32(Bdf, 0x100);
        ULONG extPtr = 0x100;
        ULONG extGuard;

        if (header != 0 && header != 0xFFFFFFFFu) {
            for (extGuard = 0; extPtr != 0 && n < MaxEntries && extGuard < 48; ++extGuard) {
                ULONG dword = IronTraceReadConfig32(Bdf, (USHORT)extPtr);
                USHORT capId;
                ULONG next;

                if (dword == 0 || dword == 0xFFFFFFFFu) {
                    break;
                }

                capId = (USHORT)(dword & 0xFFFF);
                next = (dword >> 20) & 0xFFF;

                Entries[n].CapabilityId = capId;
                Entries[n].Offset = (USHORT)extPtr;
                Entries[n].IsExtended = 1;
                Entries[n].Reserved[0] = 0;
                Entries[n].Reserved[1] = 0;
                Entries[n].Reserved[2] = 0;
                ++n;

                if (next == 0 || next == extPtr) {
                    break;
                }

                extPtr = next;
            }
        }
    }

    *Count = n;
    return STATUS_SUCCESS;
}

NTSTATUS
IronTraceQueryBarLayout(
    _In_ const IRONTRACE_BDF* Bdf,
    _Out_ IRONTRACE_QUERY_BAR_RESPONSE* Response
    )
{
    UCHAR i;
    UCHAR count = 0;
    UCHAR headerType;

    RtlZeroMemory(Response, sizeof(*Response));

    if (!IronTraceBdfIsValid(Bdf)) {
        return STATUS_INVALID_PARAMETER;
    }

    headerType = IronTraceReadConfig8(Bdf, 0x0E) & 0x7F;
    /* Type 0 header: 6 BARs; type 1: 2 BARs. */
    {
        UCHAR maxBars = (headerType == 0) ? 6 : 2;
        UCHAR classCode = IronTraceReadConfig8(Bdf, 0x0B);
        UCHAR subclass = IronTraceReadConfig8(Bdf, 0x0A);
        BOOLEAN allowProbe = !IronTraceBarProbeDenied(classCode, subclass);

        for (i = 0; i < maxBars && count < IRONTRACE_MAX_BARS; ++i) {
            USHORT off = (USHORT)(0x10 + (i * 4));
            ULONG raw = IronTraceReadConfig32(Bdf, off);
            IRONTRACE_BAR_INFO* bar = &Response->Bars[count];
            BOOLEAN isIo;
            BOOLEAN isMem64 = FALSE;

            bar->Index = i;
            bar->Size = 0;

            if ((raw & 0x1) != 0) {
                isIo = TRUE;
                bar->BarType = 1; /* Io */
                bar->BaseAddress = raw & 0xFFFFFFFCu;
            }
            else {
                UCHAR typeBits = (UCHAR)((raw >> 1) & 0x3);
                BOOLEAN prefetch = (raw & 0x8) != 0;
                isIo = FALSE;

                if (typeBits == 0x2) {
                    ULONG rawHi;
                    isMem64 = TRUE;
                    bar->BarType = prefetch ? 4 : 3;
                    if (i + 1 >= maxBars) {
                        break;
                    }
                    rawHi = IronTraceReadConfig32(Bdf, (USHORT)(off + 4));
                    bar->BaseAddress = ((UINT64)rawHi << 32) | (raw & 0xFFFFFFF0u);
                }
                else {
                    bar->BarType = prefetch ? 4 : 2;
                    bar->BaseAddress = raw & 0xFFFFFFF0u;
                }
            }

            if (allowProbe && (bar->BaseAddress != 0 || bar->BarType != 0)) {
                ULONG origLow = raw;
                ULONG origHigh = 0;
                ULONG probeLow;
                ULONG probeHigh = 0xFFFFFFFFu;

                if (isMem64) {
                    origHigh = IronTraceReadConfig32(Bdf, (USHORT)(off + 4));
                }

                if (NT_SUCCESS(IronTraceWritePciConfig32(Bdf, off, 0xFFFFFFFFu))) {
                    if (isMem64) {
                        (void)IronTraceWritePciConfig32(Bdf, (USHORT)(off + 4), 0xFFFFFFFFu);
                    }

                    probeLow = IronTraceReadConfig32(Bdf, off);
                    if (isMem64) {
                        probeHigh = IronTraceReadConfig32(Bdf, (USHORT)(off + 4));
                    }

                    bar->Size = IronTraceDecodeBarSizeFromProbe(probeLow, isIo, isMem64, probeHigh);

                    (void)IronTraceWritePciConfig32(Bdf, off, origLow);
                    if (isMem64) {
                        (void)IronTraceWritePciConfig32(Bdf, (USHORT)(off + 4), origHigh);
                    }
                }
            }

            if (isMem64) {
                ++i; /* skip next BAR slot used by high dword */
            }

            if (bar->BaseAddress != 0 || bar->BarType != 0) {
                ++count;
            }
        }
    }

    Response->BarCount = count;
    return STATUS_SUCCESS;
}

NTSTATUS
IronTraceQueryExpressCaps(
    _In_ const IRONTRACE_BDF* Bdf,
    _Out_ IRONTRACE_QUERY_EXPRESS_RESPONSE* Response
    )
{
    IRONTRACE_CAPABILITY_ENTRY entries[IRONTRACE_MAX_CAPABILITY_ENTRIES];
    USHORT count = 0;
    USHORT i;
    NTSTATUS status;

    RtlZeroMemory(Response, sizeof(*Response));

    status = IronTraceEnumerateCapabilities(
        Bdf,
        IRONTRACE_MAX_CAPABILITY_ENTRIES,
        entries,
        &count);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (i = 0; i < count; ++i) {
        if (entries[i].IsExtended == 0 && entries[i].CapabilityId == 0x10) {
            USHORT offset = entries[i].Offset;
            USHORT deviceCap;
            USHORT deviceControl;
            USHORT linkStatus;

            Response->Flags |= IRONTRACE_EXPRESS_HAS_PCIE;
            deviceCap = IronTraceReadConfig16(Bdf, (USHORT)(offset + 0x04));
            deviceControl = IronTraceReadConfig16(Bdf, (USHORT)(offset + 0x08));
            linkStatus = IronTraceReadConfig16(Bdf, (USHORT)(offset + 0x12));

            Response->DeviceControl = deviceControl;
            Response->LinkStatus = linkStatus;
            Response->MaxPayloadSupported = (UCHAR)((deviceCap >> 0) & 0x7);
            Response->MaxReadRequest = (UCHAR)((deviceControl >> 12) & 0x7);

            if ((deviceCap & (1u << 28)) != 0) {
                Response->Flags |= IRONTRACE_EXPRESS_SUPPORTS_FLR;
            }
        }

        if (entries[i].IsExtended) {
            switch (entries[i].CapabilityId) {
            case 0x0001:
                Response->Flags |= IRONTRACE_EXPRESS_HAS_AER;
                break;
            case 0x000D:
                Response->Flags |= IRONTRACE_EXPRESS_HAS_ACS;
                break;
            case 0x000F:
                Response->Flags |= IRONTRACE_EXPRESS_HAS_ATS;
                break;
            case 0x0010:
                Response->Flags |= IRONTRACE_EXPRESS_HAS_SRIOV;
                break;
            default:
                break;
            }
        }
    }

    return STATUS_SUCCESS;
}
