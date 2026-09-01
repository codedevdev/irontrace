#include "precomp.h"

static
NTSTATUS
IronTraceHandleGetProtocolInfo(
    _In_ size_t OutputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *BytesReturned) PVOID OutputBuffer,
    _Out_ PULONG_PTR BytesReturned
    )
{
    IRONTRACE_PROTOCOL_INFO info;

    *BytesReturned = 0;

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(info)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&info, sizeof(info));
    info.ProtocolVersion = IRONTRACE_DRIVER_PROTOCOL_VERSION;
    info.MinProtocolVersion = IRONTRACE_DRIVER_MIN_PROTOCOL_VERSION;
    info.CapabilityFlags =
        IRONTRACE_CAP_READ_PCI_CONFIG |
        IRONTRACE_CAP_ENUMERATE_CAPABILITIES |
        IRONTRACE_CAP_QUERY_BAR_LAYOUT |
        IRONTRACE_CAP_QUERY_EXPRESS_CAPS |
        IRONTRACE_CAP_QUERY_BAR_SIZE_PROBE;
    /* SafeDeviceReset intentionally unset — never execute FLR. */
    info.MaxConfigReadLength = IRONTRACE_MAX_CONFIG_READ_EXTENDED;
    info.DriverBuild = IRONTRACE_DRIVER_BUILD;

    RtlCopyMemory(OutputBuffer, &info, sizeof(info));
    *BytesReturned = sizeof(info);
    IronTraceAudit("GetProtocolInfo", NULL);
    return STATUS_SUCCESS;
}

/*
 * Critical deny list (mirrors usermode SafeChallengePolicyEngine / DRIVER_BOUNDARY.md):
 *  0x01 mass storage, 0x02 network, 0x03 display/GPU, 0x06 bridge,
 *  0x0C/0x03 USB host. CapSafeDeviceReset remains unset — never execute FLR.
 */
static
BOOLEAN
IronTraceIsCriticalResetClass(
    _In_ UCHAR ClassCode,
    _In_ UCHAR Subclass
    )
{
    if (ClassCode == 0x01 || ClassCode == 0x02 || ClassCode == 0x03 || ClassCode == 0x06) {
        return TRUE;
    }
    if (ClassCode == 0x0C && Subclass == 0x03) {
        return TRUE;
    }
    return FALSE;
}

static
NTSTATUS
IronTraceHandleSafeDeviceReset(
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ size_t InputBufferLength,
    _Out_ PULONG_PTR BytesReturned
    )
{
    IRONTRACE_SAFE_RESET_REQUEST* req;
    UCHAR header[16];
    USHORT got = 0;
    NTSTATUS status;
    UCHAR classCode;
    UCHAR subclass;

    *BytesReturned = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(IRONTRACE_SAFE_RESET_REQUEST)) {
        IronTraceAudit("SafeDeviceResetDenied", NULL);
        return STATUS_INVALID_PARAMETER;
    }

    req = (IRONTRACE_SAFE_RESET_REQUEST*)InputBuffer;
    if (!IronTraceBdfIsValid(&req->Bdf)) {
        IronTraceAudit("SafeDeviceResetDenied", &req->Bdf);
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(header, sizeof(header));
    status = IronTraceReadPciConfig(&req->Bdf, 0, sizeof(header), header, &got);
    if (!NT_SUCCESS(status) || got < 12) {
        IronTraceAudit("SafeDeviceResetDenied", &req->Bdf);
        return STATUS_NOT_SUPPORTED;
    }

    /* PCI header: 0x09 ProgIf, 0x0A Subclass, 0x0B ClassCode */
    subclass = header[0x0A];
    classCode = header[0x0B];

    if (IronTraceIsCriticalResetClass(classCode, subclass)) {
        IronTraceAudit("SafeDeviceResetDeniedCritical", &req->Bdf);
        return STATUS_ACCESS_DENIED;
    }

    IronTraceAudit("SafeDeviceResetDenied", &req->Bdf);
    return STATUS_NOT_SUPPORTED;
}

static
NTSTATUS
IronTraceHandleReadPciConfig(
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ size_t InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *BytesReturned) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ PULONG_PTR BytesReturned
    )
{
    IRONTRACE_READ_PCI_CONFIG_REQUEST* req;
    IRONTRACE_READ_PCI_CONFIG_RESPONSE* resp;
    USHORT got = 0;
    NTSTATUS status;
    size_t needed;

    *BytesReturned = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(*req)) {
        return STATUS_INVALID_PARAMETER;
    }

    req = (IRONTRACE_READ_PCI_CONFIG_REQUEST*)InputBuffer;
    if (!IronTraceBdfIsValid(&req->Bdf) || req->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((ULONG)req->Offset + (ULONG)req->Length > IRONTRACE_MAX_CONFIG_READ_EXTENDED ||
        req->Length > IRONTRACE_MAX_CONFIG_READ_EXTENDED) {
        return STATUS_INVALID_PARAMETER;
    }

    needed = sizeof(IRONTRACE_READ_PCI_CONFIG_RESPONSE) + req->Length;
    if (OutputBuffer == NULL || OutputBufferLength < needed) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    resp = (IRONTRACE_READ_PCI_CONFIG_RESPONSE*)OutputBuffer;
    RtlZeroMemory(resp, needed);

    status = IronTraceReadPciConfig(
        &req->Bdf,
        req->Offset,
        req->Length,
        (PUCHAR)resp + sizeof(IRONTRACE_READ_PCI_CONFIG_RESPONSE),
        &got);

    IronTraceAudit("ReadPciConfig", &req->Bdf);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    resp->BytesReturned = got;
    *BytesReturned = sizeof(IRONTRACE_READ_PCI_CONFIG_RESPONSE) + got;
    return STATUS_SUCCESS;
}

static
NTSTATUS
IronTraceHandleEnumerateCapabilities(
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ size_t InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *BytesReturned) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ PULONG_PTR BytesReturned
    )
{
    IRONTRACE_ENUM_CAPS_REQUEST* req;
    IRONTRACE_ENUM_CAPS_RESPONSE* resp;
    IRONTRACE_CAPABILITY_ENTRY* entries;
    USHORT maxEntries;
    USHORT count = 0;
    NTSTATUS status;
    size_t needed;

    *BytesReturned = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(*req)) {
        return STATUS_INVALID_PARAMETER;
    }

    req = (IRONTRACE_ENUM_CAPS_REQUEST*)InputBuffer;
    if (!IronTraceBdfIsValid(&req->Bdf)) {
        return STATUS_INVALID_PARAMETER;
    }

    maxEntries = req->MaxEntries;
    if (maxEntries == 0 || maxEntries > IRONTRACE_MAX_CAPABILITY_ENTRIES) {
        maxEntries = IRONTRACE_MAX_CAPABILITY_ENTRIES;
    }

    needed = sizeof(IRONTRACE_ENUM_CAPS_RESPONSE) + (sizeof(IRONTRACE_CAPABILITY_ENTRY) * maxEntries);
    if (OutputBuffer == NULL || OutputBufferLength < needed) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    resp = (IRONTRACE_ENUM_CAPS_RESPONSE*)OutputBuffer;
    RtlZeroMemory(resp, needed);
    entries = (IRONTRACE_CAPABILITY_ENTRY*)((PUCHAR)resp + sizeof(IRONTRACE_ENUM_CAPS_RESPONSE));

    status = IronTraceEnumerateCapabilities(&req->Bdf, maxEntries, entries, &count);
    IronTraceAudit("EnumerateCapabilities", &req->Bdf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    resp->Count = count;
    *BytesReturned = sizeof(IRONTRACE_ENUM_CAPS_RESPONSE) + (sizeof(IRONTRACE_CAPABILITY_ENTRY) * count);
    return STATUS_SUCCESS;
}

static
NTSTATUS
IronTraceHandleQueryBarLayout(
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ size_t InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *BytesReturned) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ PULONG_PTR BytesReturned
    )
{
    IRONTRACE_QUERY_BAR_REQUEST* req;
    IRONTRACE_QUERY_BAR_RESPONSE response;
    NTSTATUS status;

    *BytesReturned = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(*req)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(response)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    req = (IRONTRACE_QUERY_BAR_REQUEST*)InputBuffer;
    status = IronTraceQueryBarLayout(&req->Bdf, &response);
    IronTraceAudit("QueryBarLayout", &req->Bdf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlCopyMemory(OutputBuffer, &response, sizeof(response));
    *BytesReturned = sizeof(response);
    return STATUS_SUCCESS;
}

static
NTSTATUS
IronTraceHandleQueryExpressCaps(
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ size_t InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *BytesReturned) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ PULONG_PTR BytesReturned
    )
{
    IRONTRACE_QUERY_EXPRESS_REQUEST* req;
    IRONTRACE_QUERY_EXPRESS_RESPONSE response;
    NTSTATUS status;

    *BytesReturned = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(*req)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(response)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    req = (IRONTRACE_QUERY_EXPRESS_REQUEST*)InputBuffer;
    status = IronTraceQueryExpressCaps(&req->Bdf, &response);
    IronTraceAudit("QueryExpressCaps", &req->Bdf);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlCopyMemory(OutputBuffer, &response, sizeof(response));
    *BytesReturned = sizeof(response);
    return STATUS_SUCCESS;
}

VOID
IronTraceEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PVOID inBuf = NULL;
    PVOID outBuf = NULL;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(Queue);

    if (InputBufferLength > 0) {
        status = WdfRequestRetrieveInputBuffer(Request, 1, &inBuf, NULL);
        if (!NT_SUCCESS(status)) {
            WdfRequestCompleteWithInformation(Request, status, 0);
            return;
        }
    }

    if (OutputBufferLength > 0) {
        status = WdfRequestRetrieveOutputBuffer(Request, 1, &outBuf, NULL);
        if (!NT_SUCCESS(status)) {
            WdfRequestCompleteWithInformation(Request, status, 0);
            return;
        }
    }

    switch (IoControlCode) {
    case IOCTL_IRONTRACE_GET_PROTOCOL_INFO:
        status = IronTraceHandleGetProtocolInfo(OutputBufferLength, outBuf, &information);
        break;

    case IOCTL_IRONTRACE_READ_PCI_CONFIG:
        status = IronTraceHandleReadPciConfig(
            inBuf, InputBufferLength, outBuf, OutputBufferLength, &information);
        break;

    case IOCTL_IRONTRACE_ENUMERATE_CAPABILITIES:
        status = IronTraceHandleEnumerateCapabilities(
            inBuf, InputBufferLength, outBuf, OutputBufferLength, &information);
        break;

    case IOCTL_IRONTRACE_QUERY_BAR_LAYOUT:
        status = IronTraceHandleQueryBarLayout(
            inBuf, InputBufferLength, outBuf, OutputBufferLength, &information);
        break;

    case IOCTL_IRONTRACE_QUERY_EXPRESS_CAPS:
        status = IronTraceHandleQueryExpressCaps(
            inBuf, InputBufferLength, outBuf, OutputBufferLength, &information);
        break;

    case IOCTL_IRONTRACE_SAFE_DEVICE_RESET:
        status = IronTraceHandleSafeDeviceReset(
            inBuf, InputBufferLength, &information);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, information);
}
