#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include <initguid.h>

#include "IronTraceDriverProtocol.h"

#define IRONTRACE_POOL_TAG 'rtTI'
#define IRONTRACE_DRIVER_BUILD 600u

// {B8E4D1A0-2F3C-4A5B-9C8D-1E2F3A4B5C6D}
DEFINE_GUID(GUID_DEVINTERFACE_IRONTRACE,
    0xb8e4d1a0, 0x2f3c, 0x4a5b, 0x9c, 0x8d, 0x1e, 0x2f, 0x3a, 0x4b, 0x5c, 0x6d);

typedef struct _DEVICE_CONTEXT {
    LONG Reserved;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, DeviceGetContext);

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD IronTraceEvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL IronTraceEvtIoDeviceControl;

VOID
IronTraceAudit(
    _In_ PCSTR Operation,
    _In_opt_ const IRONTRACE_BDF* Bdf
    );

BOOLEAN
IronTraceBdfIsValid(
    _In_ const IRONTRACE_BDF* Bdf
    );

NTSTATUS
IronTraceReadPciConfig(
    _In_ const IRONTRACE_BDF* Bdf,
    _In_ USHORT Offset,
    _In_ USHORT Length,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _Out_ PUSHORT BytesRead
    );

NTSTATUS
IronTraceEnumerateCapabilities(
    _In_ const IRONTRACE_BDF* Bdf,
    _In_ USHORT MaxEntries,
    _Out_writes_(MaxEntries) IRONTRACE_CAPABILITY_ENTRY* Entries,
    _Out_ PUSHORT Count
    );

NTSTATUS
IronTraceQueryBarLayout(
    _In_ const IRONTRACE_BDF* Bdf,
    _Out_ IRONTRACE_QUERY_BAR_RESPONSE* Response
    );

NTSTATUS
IronTraceQueryExpressCaps(
    _In_ const IRONTRACE_BDF* Bdf,
    _Out_ IRONTRACE_QUERY_EXPRESS_RESPONSE* Response
    );
