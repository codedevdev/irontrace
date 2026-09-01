/*++
  IronTrace.Driver protocol v2 — shared with user-mode (mirrored in IronTrace.Contracts).
  Keep layouts identical; bump IRONTRACE_DRIVER_PROTOCOL_VERSION on breaking changes.
--*/

#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#endif

#define IRONTRACE_DRIVER_PROTOCOL_VERSION      2u
#define IRONTRACE_DRIVER_MIN_PROTOCOL_VERSION  1u

/* Custom device type (Microsoft-reserved range starts below 0x8000). */
#define IRONTRACE_DEVICE_TYPE  0x8000u

#define IRONTRACE_METHOD_BUFFERED  0u
#define IRONTRACE_FILE_ANY_ACCESS  0u

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) ( \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

#define IOCTL_IRONTRACE_GET_PROTOCOL_INFO \
    CTL_CODE(IRONTRACE_DEVICE_TYPE, 0x800, IRONTRACE_METHOD_BUFFERED, IRONTRACE_FILE_ANY_ACCESS)
#define IOCTL_IRONTRACE_READ_PCI_CONFIG \
    CTL_CODE(IRONTRACE_DEVICE_TYPE, 0x801, IRONTRACE_METHOD_BUFFERED, IRONTRACE_FILE_ANY_ACCESS)
#define IOCTL_IRONTRACE_ENUMERATE_CAPABILITIES \
    CTL_CODE(IRONTRACE_DEVICE_TYPE, 0x802, IRONTRACE_METHOD_BUFFERED, IRONTRACE_FILE_ANY_ACCESS)
#define IOCTL_IRONTRACE_QUERY_BAR_LAYOUT \
    CTL_CODE(IRONTRACE_DEVICE_TYPE, 0x803, IRONTRACE_METHOD_BUFFERED, IRONTRACE_FILE_ANY_ACCESS)
#define IOCTL_IRONTRACE_QUERY_EXPRESS_CAPS \
    CTL_CODE(IRONTRACE_DEVICE_TYPE, 0x804, IRONTRACE_METHOD_BUFFERED, IRONTRACE_FILE_ANY_ACCESS)
#define IOCTL_IRONTRACE_SAFE_DEVICE_RESET \
    CTL_CODE(IRONTRACE_DEVICE_TYPE, 0x805, IRONTRACE_METHOD_BUFFERED, IRONTRACE_FILE_ANY_ACCESS)

/* Capability bitmask returned by GetProtocolInfo. */
#define IRONTRACE_CAP_READ_PCI_CONFIG          (1u << 0)
#define IRONTRACE_CAP_ENUMERATE_CAPABILITIES   (1u << 1)
#define IRONTRACE_CAP_QUERY_BAR_LAYOUT         (1u << 2)
#define IRONTRACE_CAP_QUERY_EXPRESS_CAPS       (1u << 3)
#define IRONTRACE_CAP_SAFE_DEVICE_RESET        (1u << 4) /* ALWAYS unset — never execute FLR */
#define IRONTRACE_CAP_QUERY_BAR_SIZE_PROBE     (1u << 5) /* protocol 2: gated BAR size write-probe */

#define IRONTRACE_MAX_CONFIG_READ_STANDARD  256u
#define IRONTRACE_MAX_CONFIG_READ_EXTENDED  4096u
#define IRONTRACE_MAX_CAPABILITY_ENTRIES    64u
#define IRONTRACE_MAX_BARS                  6u

/* Device interface: {B8E4D1A0-2F3C-4A5B-9C8D-1E2F3A4B5C6D} — defined in Device.cpp / C# client. */

#pragma pack(push, 1)

typedef struct _IRONTRACE_BDF {
    UINT8 Bus;
    UINT8 Device;   /* 0–31 */
    UINT8 Function; /* 0–7 */
    UINT8 Reserved;
} IRONTRACE_BDF;

typedef struct _IRONTRACE_PROTOCOL_INFO {
    UINT32 ProtocolVersion;
    UINT32 MinProtocolVersion;
    UINT32 CapabilityFlags;
    UINT32 MaxConfigReadLength;
    UINT32 DriverBuild;
    UINT32 Reserved;
} IRONTRACE_PROTOCOL_INFO;

typedef struct _IRONTRACE_READ_PCI_CONFIG_REQUEST {
    IRONTRACE_BDF Bdf;
    UINT16 Offset;
    UINT16 Length;
} IRONTRACE_READ_PCI_CONFIG_REQUEST;

typedef struct _IRONTRACE_READ_PCI_CONFIG_RESPONSE {
    UINT16 BytesReturned;
    UINT16 Reserved;
    /* Followed by BytesReturned bytes of config data (buffer sized by caller). */
} IRONTRACE_READ_PCI_CONFIG_RESPONSE;

typedef struct _IRONTRACE_ENUM_CAPS_REQUEST {
    IRONTRACE_BDF Bdf;
    UINT16 MaxEntries;
    UINT16 Reserved;
} IRONTRACE_ENUM_CAPS_REQUEST;

typedef struct _IRONTRACE_CAPABILITY_ENTRY {
    UINT16 CapabilityId;
    UINT16 Offset;
    UINT8 IsExtended; /* 0 = standard, 1 = extended */
    UINT8 Reserved[3];
} IRONTRACE_CAPABILITY_ENTRY;

typedef struct _IRONTRACE_ENUM_CAPS_RESPONSE {
    UINT16 Count;
    UINT16 Reserved;
    /* Followed by Count × IRONTRACE_CAPABILITY_ENTRY */
} IRONTRACE_ENUM_CAPS_RESPONSE;

typedef struct _IRONTRACE_QUERY_BAR_REQUEST {
    IRONTRACE_BDF Bdf;
} IRONTRACE_QUERY_BAR_REQUEST;

/* BarType: 0=Unknown, 1=Io, 2=Memory32, 3=Memory64, 4=MemoryPrefetch */
typedef struct _IRONTRACE_BAR_INFO {
    UINT8 Index;
    UINT8 BarType;
    UINT8 Reserved[2];
    UINT64 BaseAddress;
    UINT64 Size; /* 0 if unknown (no write probe) */
} IRONTRACE_BAR_INFO;

typedef struct _IRONTRACE_QUERY_BAR_RESPONSE {
    UINT8 BarCount;
    UINT8 Reserved[3];
    IRONTRACE_BAR_INFO Bars[IRONTRACE_MAX_BARS];
} IRONTRACE_QUERY_BAR_RESPONSE;

typedef struct _IRONTRACE_QUERY_EXPRESS_REQUEST {
    IRONTRACE_BDF Bdf;
} IRONTRACE_QUERY_EXPRESS_REQUEST;

#define IRONTRACE_EXPRESS_HAS_PCIE   (1u << 0)
#define IRONTRACE_EXPRESS_HAS_AER    (1u << 1)
#define IRONTRACE_EXPRESS_HAS_ACS    (1u << 2)
#define IRONTRACE_EXPRESS_HAS_ATS    (1u << 3)
#define IRONTRACE_EXPRESS_HAS_SRIOV  (1u << 4)
#define IRONTRACE_EXPRESS_SUPPORTS_FLR (1u << 5)

typedef struct _IRONTRACE_QUERY_EXPRESS_RESPONSE {
    UINT32 Flags;
    UINT16 DeviceControl;
    UINT16 LinkStatus;
    UINT8 MaxPayloadSupported;
    UINT8 MaxReadRequest;
    UINT8 Reserved[2];
} IRONTRACE_QUERY_EXPRESS_RESPONSE;

typedef struct _IRONTRACE_SAFE_RESET_REQUEST {
    IRONTRACE_BDF Bdf;
    UINT32 Reserved;
} IRONTRACE_SAFE_RESET_REQUEST;

#pragma pack(pop)
