#include "precomp.h"

VOID
IronTraceAudit(
    _In_ PCSTR Operation,
    _In_opt_ const IRONTRACE_BDF* Bdf
    )
{
    if (Bdf != NULL) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "IronTrace: op=%s bdf=%02X:%02X.%u\n",
            Operation,
            Bdf->Bus,
            Bdf->Device,
            Bdf->Function);
    }
    else {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "IronTrace: op=%s\n",
            Operation);
    }
}
