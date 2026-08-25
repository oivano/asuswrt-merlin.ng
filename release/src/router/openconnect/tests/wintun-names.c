/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2019 David Woodhouse
 * Copyright © 2024 Marios Paouris
 *
 * Authors: David Woodhouse <dwmw2@infradead.org>
 *          Marios Paouris <mspaourh@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <config.h>

#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define __OPENCONNECT_INTERNAL_H__

#define PRG_ERR		0
#define PRG_INFO	1
#define PRG_DEBUG	2
#define PRG_TRACE	3

#define vpn_progress(v, d, ...) do { \
  if ( d < PRG_TRACE) { \
    printf(__VA_ARGS__); \
  } \
} while (0);

#define _(x) x

struct openconnect_info {
	char *ifname;
    wchar_t *ifname_w;
};

/* don't link linkopenconnect in this test, just for this function
 * it won't get loaded under wine when cross compiling anyway */
#define openconnect__win32_strerror(err) (strdup("(Actual error text not present in tests)"))

#define OPEN_TUN_SOFTFAIL 0
#define OPEN_TUN_HARDFAIL -1

#define WINTUN_TUNNEL_TYPE L"OpenConnect"

#define VALID_WINTUN_HANDLE 7782
#define __LIST_TAPS__

#include "../tun-win32.c"
#include "../wintun.h"

static WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
static WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion;
static WINTUN_DELETE_DRIVER_FUNC *WintunDeleteDriver;
static WINTUN_SET_LOGGER_FUNC *WintunSetLogger;
static WINTUN_START_SESSION_FUNC *WintunStartSession;
static WINTUN_END_SESSION_FUNC *WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC *WintunSendPacket;

static HMODULE
InitializeWintun(void)
{
    HMODULE Wintun =
        LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!Wintun)
        return NULL;
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(Wintun, #Name)) == NULL)
    if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
        X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) ||
        X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
        X(WintunAllocateSendPacket) || X(WintunSendPacket))
#undef X
    {
        DWORD LastError = GetLastError();
        FreeLibrary(Wintun);
        SetLastError(LastError);
        return NULL;
    }
    return Wintun;
}

static void CALLBACK
ConsoleLogger(_In_ WINTUN_LOGGER_LEVEL Level, _In_ DWORD64 Timestamp, _In_z_ const WCHAR *LogLine)
{
    WCHAR LevelMarker;
    switch (Level)
    {
    case WINTUN_LOG_INFO:
        LevelMarker = L'+';
        break;
    case WINTUN_LOG_WARN:
        LevelMarker = L'-';
        break;
    case WINTUN_LOG_ERR:
        LevelMarker = L'!';
        break;
    default:
        return;
    }
    fwprintf(
        stdout,
        L"[%c] %ls\n",
        LevelMarker,
        LogLine);
}

static void
Log(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ const WCHAR *Format, ...)
{
    WCHAR LogLine[0x200];
    va_list args;
    va_start(args, Format);
    _vsnwprintf_s(LogLine, _countof(LogLine), _TRUNCATE, Format, args);
    va_end(args);
    ConsoleLogger(Level, (DWORD64) 0, LogLine);
}

WINTUN_ADAPTER_HANDLE create_wintun_adapter(PWSTR adapterName)
{
    DWORD LastError;

    GUID ExampleGuid = { 0xdeadbeef, 0xbaad, 0xcafe, { 0x77, 0x82, 0x07, 0x07, 0x82, 0xab, 0xcd, 0xef } };
    WINTUN_ADAPTER_HANDLE Adapter = WintunCreateAdapter(adapterName, WINTUN_TUNNEL_TYPE, &ExampleGuid);
    if (!Adapter)
    {
        LastError = GetLastError();
        Log(WINTUN_LOG_ERR, L"Failed to create adapter (%lu)", LastError);
        goto cleanupWintun;
    }

    NETIO_STATUS ret;
    NET_LUID luid;
    MIB_IF_ROW2 row;
    memset(&row, 0, sizeof(MIB_IF_ROW2));

    WintunGetAdapterLUID(Adapter, &luid);

    row.InterfaceLuid = luid;

    ret = GetIfEntry2(&row);

    if (ret == 0) {
        Log(WINTUN_LOG_INFO, L"Adapter Alias is: %ls", row.Alias);
    }

    WINTUN_SESSION_HANDLE Session = WintunStartSession(Adapter, 0x400000);

    if (!Session)
    {
	LastError = GetLastError();
	Log(WINTUN_LOG_ERR, L"Failed to create session (%lu)", LastError);
        goto cleanupAdapter;
    }
    else {
        ; /*Log(WINTUN_LOG_INFO, L"Wintun session started");*/
    }

    LastError = ERROR_SUCCESS;

    WintunEndSession(Session);
    /*Log(WINTUN_LOG_INFO, L"Wintun session ended");*/
	return Adapter;

cleanupAdapter:
    WintunCloseAdapter(Adapter);
    /*Log(WINTUN_LOG_INFO, L"Wintun adapter closed");*/
cleanupWintun:
    return NULL;
}

static intptr_t check_tun(struct openconnect_info *vpninfo, struct oc_adapter_info *list, wchar_t *wname)
{
    if (list) {
        struct oc_adapter_info *found = find_adapter_by_name(vpninfo, list, wname);
        if (!found || found->type != ADAPTER_WINTUN) {
            wprintf(L"Device %s was%s found%s",
                (!found ? " not" : ""), (found? ", but is not of expected type" : "")
            );
            return OPEN_TUN_SOFTFAIL;
        }

        if ( ! wcscmp(wname, found->ifname) ) {
            wprintf(L"Found %s device '%ls' guid %s\n",
                (found->type == ADAPTER_WINTUN) ? "Wintun" : "Tap", wname, found->guid);
            return VALID_WINTUN_HANDLE;
        }
    }
    return OPEN_TUN_SOFTFAIL;
}

int main(void)
{
    _setmode(_fileno(stdout), _O_U16TEXT);

    struct openconnect_info empty_info = { NULL, NULL};

    HMODULE Wintun = InitializeWintun();
    if (!Wintun) {
        DWORD LastError = GetLastError();
        Log(WINTUN_LOG_ERR, L"Failed to initialize Wintun (%lu)", LastError);
        return LastError;
    }

    WintunSetLogger(ConsoleLogger);
    Log(WINTUN_LOG_INFO, L"Wintun library loaded");

    Log(WINTUN_LOG_INFO, L"MAX_ADAPTER_NAME is: %d", MAX_ADAPTER_NAME);

    DWORD ret = 0;
    WINTUN_ADAPTER_HANDLE adapter;
    WCHAR adapterName[MAX_ADAPTER_NAME];

    memset(adapterName, 0, sizeof(adapterName));

    wsprintfW(adapterName, L"testAdapterNameForRunningLoops_");
    int add = 0;
    int len = 0;
    struct oc_adapter_info *list;

    do {
        ret = OPEN_TUN_HARDFAIL;
        wsprintfW(adapterName, L"%s%d", adapterName, add);
        add = (add+1)%10;
        len = wcslen(adapterName);
        Log(WINTUN_LOG_INFO, L"len=%3d name=%ls", len, adapterName);
        adapter = create_wintun_adapter(adapterName);

        if (adapter) {
            list = get_adapter_list(NULL);
            if (list) {
                ret = check_tun(&empty_info, list, adapterName);
                free_adapter_list(list);
            }

            WintunCloseAdapter(adapter);
            Log(WINTUN_LOG_INFO, L"Wintun adapter closed");
        }
    } while ( (len < (MAX_ADAPTER_NAME - 1)) && (ret == VALID_WINTUN_HANDLE) );

    if (ret != VALID_WINTUN_HANDLE) {
        /* last test was not successful */
        FreeLibrary(Wintun);
        return 1;
    }

    /* do an extra test with a string only with unicode characters */
    memset(adapterName, 0, sizeof(adapterName));
    wsprintfW(adapterName, L"ΌνομαΠροσαρμογέαΜόνοΣταΕλληνικά_");
    while ((len = wcslen(adapterName)) < (MAX_ADAPTER_NAME - 1)) {
        wsprintfW(adapterName, L"%ls%lc", adapterName, L'ά');
    }

    Log(WINTUN_LOG_INFO, L"len=%3d name=%ls", len, adapterName);

    ret = OPEN_TUN_HARDFAIL;
    adapter = create_wintun_adapter(adapterName);

    if (adapter) {
        list = get_adapter_list(NULL);
        if (list) {
            ret = check_tun(&empty_info, list, adapterName);
            free_adapter_list(list);
        }

        WintunCloseAdapter(adapter);
        Log(WINTUN_LOG_INFO, L"Wintun adapter closed");
    }

    FreeLibrary(Wintun);

    return (ret == VALID_WINTUN_HANDLE ? 0 : 2);
}
