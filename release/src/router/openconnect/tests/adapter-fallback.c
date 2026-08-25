/*
 * OpenConnect (SSL + DTLS) VPN client
 *
  * Copyright © 2024 Marios Paouris
 *
 * Author: Marios Paouris <mspaourh@gmail.com>
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

#define LIST_APPEND(__list, __end, __new) do { \
    if (!__list) \
        __list = __new; \
    if (__end) \
        __end->next = __new; \
    __end = __new; \
} while (0);

struct openconnect_info {
	char *ifname;
    wchar_t *ifname_w;
};

/* don't link linkopenconnect in this test, just for this function
 * it won't get loaded under wine when cross compiling anyway */
#define openconnect__win32_strerror(err) (strdup("(Actual error text not present in tests)"))

#define OPEN_TUN_SOFTFAIL 0
#define OPEN_TUN_HARDFAIL -1

#define __LIST_TAPS__

#define MAX_FALLBACK_TRIES 15

#include "../tun-win32.c"

#define NORMAL_CASE L"www.vpnserver.org"
#define EDGE_CASE L"AVeryLongAdapterWhoseNameConsistsOfExactlyOneHundredTwentySevenCharactersAndNeedsTooManyWordsToSatisfyThisLooongParticularLimit"
#define LONG_CASE L"AnotherVeryLongAdapterWhoseNameConsistsOfExactlyOneHundredTwentySevenCharactersAndNeedsTooManyWordsToSatisfyThisLooongParticularLimit+PlusMoreToTruncate"
#define LONG_CASE_EXPECT L"AnotherVeryLongAdapterWhoseNameConsistsOfExactlyOneHundredTwentySevenCharactersAndNeedsTooManyWordsToSatisfyThisLooongParticula"
#define WC_ZERO 0xfeff0030 /* DIGIT ZERO (U+0030) */
#define WC_GCLEF_HIGH 0xD834 /* U+1D11E Musical Symbol G Clef = 0xD834 0xDD1E */
#define WC_GCLEF_LOW  0xDD1E /* U+1D11E Musical Symbol G Clef = 0xD834 0xDD1E */

static void CALLBACK
ConsoleLogger(_In_z_ const WCHAR *LogLine)
{
    fwprintf(
        stdout,
        L"%ls\n",
        LogLine);
}

static void
Log(_In_z_ const WCHAR *Format, ...)
{
    WCHAR LogLine[0x200];
    va_list args;
    va_start(args, Format);
    _vsnwprintf_s(LogLine, _countof(LogLine), _TRUNCATE, Format, args);
    va_end(args);
    ConsoleLogger(LogLine);
}

/* iteratively try to find an adapter name with a given prefix.
   after each try, add the adapter to the list so the next try will find it in the list
   and generate another name,
   Repeat until max tries has been reached and no adapter name can be found
 */

static int test_repeated(wchar_t* prefix, int max_tries, wchar_t expectedNames[][MAX_ADAPTER_NAME])
{
    struct openconnect_info empty_info = { NULL, NULL};
    struct oc_adapter_info *list = NULL, *end = NULL;
    int ret = 0;
    Log(L"Test prefix  : %s for %d tries", prefix, max_tries);

    for (int i = 0; i <= (max_tries + 1); i++) {
        wchar_t * adapterName = first_available_adapter_name(&empty_info, list, prefix);

        if (adapterName) {
            Log(L"%2d: available: %s\n" \
                 L"     expected: %s", i, adapterName, (i < max_tries ? expectedNames[i]: L""));

            struct oc_adapter_info *new = adapter_alloc(&empty_info, ADAPTER_NONE, adapterName, "");
            LIST_APPEND(list, end, new);

            if (i == max_tries) {
                Log(L"Available adapter name was not expected: %s", adapterName);
                ret = 1;
                goto out;
            }

            if (wcscmp(expectedNames[i], adapterName)) {
                Log(L"Available adapter name does not match expected adapter name");
                ret = 1;
                goto out;
            }
        }
        else {
            if ( i != max_tries) {
                Log(L"Could not find an available adapter name, expected %s", expectedNames[i]);
                ret = 2;
                goto out;
            }
            i = max_tries + 10;
        }
    }

out:
    free_adapter_list(list);
    Log(L"");

    return ret;
}

static int test_single(wchar_t *prefix, wchar_t *expectedName)
{
    struct openconnect_info empty_info = { NULL, NULL};
    struct oc_adapter_info *list = NULL;
    int ret = 0;
    Log(L"Test prefix  : %s", prefix);

    wchar_t * adapterName = first_available_adapter_name(&empty_info, list, prefix);

    if (adapterName) {
        Log(L"  : available: %s\n" \
            L"     expected: %s", adapterName, expectedName);

        struct oc_adapter_info *new = adapter_alloc(&empty_info, ADAPTER_NONE, adapterName, "");

        if (wcscmp(expectedName, adapterName)) {
            Log(L"Available adapter name does not match expected adapter name");
            ret = 5;
            goto out;
        }

        free(adapterName);
    }
    else {
        Log(L"Could not find an available adapter name, expected %s", expectedName);
        ret = 6;
    }

out:
    Log(L"");
    return ret;
}

int main(void)
{
    _setmode(_fileno(stdout), _O_U16TEXT);

    int ret = 0;

    wchar_t expectedNames[MAX_FALLBACK_TRIES + 1][MAX_ADAPTER_NAME];

    /* test the common case: a vpn url with a normal length (less than MAX_ADAPTER_NAME). */
    memset(expectedNames, 0, sizeof(expectedNames));
    wcsncpy(expectedNames[0], NORMAL_CASE, MAX_ADAPTER_NAME - 1);
    for (int i = 1; i <= MAX_FALLBACK_TRIES; i++) {
        _snwprintf(expectedNames[i], MAX_ADAPTER_NAME - 1, L"%s%d", NORMAL_CASE, i);
    }

    ret = test_repeated(NORMAL_CASE, MAX_FALLBACK_TRIES, expectedNames);

    if (ret) {
        return 1;
    }

    /* test an edge case: a name with the maximum allowed length (MAX_ADAPTER_NAME - 1). */
    memset(expectedNames, 0, sizeof(expectedNames));
    wcsncpy(expectedNames[0], EDGE_CASE, MAX_ADAPTER_NAME - 1);
    for (int i = 1; i <= MAX_FALLBACK_TRIES; i++) {
        wcsncpy(expectedNames[i], EDGE_CASE, MAX_ADAPTER_NAME - 1);
        int rem = i % 10;
        expectedNames[i][MAX_ADAPTER_NAME -2] = (WC_ZERO + rem);
        int quot = i / 10;
        if (quot > 0) {
            expectedNames[i][MAX_ADAPTER_NAME -3] = (WC_ZERO + quot);
        }
    }

    ret = test_repeated(EDGE_CASE, MAX_FALLBACK_TRIES, expectedNames);

    if (ret) {
        return 2;
    }


    /* test the case where the name needs to be truncated*/
    ret = test_single(LONG_CASE, LONG_CASE_EXPECT);
    if (ret) {
        return 3;
    }

    /* test the case when the name needs to be truncated and a surrogate pair is present at the truncation point */
    size_t len = sizeof(LONG_CASE)/sizeof(wchar_t) - 1;
    wchar_t adapterName[sizeof(LONG_CASE) + 1];
    memset(adapterName, 0, sizeof(adapterName));
    wcsncpy(adapterName, LONG_CASE, len);
    adapterName[len + 1] = 0;
    adapterName[MAX_ADAPTER_NAME - 2] = WC_GCLEF_HIGH ;
    adapterName[MAX_ADAPTER_NAME - 1] = WC_GCLEF_LOW ;

    memset(expectedNames, 0, sizeof(expectedNames));
    wcsncpy(expectedNames[0], LONG_CASE, MAX_ADAPTER_NAME - 2);

    ret = test_single(adapterName, expectedNames[0]);
    if (ret) {
        return 4;
    }

    /* test the case when the name needs to be truncated and a surrogate pair is present just before the truncation point */
    memset(adapterName, 0, sizeof(adapterName));
    wcsncpy(adapterName, LONG_CASE, len);
    adapterName[len + 1] = 0;
    adapterName[MAX_ADAPTER_NAME - 3] = WC_GCLEF_HIGH;
    adapterName[MAX_ADAPTER_NAME - 2] = WC_GCLEF_LOW;

    memset(expectedNames, 0, sizeof(expectedNames));
    wcsncpy(expectedNames[0], adapterName, MAX_ADAPTER_NAME - 1);

    for (int i = 1 ; i <= MAX_FALLBACK_TRIES; i++) {
        wcsncpy(expectedNames[i], expectedNames[0], MAX_ADAPTER_NAME - 1);
        int rem = i % 10;
        int quot = i / 10;

        expectedNames[i][MAX_ADAPTER_NAME - 3] = WC_ZERO + ( quot > 0 ? quot: rem ); 
        expectedNames[i][MAX_ADAPTER_NAME - 2] = ( quot > 0 ? WC_ZERO + rem : 0); 
        expectedNames[i][MAX_ADAPTER_NAME - 1] = 0;
    }

    ret = test_repeated(adapterName, MAX_FALLBACK_TRIES, expectedNames);
    if (ret) {
        return 5;
    }

    return ret;
}
