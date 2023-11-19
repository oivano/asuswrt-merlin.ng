/* ANSI-C code produced by gperf version 3.1 */
/* Command-line: /usr/bin/gperf -m 10 -C -G -D -t --output-file=keywords.c ./keywords.txt  */
/* Computed positions: -k'2-3,6,$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif

#line 1 "./keywords.txt"

/*
 * Copyright (C) 2005 Andreas Steffen
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <string.h>

#define IN_GPERF_GENERATED_FILE
#include "keywords.h"

#line 22 "./keywords.txt"
struct kw_entry {
    char *name;
    kw_token_t token;
};

#define TOTAL_KEYWORDS 140
#define MIN_WORD_LENGTH 2
#define MAX_WORD_LENGTH 17
#define MIN_HASH_VALUE 9
#define MAX_HASH_VALUE 257
/* maximum key range = 249, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
hash (register const char *str, register size_t len)
{
  static const unsigned short asso_values[] =
    {
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258,  14,
      129, 258, 258, 258,   4, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258,   3, 258,  31,   4,  83,
       50,   5,   4,   1,  79,   1, 258, 121,  62,   5,
       33,  51,  41,   2,  22,   1,  25, 103,   6,   1,
      258,   8,   2, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258, 258, 258, 258, 258,
      258, 258, 258, 258, 258, 258
    };
  register unsigned int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[5]];
      /*FALLTHROUGH*/
      case 5:
      case 4:
      case 3:
        hval += asso_values[(unsigned char)str[2]];
      /*FALLTHROUGH*/
      case 2:
        hval += asso_values[(unsigned char)str[1]];
        break;
    }
  return hval + asso_values[(unsigned char)str[len - 1]];
}

static const struct kw_entry wordlist[] =
  {
#line 164 "./keywords.txt"
    {"pfs",               KW_PFS_DEPRECATED},
#line 134 "./keywords.txt"
    {"rightgroups",       KW_RIGHTGROUPS},
#line 36 "./keywords.txt"
    {"aggressive",        KW_AGGRESSIVE},
#line 45 "./keywords.txt"
    {"lifetime",          KW_KEYLIFE},
#line 126 "./keywords.txt"
    {"rightsigkey",       KW_RIGHTSIGKEY},
#line 49 "./keywords.txt"
    {"lifebytes",         KW_LIFEBYTES},
#line 53 "./keywords.txt"
    {"keyingtries",       KW_KEYINGTRIES},
#line 101 "./keywords.txt"
    {"leftsigkey",        KW_LEFTSIGKEY},
#line 46 "./keywords.txt"
    {"keylife",           KW_KEYLIFE},
#line 102 "./keywords.txt"
    {"leftrsasigkey",     KW_LEFTSIGKEY},
#line 111 "./keywords.txt"
    {"right",             KW_RIGHT},
#line 105 "./keywords.txt"
    {"leftcertpolicy",    KW_LEFTCERTPOLICY},
#line 86 "./keywords.txt"
    {"left",              KW_LEFT},
#line 113 "./keywords.txt"
    {"rightsubnet",       KW_RIGHTSUBNET},
#line 112 "./keywords.txt"
    {"rightikeport",      KW_RIGHTIKEPORT},
#line 131 "./keywords.txt"
    {"rightsendcert",     KW_RIGHTSENDCERT},
#line 109 "./keywords.txt"
    {"leftgroups",        KW_LEFTGROUPS},
#line 127 "./keywords.txt"
    {"rightrsasigkey",    KW_RIGHTSIGKEY},
#line 103 "./keywords.txt"
    {"leftcert",          KW_LEFTCERT},
#line 51 "./keywords.txt"
    {"lifepackets",       KW_LIFEPACKETS},
#line 29 "./keywords.txt"
    {"uniqueids",         KW_UNIQUEIDS},
#line 92 "./keywords.txt"
    {"leftdns",           KW_LEFTDNS},
#line 106 "./keywords.txt"
    {"leftsendcert",      KW_LEFTSENDCERT},
#line 114 "./keywords.txt"
    {"rightsubnetwithin", KW_RIGHTSUBNET},
#line 120 "./keywords.txt"
    {"rightallowany",     KW_RIGHTALLOWANY},
#line 155 "./keywords.txt"
    {"keep_alive",        KW_SETUP_DEPRECATED},
#line 116 "./keywords.txt"
    {"rightsourceip",     KW_RIGHTSOURCEIP},
#line 33 "./keywords.txt"
    {"type",              KW_TYPE},
#line 124 "./keywords.txt"
    {"rightid",           KW_RIGHTID},
#line 117 "./keywords.txt"
    {"rightdns",          KW_RIGHTDNS},
#line 72 "./keywords.txt"
    {"reqid",             KW_REQID},
#line 85 "./keywords.txt"
    {"certuribase",       KW_CERTURIBASE},
#line 167 "./keywords.txt"
    {"leftnexthop",       KW_LEFT_DEPRECATED},
#line 73 "./keywords.txt"
    {"replay_window",     KW_REPLAY_WINDOW},
#line 90 "./keywords.txt"
    {"leftprotoport",     KW_LEFTPROTOPORT},
#line 34 "./keywords.txt"
    {"compress",          KW_COMPRESS},
#line 40 "./keywords.txt"
    {"mobike",	           KW_MOBIKE},
#line 71 "./keywords.txt"
    {"me_peerid",         KW_ME_PEERID},
#line 139 "./keywords.txt"
    {"interfaces",        KW_SETUP_DEPRECATED},
#line 157 "./keywords.txt"
    {"virtual_private",   KW_SETUP_DEPRECATED},
#line 94 "./keywords.txt"
    {"lefthostaccess",    KW_LEFTHOSTACCESS},
#line 107 "./keywords.txt"
    {"leftca",            KW_LEFTCA},
#line 118 "./keywords.txt"
    {"rightfirewall",     KW_RIGHTFIREWALL},
#line 115 "./keywords.txt"
    {"rightprotoport",    KW_RIGHTPROTOPORT},
#line 65 "./keywords.txt"
    {"inactivity",        KW_INACTIVITY},
#line 93 "./keywords.txt"
    {"leftfirewall",      KW_LEFTFIREWALL},
#line 58 "./keywords.txt"
    {"esp",               KW_ESP},
#line 168 "./keywords.txt"
    {"rightnexthop",      KW_RIGHT_DEPRECATED},
#line 41 "./keywords.txt"
    {"forceencaps",       KW_FORCEENCAPS},
#line 95 "./keywords.txt"
    {"leftallowany",      KW_LEFTALLOWANY},
#line 79 "./keywords.txt"
    {"crluri",            KW_CRLURI},
#line 96 "./keywords.txt"
    {"leftupdown",        KW_LEFTUPDOWN},
#line 75 "./keywords.txt"
    {"mark_in",           KW_MARK_IN},
#line 31 "./keywords.txt"
    {"strictcrlpolicy",   KW_STRICTCRLPOLICY},
#line 156 "./keywords.txt"
    {"force_keepalive",   KW_SETUP_DEPRECATED},
#line 119 "./keywords.txt"
    {"righthostaccess",   KW_RIGHTHOSTACCESS},
#line 50 "./keywords.txt"
    {"marginbytes",       KW_MARGINBYTES},
#line 70 "./keywords.txt"
    {"mediated_by",       KW_MEDIATED_BY},
#line 52 "./keywords.txt"
    {"marginpackets",     KW_MARGINPACKETS},
#line 48 "./keywords.txt"
    {"margintime",        KW_REKEYMARGIN},
#line 42 "./keywords.txt"
    {"fragmentation",     KW_FRAGMENTATION},
#line 165 "./keywords.txt"
    {"pfsgroup",          KW_PFS_DEPRECATED},
#line 80 "./keywords.txt"
    {"crluri1",           KW_CRLURI},
#line 130 "./keywords.txt"
    {"rightcertpolicy",   KW_RIGHTCERTPOLICY},
#line 150 "./keywords.txt"
    {"hidetos",           KW_SETUP_DEPRECATED},
#line 32 "./keywords.txt"
    {"keyexchange",       KW_KEYEXCHANGE},
#line 91 "./keywords.txt"
    {"leftsourceip",      KW_LEFTSOURCEIP},
#line 82 "./keywords.txt"
    {"ocspuri",           KW_OCSPURI},
#line 99 "./keywords.txt"
    {"leftid",            KW_LEFTID},
#line 166 "./keywords.txt"
    {"eap",               KW_CONN_DEPRECATED},
#line 35 "./keywords.txt"
    {"installpolicy",     KW_INSTALLPOLICY},
#line 136 "./keywords.txt"
    {"also",              KW_ALSO},
#line 128 "./keywords.txt"
    {"rightcert",         KW_RIGHTCERT},
#line 122 "./keywords.txt"
    {"rightauth",         KW_RIGHTAUTH},
#line 69 "./keywords.txt"
    {"mediation",         KW_MEDIATION},
#line 132 "./keywords.txt"
    {"rightca",           KW_RIGHTCA},
#line 143 "./keywords.txt"
    {"klipsdebug",        KW_SETUP_DEPRECATED},
#line 163 "./keywords.txt"
    {"ldapbase",          KW_CA_DEPRECATED},
#line 151 "./keywords.txt"
    {"overridemtu",       KW_SETUP_DEPRECATED},
#line 64 "./keywords.txt"
    {"sha256_96",         KW_SHA256_96},
#line 83 "./keywords.txt"
    {"ocspuri1",          KW_OCSPURI},
#line 61 "./keywords.txt"
    {"dpdtimeout",        KW_DPDTIMEOUT},
#line 39 "./keywords.txt"
    {"aaa_identity",      KW_AAA_IDENTITY},
#line 57 "./keywords.txt"
    {"ike",               KW_IKE},
#line 76 "./keywords.txt"
    {"mark_out",          KW_MARK_OUT},
#line 140 "./keywords.txt"
    {"dumpdir",           KW_SETUP_DEPRECATED},
#line 55 "./keywords.txt"
    {"rekey",             KW_REKEY},
#line 125 "./keywords.txt"
    {"rightid2",          KW_RIGHTID2},
#line 54 "./keywords.txt"
    {"rekeyfuzz",         KW_REKEYFUZZ},
#line 38 "./keywords.txt"
    {"eap_identity",      KW_EAP_IDENTITY},
#line 135 "./keywords.txt"
    {"rightgroups2",      KW_RIGHTGROUPS2},
#line 44 "./keywords.txt"
    {"ikelifetime",       KW_IKELIFETIME},
#line 88 "./keywords.txt"
    {"leftsubnet",        KW_LEFTSUBNET},
#line 121 "./keywords.txt"
    {"rightupdown",       KW_RIGHTUPDOWN},
#line 37 "./keywords.txt"
    {"authby",            KW_AUTHBY},
#line 104 "./keywords.txt"
    {"leftcert2",         KW_LEFTCERT2},
#line 154 "./keywords.txt"
    {"nat_traversal",     KW_SETUP_DEPRECATED},
#line 28 "./keywords.txt"
    {"charondebug",       KW_CHARONDEBUG},
#line 62 "./keywords.txt"
    {"dpdaction",         KW_DPDACTION},
#line 68 "./keywords.txt"
    {"xauth_identity",    KW_XAUTH_IDENTITY},
#line 59 "./keywords.txt"
    {"ah",                KW_AH},
#line 89 "./keywords.txt"
    {"leftsubnetwithin",  KW_LEFTSUBNET},
#line 66 "./keywords.txt"
    {"modeconfig",        KW_MODECONFIG},
#line 162 "./keywords.txt"
    {"ldaphost",          KW_CA_DEPRECATED},
#line 87 "./keywords.txt"
    {"leftikeport",       KW_LEFTIKEPORT},
#line 152 "./keywords.txt"
    {"crlcheckinterval",  KW_SETUP_DEPRECATED},
#line 60 "./keywords.txt"
    {"dpddelay",          KW_DPDDELAY},
#line 78 "./keywords.txt"
    {"cacert",            KW_CACERT},
#line 110 "./keywords.txt"
    {"leftgroups2",       KW_LEFTGROUPS2},
#line 123 "./keywords.txt"
    {"rightauth2",        KW_RIGHTAUTH2},
#line 77 "./keywords.txt"
    {"tfc",               KW_TFC},
#line 146 "./keywords.txt"
    {"postpluto",         KW_SETUP_DEPRECATED},
#line 47 "./keywords.txt"
    {"rekeymargin",       KW_REKEYMARGIN},
#line 108 "./keywords.txt"
    {"leftca2",           KW_LEFTCA2},
#line 149 "./keywords.txt"
    {"packetdefault",     KW_SETUP_DEPRECATED},
#line 74 "./keywords.txt"
    {"mark",              KW_MARK},
#line 141 "./keywords.txt"
    {"charonstart",       KW_SETUP_DEPRECATED},
#line 147 "./keywords.txt"
    {"plutostderrlog",    KW_SETUP_DEPRECATED},
#line 137 "./keywords.txt"
    {"auto",              KW_AUTO},
#line 148 "./keywords.txt"
    {"fragicmp",          KW_SETUP_DEPRECATED},
#line 63 "./keywords.txt"
    {"closeaction",       KW_CLOSEACTION},
#line 145 "./keywords.txt"
    {"prepluto",          KW_SETUP_DEPRECATED},
#line 100 "./keywords.txt"
    {"leftid2",           KW_LEFTID2},
#line 153 "./keywords.txt"
    {"nocrsend",          KW_SETUP_DEPRECATED},
#line 97 "./keywords.txt"
    {"leftauth",          KW_LEFTAUTH},
#line 56 "./keywords.txt"
    {"reauth",            KW_REAUTH},
#line 142 "./keywords.txt"
    {"plutostart",        KW_SETUP_DEPRECATED},
#line 30 "./keywords.txt"
    {"cachecrls",         KW_CACHECRLS},
#line 67 "./keywords.txt"
    {"xauth",             KW_XAUTH},
#line 81 "./keywords.txt"
    {"crluri2",           KW_CRLURI2},
#line 133 "./keywords.txt"
    {"rightca2",          KW_RIGHTCA2},
#line 129 "./keywords.txt"
    {"rightcert2",        KW_RIGHTCERT2},
#line 144 "./keywords.txt"
    {"plutodebug",        KW_SETUP_DEPRECATED},
#line 159 "./keywords.txt"
    {"pkcs11initargs",    KW_PKCS11_DEPRECATED},
#line 158 "./keywords.txt"
    {"pkcs11module",      KW_PKCS11_DEPRECATED},
#line 161 "./keywords.txt"
    {"pkcs11proxy",       KW_PKCS11_DEPRECATED},
#line 160 "./keywords.txt"
    {"pkcs11keepstate",   KW_PKCS11_DEPRECATED},
#line 84 "./keywords.txt"
    {"ocspuri2",          KW_OCSPURI2},
#line 98 "./keywords.txt"
    {"leftauth2",         KW_LEFTAUTH2},
#line 43 "./keywords.txt"
    {"ikedscp",           KW_IKEDSCP,}
  };

static const short lookup[] =
  {
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,   0,
     -1,  -1,  -1,  -1,  -1,   1,  -1,  -1,   2,   3,
     -1,  -1,   4,   5,  -1,  -1,   6,  -1,   7,   8,
     -1,   9,  10,  -1,  -1,  -1,  11,  -1,  12,  13,
     14,  15,  16,  -1,  -1,  -1,  17,  18,  19,  20,
     21,  22,  -1,  23,  24,  -1,  25,  26,  27,  -1,
     28,  29,  30,  -1,  -1,  31,  32,  -1,  33,  34,
     35,  36,  37,  38,  39,  40,  -1,  41,  -1,  -1,
     -1,  42,  43,  44,  45,  -1,  46,  -1,  47,  -1,
     48,  49,  50,  51,  52,  53,  54,  55,  56,  57,
     58,  59,  -1,  -1,  60,  61,  62,  -1,  63,  -1,
     64,  -1,  65,  66,  67,  68,  69,  70,  71,  72,
     -1,  73,  74,  75,  76,  77,  78,  79,  80,  -1,
     -1,  81,  82,  -1,  83,  -1,  -1,  84,  85,  86,
     87,  88,  89,  -1,  90,  -1,  91,  92,  -1,  93,
     94,  -1,  95,  96,  -1,  97,  -1,  -1,  98,  99,
    100, 101,  -1, 102,  -1, 103, 104, 105,  -1, 106,
    107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
     -1, 117,  -1, 118,  -1, 119,  -1,  -1, 120, 121,
     -1,  -1,  -1,  -1,  -1, 122,  -1, 123,  -1, 124,
    125, 126,  -1,  -1,  -1,  -1,  -1, 127,  -1,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1, 128,  -1,
     -1, 129, 130,  -1, 131,  -1, 132,  -1,  -1,  -1,
     -1,  -1,  -1, 133,  -1, 134,  -1, 135, 136,  -1,
     -1,  -1,  -1, 137,  -1,  -1,  -1,  -1,  -1,  -1,
    138,  -1,  -1,  -1,  -1,  -1,  -1, 139
  };

const struct kw_entry *
in_word_set (register const char *str, register size_t len)
{
  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register unsigned int key = hash (str, len);

      if (key <= MAX_HASH_VALUE)
        {
          register int index = lookup[key];

          if (index >= 0)
            {
              register const char *s = wordlist[index].name;

              if (*str == *s && !strcmp (str + 1, s + 1))
                return &wordlist[index];
            }
        }
    }
  return 0;
}
