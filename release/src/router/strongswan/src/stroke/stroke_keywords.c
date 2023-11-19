/* ANSI-C code produced by gperf version 3.1 */
/* Command-line: /usr/bin/gperf -m 10 -D -C -G -t --output-file=stroke_keywords.c ./stroke_keywords.txt  */
/* Computed positions: -k'1,5,7' */

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

#line 1 "./stroke_keywords.txt"

/*
 * Copyright (C) 2006 Andreas Steffen
 *
 * Copyright (C) secunet Security Networks AG
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

#include "stroke_keywords.h"

#line 23 "./stroke_keywords.txt"
struct stroke_token {
    char *name;
    stroke_keyword_t kw;
};

#define TOTAL_KEYWORDS 48
#define MIN_WORD_LENGTH 2
#define MAX_WORD_LENGTH 15
#define MIN_HASH_VALUE 3
#define MAX_HASH_VALUE 59
/* maximum key range = 57, duplicates = 0 */

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
  static const unsigned char asso_values[] =
    {
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 25, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60,  0, 18,  1,
       1, 15, 60, 23, 60, 23, 60, 11,  0,  7,
      60, 24, 14, 60,  6,  9, 16,  9, 60, 60,
       2,  3, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
      60, 60, 60, 60, 60, 60
    };
  register unsigned int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[6]];
      /*FALLTHROUGH*/
      case 6:
      case 5:
        hval += asso_values[(unsigned char)str[4]];
      /*FALLTHROUGH*/
      case 4:
      case 3:
      case 2:
      case 1:
        hval += asso_values[(unsigned char)str[0]];
        break;
    }
  return hval;
}

static const struct stroke_token wordlist[] =
  {
#line 28 "./stroke_keywords.txt"
    {"add",             STROKE_ADD},
#line 29 "./stroke_keywords.txt"
    {"del",             STROKE_DEL},
#line 35 "./stroke_keywords.txt"
    {"down",            STROKE_DOWN},
#line 56 "./stroke_keywords.txt"
    {"listall",         STROKE_LIST_ALL},
#line 52 "./stroke_keywords.txt"
    {"listcrls",        STROKE_LIST_CRLS},
#line 33 "./stroke_keywords.txt"
    {"up",              STROKE_UP},
#line 48 "./stroke_keywords.txt"
    {"listaacerts",     STROKE_LIST_AACERTS},
#line 46 "./stroke_keywords.txt"
    {"listcacerts",     STROKE_LIST_CACERTS},
#line 38 "./stroke_keywords.txt"
    {"rekey",           STROKE_REKEY},
#line 63 "./stroke_keywords.txt"
    {"rereadall",       STROKE_REREAD_ALL},
#line 45 "./stroke_keywords.txt"
    {"listcerts",       STROKE_LIST_CERTS},
#line 62 "./stroke_keywords.txt"
    {"rereadcrls",      STROKE_REREAD_CRLS},
#line 61 "./stroke_keywords.txt"
    {"rereadacerts",    STROKE_REREAD_ACERTS},
#line 60 "./stroke_keywords.txt"
    {"rereadaacerts",   STROKE_REREAD_AACERTS},
#line 58 "./stroke_keywords.txt"
    {"rereadcacerts",   STROKE_REREAD_CACERTS},
#line 71 "./stroke_keywords.txt"
    {"leases",          STROKE_LEASES},
#line 74 "./stroke_keywords.txt"
    {"listcounters",    STROKE_COUNTERS},
#line 30 "./stroke_keywords.txt"
    {"delete",          STROKE_DELETE},
#line 40 "./stroke_keywords.txt"
    {"status",          STROKE_STATUS},
#line 49 "./stroke_keywords.txt"
    {"listacerts",      STROKE_LIST_ACERTS},
#line 31 "./stroke_keywords.txt"
    {"route",           STROKE_ROUTE},
#line 41 "./stroke_keywords.txt"
    {"statusall",       STROKE_STATUSALL},
#line 57 "./stroke_keywords.txt"
    {"rereadsecrets",   STROKE_REREAD_SECRETS},
#line 42 "./stroke_keywords.txt"
    {"statusallnb",     STROKE_STATUSALL_NOBLK},
#line 43 "./stroke_keywords.txt"
    {"statusall-nb",    STROKE_STATUSALL_NOBLK},
#line 54 "./stroke_keywords.txt"
    {"listalgs",        STROKE_LIST_ALGS},
#line 34 "./stroke_keywords.txt"
    {"up-nb",           STROKE_UP_NOBLK},
#line 68 "./stroke_keywords.txt"
    {"exportx509",      STROKE_EXPORT_X509},
#line 55 "./stroke_keywords.txt"
    {"listplugins",     STROKE_LIST_PLUGINS},
#line 51 "./stroke_keywords.txt"
    {"listcainfos",     STROKE_LIST_CAINFOS},
#line 69 "./stroke_keywords.txt"
    {"exportconncert",  STROKE_EXPORT_CONN_CERT},
#line 70 "./stroke_keywords.txt"
    {"exportconnchain", STROKE_EXPORT_CONN_CHAIN},
#line 39 "./stroke_keywords.txt"
    {"loglevel",        STROKE_LOGLEVEL},
#line 64 "./stroke_keywords.txt"
    {"purgeocsp",       STROKE_PURGE_OCSP},
#line 32 "./stroke_keywords.txt"
    {"unroute",         STROKE_UNROUTE},
#line 53 "./stroke_keywords.txt"
    {"listocsp",        STROKE_LIST_OCSP},
#line 37 "./stroke_keywords.txt"
    {"down-srcip",      STROKE_DOWN_SRCIP},
#line 44 "./stroke_keywords.txt"
    {"listpubkeys",     STROKE_LIST_PUBKEYS},
#line 65 "./stroke_keywords.txt"
    {"purgecrls",       STROKE_PURGE_CRLS},
#line 59 "./stroke_keywords.txt"
    {"rereadocspcerts", STROKE_REREAD_OCSPCERTS},
#line 47 "./stroke_keywords.txt"
    {"listocspcerts",   STROKE_LIST_OCSPCERTS},
#line 72 "./stroke_keywords.txt"
    {"memusage",        STROKE_MEMUSAGE},
#line 67 "./stroke_keywords.txt"
    {"purgeike",        STROKE_PURGE_IKE},
#line 73 "./stroke_keywords.txt"
    {"user-creds",      STROKE_USER_CREDS},
#line 36 "./stroke_keywords.txt"
    {"down-nb",         STROKE_DOWN_NOBLK},
#line 66 "./stroke_keywords.txt"
    {"purgecerts",      STROKE_PURGE_CERTS},
#line 50 "./stroke_keywords.txt"
    {"listgroups",      STROKE_LIST_GROUPS},
#line 75 "./stroke_keywords.txt"
    {"resetcounters",   STROKE_COUNTERS_RESET}
  };

static const signed char lookup[] =
  {
    -1, -1, -1,  0,  1,  2, -1,  3, -1,  4, -1,  5,  6,  7,
     8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
    36, 37, 38, 39, 40, 41, 42, -1, 43, 44, -1, -1, 45, -1,
    -1, 46, -1, 47
  };

const struct stroke_token *
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
