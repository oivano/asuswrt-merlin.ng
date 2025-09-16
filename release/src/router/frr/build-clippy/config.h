/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* bfdd control socket */
#define BFDD_CONTROL_SOCKET "/var/run/bfdd.sock"

/* bfdd */
/* #undef BFD_BSD */

/* bfdd */
/* #undef BFD_LINUX */

/* BSD v6 sysctl to turn on and off forwarding */
/* #undef BSD_V6_SYSCTL */

/* Mask for config files */
#define CONFIGFILE_MASK 0600

/* Consumed Time Check */
#define CONSUMED_TIME_CHECK 5000000

/* daemon vty directory */
#define DAEMON_VTY_DIR "/var/run"

/* Build for development */
/* #undef DEV_BUILD */

/* Name of the configuration default set */
#define DFLT_NAME "traditional"

/* Disable BGP installation to zebra */
#define DISABLE_BGP_ANNOUNCE 0

/* Enable BGP VNC support */
#define ENABLE_BGP_VNC 1

/* found_ssh */
/* #undef FOUND_SSH */

/* did autoconf checks for atomic funcs */
#define FRR_AUTOCONF_ATOMIC 1

/* frr Group */
#define FRR_GROUP "frr"

/* frr User */
#define FRR_USER "frr"

/* include git version info */
/* #undef GIT_VERSION */

/* GNU Linux */
#define GNU_LINUX /**/

/* Compile extensions to use with a fuzzer for netlink */
/* #undef HANDLE_NETLINK_FUZZING */

/* Compile extensions to use with a fuzzer */
/* #undef HANDLE_ZAPI_FUZZING */

/* Define to 1 if you have the `alarm' function. */
#define HAVE_ALARM 1

/* Have history.h append_history */
/* #undef HAVE_APPEND_HISTORY */

/* Define to 1 if you have the <asm/types.h> header file. */
#define HAVE_ASM_TYPES_H 1

/* bfdd */
#define HAVE_BFDD 0

/* BSD ifi_link_state available */
/* #undef HAVE_BSD_IFI_LINK_STATE */

/* BSD link-detect */
/* #undef HAVE_BSD_LINK_DETECT */

/* Can pass ifindex in struct ip_mreq */
/* #undef HAVE_BSD_STRUCT_IP_MREQ_HACK */

/* capabilities */
/* #undef HAVE_CAPABILITIES */

/* Have monotonic clock */
#define HAVE_CLOCK_MONOTONIC /**/

/* Compile Special Cumulus Code in */
/* #undef HAVE_CUMULUS */

/* Compile extensions for a DataCenter */
/* #undef HAVE_DATACENTER */

/* Define to 1 if you have the declaration of `be32dec', and to 0 if you
   don't. */
#define HAVE_DECL_BE32DEC 0

/* Define to 1 if you have the declaration of `be32enc', and to 0 if you
   don't. */
#define HAVE_DECL_BE32ENC 0

/* Define to 1 if you have the declaration of `TCP_MD5SIG', and to 0 if you
   don't. */
#define HAVE_DECL_TCP_MD5SIG 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Have dlinfo RTLD_DI_LINKMAP */
#define HAVE_DLINFO_LINKMAP 1

/* Have dlinfo RTLD_DI_ORIGIN */
#define HAVE_DLINFO_ORIGIN 1

/* Define to 1 if your system has a working POSIX `fnmatch' function. */
#define HAVE_FNMATCH 1

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* Define to 1 if you have the `getgrouplist' function. */
#define HAVE_GETGROUPLIST 1

/* Glibc backtrace */
#define HAVE_GLIBC_BACKTRACE /**/

/* Define to 1 if you have the <inet/nd.h> header file. */
/* #undef HAVE_INET_ND_H */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Have IP_FREEBIND */
#define HAVE_IP_FREEBIND 1

/* Have IP_PKTINFO */
#define HAVE_IP_PKTINFO 1

/* Have IP_RECVDSTADDR */
/* #undef HAVE_IP_RECVDSTADDR */

/* Have IP_RECVIF */
/* #undef HAVE_IP_RECVIF */

/* Define to 1 if you have the <json-c/json.h> header file. */
/* #undef HAVE_JSON_C_JSON_H */

/* Define to 1 if you have the <kvm.h> header file. */
/* #undef HAVE_KVM_H */

/* Capabilities */
/* #undef HAVE_LCAPS */

/* ldpd */
#define HAVE_LDPD 1

/* Define to 1 if you have the `crypt' library (-lcrypt). */
#define HAVE_LIBCRYPT 1

/* Define to 1 if you have the `crypto' library (-lcrypto). */
/* #undef HAVE_LIBCRYPTO */

/* Define to 1 if you have the `nsl' library (-lnsl). */
/* #undef HAVE_LIBNSL */

/* Define to 1 if you have the `pcreposix' library (-lpcreposix). */
/* #undef HAVE_LIBPCREPOSIX */

/* Define to 1 if you have the `resolv' library (-lresolv). */
/* #undef HAVE_LIBRESOLV */

/* Define to 1 if you have the `socket' library (-lsocket). */
/* #undef HAVE_LIBSOCKET */

/* Define to 1 if you have the `umem' library (-lumem). */
/* #undef HAVE_LIBUMEM */

/* Define to 1 if you have the <link.h> header file. */
#define HAVE_LINK_H 1

/* Define to 1 if you have the <linux/mroute.h> header file. */
#define HAVE_LINUX_MROUTE_H 1

/* Define to 1 if you have the <linux/version.h> header file. */
#define HAVE_LINUX_VERSION_H 1

/* mallinfo */
#define HAVE_MALLINFO /**/

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the <malloc/malloc.h> header file. */
/* #undef HAVE_MALLOC_MALLOC_H */

/* malloc_size */
/* #undef HAVE_MALLOC_SIZE */

/* malloc_usable_size */
#define HAVE_MALLOC_USABLE_SIZE /**/

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <netinet6/in6.h> header file. */
/* #undef HAVE_NETINET6_IN6_H */

/* Define to 1 if you have the <netinet6/in6_var.h> header file. */
/* #undef HAVE_NETINET6_IN6_VAR_H */

/* Define to 1 if you have the <netinet6/nd6.h> header file. */
/* #undef HAVE_NETINET6_ND6_H */

/* Define to 1 if you have the <netinet/in6_var.h> header file. */
/* #undef HAVE_NETINET_IN6_VAR_H */

/* Define to 1 if you have the <netinet/in_var.h> header file. */
/* #undef HAVE_NETINET_IN_VAR_H */

/* Define to 1 if you have the <netinet/ip_icmp.h> header file. */
#define HAVE_NETINET_IP_ICMP_H 1

/* Define to 1 if you have the <netinet/ip_mroute.h> header file. */
/* #undef HAVE_NETINET_IP_MROUTE_H */

/* netlink */
#define HAVE_NETLINK /**/

/* Have netns */
#define HAVE_NETNS /**/

/* Define to 1 if you have the <net/if_dl.h> header file. */
/* #undef HAVE_NET_IF_DL_H */

/* Define to 1 if you have the <net/if_var.h> header file. */
/* #undef HAVE_NET_IF_VAR_H */

/* Define to 1 if you have the <net/netopt.h> header file. */
/* #undef HAVE_NET_NETOPT_H */

/* NET_RT_IFLIST */
/* #undef HAVE_NET_RT_IFLIST */

/* Have openpam.h */
/* #undef HAVE_OPENPAM_H */

/* Have pam_misc.h */
/* #undef HAVE_PAM_MISC_H */

/* have NetBSD pollts() */
/* #undef HAVE_POLLTS */

/* Define to 1 if you have the `pow' function. */
#define HAVE_POW 1

/* have Linux/BSD ppoll() */
#define HAVE_PPOLL 1

/* Solaris printstack */
/* #undef HAVE_PRINTSTACK */

/* Define to 1 if you have the <priv.h> header file. */
/* #undef HAVE_PRIV_H */

/* protobuf */
/* #undef HAVE_PROTOBUF */

/* prctl */
#define HAVE_PR_SET_KEEPCAPS /**/

/* Have PTHREAD_PRIO_INHERIT. */
#define HAVE_PTHREAD_PRIO_INHERIT 1

/* Have RFC3678 protocol-independed API */
#define HAVE_RFC3678 1

/* Enable IPv6 Routing Advertisement support */
#define HAVE_RTADV /**/

/* Define to 1 if you have the `setns' function. */
#define HAVE_SETNS 1

/* Allow user to use ssh/telnet/bash */
/* #undef HAVE_SHELL_ACCESS */

/* getpflags */
/* #undef HAVE_SOLARIS_CAPABILITIES */

/* Have SO_BINDANY */
/* #undef HAVE_SO_BINDANY */

/* Stack symbol decoding */
#define HAVE_STACK_TRACE /**/

/* Define to 1 if `stat' has the bug that it succeeds when given the
   zero-length file name argument. */
/* #undef HAVE_STAT_EMPTY_STRING_BUG */

/* found stdatomic.h */
#define HAVE_STDATOMIC_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strlcat' function. */
/* #undef HAVE_STRLCAT */

/* Define to 1 if you have the `strlcpy' function. */
/* #undef HAVE_STRLCPY */

/* Define to 1 if you have the <stropts.h> header file. */
/* #undef HAVE_STROPTS_H */

/* Define to 1 if the system has the type `struct icmphdr'. */
#define HAVE_STRUCT_ICMPHDR 1

/* Define to 1 if the system has the type `struct if6_aliasreq'. */
/* #undef HAVE_STRUCT_IF6_ALIASREQ */

/* Define to 1 if `ifra_lifetime' is a member of `struct if6_aliasreq'. */
/* #undef HAVE_STRUCT_IF6_ALIASREQ_IFRA_LIFETIME */

/* Define to 1 if the system has the type `struct ifaliasreq'. */
/* #undef HAVE_STRUCT_IFALIASREQ */

/* Define to 1 if `ifm_status' is a member of `struct ifmediareq'. */
/* #undef HAVE_STRUCT_IFMEDIAREQ_IFM_STATUS */

/* Define to 1 if `ifi_link_state' is a member of `struct if_data'. */
/* #undef HAVE_STRUCT_IF_DATA_IFI_LINK_STATE */

/* Define to 1 if the system has the type `struct igmpmsg'. */
#define HAVE_STRUCT_IGMPMSG 1

/* Define to 1 if the system has the type `struct in6_aliasreq'. */
/* #undef HAVE_STRUCT_IN6_ALIASREQ */

/* Define to 1 if the system has the type `struct in_pktinfo'. */
#define HAVE_STRUCT_IN_PKTINFO 1

/* Define to 1 if `imr_ifindex' is a member of `struct ip_mreqn'. */
#define HAVE_STRUCT_IP_MREQN_IMR_IFINDEX 1

/* Define to 1 if the system has the type `struct mfcctl'. */
#define HAVE_STRUCT_MFCCTL 1

/* Define to 1 if the system has the type `struct nd_opt_adv_interval'. */
#define HAVE_STRUCT_ND_OPT_ADV_INTERVAL 1

/* Define to 1 if `nd_opt_ai_type' is a member of `struct
   nd_opt_adv_interval'. */
/* #undef HAVE_STRUCT_ND_OPT_ADV_INTERVAL_ND_OPT_AI_TYPE */

/* Define to 1 if the system has the type `struct nd_opt_homeagent_info'. */
/* #undef HAVE_STRUCT_ND_OPT_HOMEAGENT_INFO */

/* Define to 1 if the system has the type `struct rt_addrinfo'. */
/* #undef HAVE_STRUCT_RT_ADDRINFO */

/* Define to 1 if the system has the type `struct sioc_sg_req'. */
#define HAVE_STRUCT_SIOC_SG_REQ 1

/* Define to 1 if the system has the type `struct sioc_vif_req'. */
#define HAVE_STRUCT_SIOC_VIF_REQ 1

/* Define to 1 if the system has the type `struct sockaddr_dl'. */
/* #undef HAVE_STRUCT_SOCKADDR_DL */

/* Define to 1 if `sdl_len' is a member of `struct sockaddr_dl'. */
/* #undef HAVE_STRUCT_SOCKADDR_DL_SDL_LEN */

/* Define to 1 if `sin_len' is a member of `struct sockaddr_in'. */
/* #undef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */

/* Define to 1 if `sa_len' is a member of `struct sockaddr'. */
/* #undef HAVE_STRUCT_SOCKADDR_SA_LEN */

/* Define to 1 if `sun_len' is a member of `struct sockaddr_un'. */
/* #undef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

/* Define to 1 if `domainname' is a member of `struct utsname'. */
#define HAVE_STRUCT_UTSNAME_DOMAINNAME 1

/* Define to 1 if the system has the type `struct vifctl'. */
#define HAVE_STRUCT_VIFCTL 1

/* Compile systemd support in */
/* #undef HAVE_SYSTEMD */

/* Define to 1 if you have the <sys/capability.h> header file. */
/* #undef HAVE_SYS_CAPABILITY_H */

/* Define to 1 if you have the <sys/cdefs.h> header file. */
#define HAVE_SYS_CDEFS_H 1

/* Define to 1 if you have the <sys/conf.h> header file. */
/* #undef HAVE_SYS_CONF_H */

/* Define to 1 if you have the <sys/ksym.h> header file. */
/* #undef HAVE_SYS_KSYM_H */

/* Define to 1 if you have the <sys/sockio.h> header file. */
/* #undef HAVE_SYS_SOCKIO_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/sysctl.h> header file. */
#define HAVE_SYS_SYSCTL_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <ucontext.h> header file. */
#define HAVE_UCONTEXT_H 1

/* Define to 1 if `uc_mcontext.gregs' is a member of `ucontext_t'. */
#define HAVE_UCONTEXT_T_UC_MCONTEXT_GREGS 1

/* Define to 1 if `uc_mcontext.regs' is a member of `ucontext_t'. */
/* #undef HAVE_UCONTEXT_T_UC_MCONTEXT_REGS */

/* Define to 1 if `uc_mcontext.regs.nip' is a member of `ucontext_t'. */
/* #undef HAVE_UCONTEXT_T_UC_MCONTEXT_REGS_NIP */

/* Define to 1 if `uc_mcontext.uc_regs' is a member of `ucontext_t'. */
/* #undef HAVE_UCONTEXT_T_UC_MCONTEXT_UC_REGS */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Compile in v6 Route Replacement Semantics */
#define HAVE_V6_RR_SEMANTICS /**/

/* Define to 1 if you have the `vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the <vfork.h> header file. */
/* #undef HAVE_VFORK_H */

/* Define to 1 if the system has the type `vifi_t'. */
#define HAVE_VIFI_T 1

/* Define to 1 if `fork' works. */
#define HAVE_WORKING_FORK 1

/* Define to 1 if `vfork' works. */
#define HAVE_WORKING_VFORK 1

/* Enable ZeroMQ support */
/* #undef HAVE_ZEROMQ */

/* found __atomic builtins */
/* #undef HAVE___ATOMIC */

/* found __sync builtins */
/* #undef HAVE___SYNC */

/* found __sync_swap builtin */
/* #undef HAVE___SYNC_SWAP */

/* Linux ipv6 Min Hop Count */
#define IPV6_MINHOPCOUNT 73

/* selected method for isis, == one of the constants */
#define ISIS_METHOD ISIS_METHOD_PFPACKET

/* constant value for isis method bpf */
#define ISIS_METHOD_BPF 3

/* constant value for isis method dlpi */
#define ISIS_METHOD_DLPI 2

/* constant value for isis method pfpacket */
#define ISIS_METHOD_PFPACKET 1

/* KAME IPv6 */
/* #undef KAME */

/* Define for compiling with old vpn commands */
/* #undef KEEP_OLD_VPN_COMMANDS */

/* ldpd control socket */
#define LDPD_SOCKET "/var/run/ldpd.sock"

/* Linux IPv6 stack */
#define LINUX_IPV6 1

/* Mask for log files */
#define LOGFILE_MASK 0600

/* Define to 1 if `lstat' dereferences a symlink specified with a trailing
   slash. */
#define LSTAT_FOLLOWS_SLASHED_SYMLINK 1

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* path to modules */
#define MODULE_PATH "/usr/local/lib/frr/modules"

/* Maximum number of paths for a route */
#define MULTIPATH_NUM 1

/* OpenBSD */
/* #undef OPEN_BSD */

/* Name of package */
#define PACKAGE "frr"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "https://github.com/frrouting/frr/issues"

/* Define to the full name of this package. */
#define PACKAGE_NAME "frr"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "frr 6.0.3"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "frr"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "6.0.3"

/* Have openpam_ttyconv */
/* #undef PAM_CONV_FUNC */

/* Define to necessary symbol if this constant uses a non-standard name on
   your system. */
/* #undef PTHREAD_CREATE_JOINABLE */

/* Use SNMP AgentX to interface with snmpd */
/* #undef SNMP_AGENTX */

/* Solaris IPv6 */
/* #undef SOLARIS_IPV6 */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* SunOS 5 */
/* #undef SUNOS_5 */

/* OSPFAPI */
#define SUPPORT_OSPF_API /**/

/* Realms support */
/* #undef SUPPORT_REALMS */

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1

/* Define to 1 if your <sys/time.h> declares `struct tm'. */
/* #undef TM_IN_SYS_TIME */

/* Use PAM for authentication */
/* #undef USE_PAM */

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif


/* Version number of package */
#define VERSION "6.0.3"

/* VTY shell */
/* #undef VTYSH */

/* path to vtysh binary */
#define VTYSH_BIN_PATH "/usr/local/bin/vtysh"

/* What pager to use */
#define VTYSH_PAGER "more"

/* VTY Sockets Group */
/* #undef VTY_GROUP */

/* path to watchfrr.sh */
#define WATCHFRR_SH_PATH "/usr/local/sbin/watchfrr.sh"

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# ifndef WORDS_BIGENDIAN
/* #  undef WORDS_BIGENDIAN */
# endif
#endif

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
/* #undef YYTEXT_POINTER */

/* zebra api socket */
#define ZEBRA_SERV_PATH "/var/run/zserv.api"

/* Enable large inode numbers on Mac OS X 10.5.  */
#ifndef _DARWIN_USE_64_BIT_INODE
# define _DARWIN_USE_64_BIT_INODE 1
#endif

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define to 1 if on MINIX. */
/* #undef _MINIX */

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
/* #undef _POSIX_1_SOURCE */

/* Define to 1 if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */

/* Define to empty if `const' does not conform to ANSI C. */
/* #undef const */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
/* #undef inline */
#endif

/* Define to `int' if <sys/types.h> does not define. */
/* #undef mode_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* Old readline */
/* #undef rl_completion_matches */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef uid_t */

/* Define as `fork' if `vfork' does not work. */
/* #undef vfork */

/* Define to empty if the keyword `volatile' does not work. Warning: valid
   code using `volatile' can become incorrect without. Disable with care. */
/* #undef volatile */
