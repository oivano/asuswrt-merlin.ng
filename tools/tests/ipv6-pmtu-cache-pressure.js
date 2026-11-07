const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const kernel = path.resolve(__dirname, '../../release/src-rt-6.x.4708/linux/linux-2.6.36');
const routeSource = fs.readFileSync(path.join(kernel, 'net/ipv6/route.c'), 'utf8');
const fibSource = fs.readFileSync(path.join(kernel, 'net/ipv6/ip6_fib.c'), 'utf8');
const headerSource = fs.readFileSync(path.join(kernel, 'include/net/ip6_fib.h'), 'utf8');
const dstSource = fs.readFileSync(path.join(kernel, 'net/core/dst.c'), 'utf8');

const gcStart = routeSource.indexOf('static int ip6_dst_gc(struct dst_ops *ops)');
const gcEnd = routeSource.indexOf('/* Clean host part of a prefix.', gcStart);
assert(gcStart >= 0 && gcEnd > gcStart, 'IPv6 dst-cache GC function is present');
const gc = routeSource.slice(gcStart, gcEnd);
assert.match(gc, /fib6_run_gc\(net->ipv6\.ip6_rt_gc_expire, net, 1\)/,
    'allocation-triggered GC marks cache pressure');
assert.match(gc, /if \(time_after\(rt_last_gc \+ rt_min_interval, now\)\)/,
    'allocation-triggered GC is rate-limited by the minimum interval at every cache size');
assert.doesNotMatch(gc, /rt_max_size/,
    'cache size does not bypass allocation-triggered GC rate limiting');
assert.match(gc, /return 0;/,
    'cache pressure does not make dst_alloc reject every new IPv6 destination');
assert.doesNotMatch(gc, /return\s*\(atomic_read\(&ops->entries\)\s*>\s*rt_max_size\)/,
    'ip6_rt_max_size is not a hard allocation-failure threshold');
assert.match(dstSource,
    /if \(ops->gc && atomic_read\(&ops->entries\) > ops->gc_thresh\) \{[\s\S]*?if \(ops->gc\(ops\)\)[\s\S]*?return NULL;/,
    'destination allocation still invokes GC above gc_thresh and handles real GC failures');
assert.match(routeSource, /static unsigned int ip6_pmtu_cache_pending/,
    'PMTU clone admissions reserve capacity while destination allocation is in flight');
assert.match(routeSource,
    /atomic_read\(&net->ipv6\.ip6_dst_ops\.entries\)[\s\S]*?ip6_pmtu_cache_pending < max_size/,
    'PMTU clone admission accounts for existing destinations and concurrent reservations');
assert.match(routeSource,
    /static void ip6_pmtu_cache_release\(void\)[\s\S]*?ip6_pmtu_cache_pending--/,
    'PMTU reservation is released after allocation');
const pmtuStart = routeSource.indexOf('static void rt6_do_pmtu_disc(');
const pmtuEnd = routeSource.indexOf('\nvoid rt6_pmtu_discovery(', pmtuStart);
assert(pmtuStart >= 0 && pmtuEnd > pmtuStart, 'PMTU route update function is present');
const pmtu = routeSource.slice(pmtuStart, pmtuEnd);
assert.match(pmtu,
    /if \(!ip6_pmtu_cache_reserve\(net\)\)\s+goto out/,
    'new PMTU clones are refused above the configured clone limit');
assert.match(pmtu,
    /rt6_alloc_clone\(rt, daddr\)[\s\S]*?ip6_pmtu_cache_release\(\)/,
    'all PMTU clone allocation paths release their reservation');

const ageStart = fibSource.indexOf('static int fib6_age(struct rt6_info *rt, void *arg)');
const ageEnd = fibSource.indexOf('static DEFINE_SPINLOCK(fib6_gc_lock)', ageStart);
assert(ageStart >= 0 && ageEnd > ageStart, 'IPv6 FIB aging function is present');
const age = fibSource.slice(ageStart, ageEnd);
assert.match(age,
    /gc_args\.pressure && \(rt->rt6i_flags & RTF_CACHE\)[\s\S]*?atomic_read\(&rt->dst\.__refcnt\) == 0[\s\S]*?time_after_eq\(now, rt->dst\.lastuse \+ gc_args\.timeout\)/,
    'pressure GC can evict idle, unreferenced PMTU cache clones before nominal expiry');
assert.match(fibSource, /void fib6_run_gc\(unsigned long expires, struct net \*net, int pressure\)/,
    'FIB GC receives explicit pressure context');
assert.match(headerSource, /fib6_run_gc\(unsigned long expires,[\s\S]*?struct net \*net, int pressure\)/,
    'FIB GC pressure context is declared for all callers');
assert.match(fibSource, /fib6_run_gc\(0, \(struct net \*\)arg, 0\)/,
    'periodic GC does not apply pressure-only PMTU eviction');

const raStart = routeSource.indexOf('int ip6_route_add_ra(struct fib6_config *cfg)');
const raEnd = routeSource.indexOf('static struct rt6_info * ip6_rt_copy', raStart);
assert(raStart >= 0 && raEnd > raStart, 'IPv6 RA route admission function is present');
const raAdmission = routeSource.slice(raStart, raEnd);
assert.match(raAdmission, /route_count >= IPV6_RA_ROUTE_LIMIT/,
    'per-interface RA route count limit remains');
assert.doesNotMatch(raAdmission, /ip6_dst_ops\.entries|IPV6_RA_DST_RESERVE/,
    'untrusted PMTU cache occupancy cannot block RA route admission before GC');

console.log('PASS: IPv6 PMTU cache pressure is reclaimable without hard dst-allocation failure');