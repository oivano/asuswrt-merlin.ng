const assert = require("assert");
const fs = require("fs");

const source = fs.readFileSync("release/src/router/rc/services.c", "utf8");
const start = source.slice(
	source.indexOf("void start_dnsmasq(void)"),
	source.indexOf("void stop_dnsmasq(void)")
);
const worker = source.slice(
	source.indexOf("static int update_dnsmasq_blocklist_worker(void)"),
	source.indexOf("static int dnsmasq_blocklist_worker_lock(void)")
);
const lock = source.slice(
	source.indexOf("static int dnsmasq_blocklist_worker_lock(void)"),
	source.indexOf("void update_dnsmasq_blocklist(void)")
);
const dispatch = source.slice(
	source.indexOf("void update_dnsmasq_blocklist(void)"),
	source.indexOf("void dnsmasq_blocklist_count(void)")
);
const trust = source.slice(
	source.indexOf("static int blocklist_open_directory(const char *dir)"),
	source.indexOf("static int blocklist_external_path(const char *path)")
);
const tempCreation = source.slice(
	source.indexOf("static int blocklist_create_temp_file("),
	source.indexOf("static int blocklist_download(")
);
const download = source.slice(
	source.indexOf("static int blocklist_download("),
	source.indexOf("static int blocklist_write_data(")
);
const sanitizer = source.slice(
	source.indexOf("static int blocklist_valid_domain(const char *domain)"),
	source.indexOf("#endif", source.indexOf("static int prepare_dnsmasq_blocklist("))
);
const prepare = source.slice(
	source.indexOf("static int prepare_dnsmasq_blocklist("),
	source.indexOf("#endif", source.indexOf("static int prepare_dnsmasq_blocklist("))
);

assert(prepare.includes("blocklist_open_directory(dir)"), "startup should require a private blocklist directory");
assert(prepare.includes('blocklist_prepare_file_at(dirfd, "blockinglist.conf", 1)'), "startup should create an empty initial list safely");
assert(prepare.includes("*update = missing;"), "only a successfully prepared missing list should trigger a rebuild");
assert(prepare.includes("blocklist_build_runtime_config(dirfd)"), "startup should sanitize USB data before use");
assert(prepare.includes("blocklist_safe_config_path(config)"), "USB-derived runtime path must not inject config lines");
assert(start.includes('fprintf(fp, "conf-file=%s\\n", blocklist_config)'), "dnsmasq should include only the root-owned generated config");
assert(!start.includes("conf-file=%s\\nconf-file=%s\\nconf-file=%s"), "USB files must not be loaded as general dnsmasq config");
assert(start.indexOf("prepare_dnsmasq_blocklist(") >= 0 &&
	start.indexOf("prepare_dnsmasq_blocklist(") < start.indexOf("stop_dnsmasq();"),
	"list validation must finish before the running dnsmasq is stopped");
assert(trust.includes("O_NOFOLLOW") && trust.includes("st_uid != 0"), "blocklist paths must reject symlinks and non-root ownership");
assert(trust.includes("open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)") && trust.includes("return fd"), "worker should pin the validated storage directory");
assert(trust.includes("mkdir(dir, 0700)") && trust.includes("st_uid == 0") && trust.includes("(st.st_mode & 07777) == 0700"), "blocklist directory must be root-owned and exactly 0700");
assert(trust.includes("(st.st_mode & 07777) != 0600 && (fchmod(fd, 0600) < 0"), "blocklist files must have restrictive permissions without no-op ctime bumps");
assert(tempCreation.includes("openat(dirfd, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW") &&
	tempCreation.includes("st_uid == 0") && tempCreation.includes("st_nlink == 1"), "temporary files must be exclusive, no-follow, and validated by descriptor");
assert(download.includes("dup2(output_fd, STDOUT_FILENO)") && download.includes("execv(argv[0], argv)"), "curl should stream into the held download descriptor");
assert(sanitizer.includes('"local=/"') && sanitizer.includes('"address=/"'), "only supported data records should be accepted");
assert(sanitizer.includes("blocklist_safe_config_path") && sanitizer.includes("*p < 0x20") && sanitizer.includes("*p == '#'"), "USB-derived paths must not inject runtime config lines");
assert(sanitizer.includes("*p == '\\\\'"), "USB-derived backslashes must not escape runtime config syntax");
assert(tempCreation.includes("O_CREAT | O_EXCL | O_NOFOLLOW") &&
	sanitizer.includes('blocklist_create_temp_file(dirfd, DNSMASQ_BLOCKLIST_RUNTIME_NAME ".new"'),
	"generated runtime config must use an exclusive, uniquely named temporary file");
assert(sanitizer.includes("inet_pton(AF_INET") && sanitizer.includes("inet_pton(AF_INET6"), "address records must contain literal IP addresses");
assert(sanitizer.includes("strcmp(*address, block_ip)"), "USB address records must use only the configured blocking target");
assert(sanitizer.includes('nvram_safe_get("dnsmasq_blocklist_ip")') && sanitizer.includes('block_ip = "0.0.0.0"'),
	"runtime sanitization must use the configured target and match the downloader default");
assert(sanitizer.includes("strcmp(*address, valid_address)"), "a repeated sink address should be validated once");
// dnsmasq reads addn-hosts after setuid(nobody); a root-only USB hosts file never loads and is re-read on every SIGHUP.
assert(!source.includes("addn-hosts=%s") && !sanitizer.includes('"%s %s\\n"'), "blocklist must not be emitted as an addn-hosts file");
assert(sanitizer.includes('"address=/"') && sanitizer.includes("fputs(address, config)"), "address records must stay dnsmasq address= entries (subdomain blocking)");
assert(!sanitizer.includes("fprintf(config"), "per-line runtime output should avoid format parsing");
assert(!source.includes('"/tmp/dnsmasq-blocklist'), "generated list must not be copied into RAM-backed /tmp");
assert(sanitizer.includes("renameat(dirfd, new_name, dirfd, DNSMASQ_BLOCKLIST_RUNTIME_NAME)"), "runtime config must be published inside the pinned private directory");
assert(sanitizer.includes("setvbuf(config, NULL, _IOFBF, DNSMASQ_BLOCKLIST_IO_BUF)") &&
	sanitizer.includes("setvbuf(fp, NULL, _IOFBF, DNSMASQ_BLOCKLIST_IO_BUF)"), "large-list streams should use large stdio buffers");
assert(prepare.includes("blocklist_runtime_current(dirfd) || blocklist_build_runtime_config(dirfd)"),
	"unchanged inputs must reuse the already validated runtime config");
assert(source.includes('#define DNSMASQ_BLOCKLIST_STAMP\t"/tmp/'), "the reuse stamp must be RAM-only so each boot revalidates");
assert(sanitizer.includes("st.st_uid == 0") && sanitizer.includes("O_RDONLY | O_NOFOLLOW | O_NONBLOCK") &&
	sanitizer.includes("memcmp(now, saved, sizeof(now))"), "stamp must be root-owned and match every file identity");
assert(sanitizer.indexOf("have_inputs = blocklist_stamp_get(") < sanitizer.indexOf('blocklist_open_data_file_at(dirfd, "blockinglist.conf")') &&
	sanitizer.includes("memcmp(now, inputs"), "stamp must describe the inputs that were actually read");

const net = require("net");
function parseDataLine(line, blockIp = "0.0.0.0") {
	line = line.trim();
	let match = /^server=\/([^/]+)\/#$/.exec(line);
	if (match) return validDomain(match[1]) ? { type: "server", domain: match[1] } : null;
	match = /^local=\/([A-Za-z0-9.-]+)\/$/.exec(line);
	if (match) return validDomain(match[1]) ? { type: "local", domain: match[1] } : null;
	match = /^address=\/([^/]+)\/([^/]+)$/.exec(line);
	if (!match || !validDomain(match[1]) || match[2] !== blockIp || !net.isIP(match[2])) return null;
	return { type: "address", domain: match[1], address: match[2] };
}
function validDomain(domain) {
	if (!domain || domain.length > 253) return false;
	return domain.split(".").every(label => label.length > 0 && label.length <= 63 &&
		/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label));
}
for (const line of [
	"conf-script=/tmp/payload",
	"dhcp-script=/tmp/payload",
	"user=root",
	"address=/bad.example/$(touch /tmp/pwned)",
	"address=/bad..example/0.0.0.0",
	"local=/bad.example/;conf-script=/tmp/payload"
]) {
	assert.strictEqual(parseDataLine(line), null, `unsafe input must be ignored: ${line}`);
}
assert.deepStrictEqual(parseDataLine("address=/.ads.example/0.0.0.0"), null, "domain syntax must be strict");
assert.deepStrictEqual(parseDataLine("address=ads.example/0.0.0.0"), null, "address directive delimiters must be exact");
assert.strictEqual(parseDataLine("address=/example.test/203.0.113.5"), null,
	"USB lists must not select an address target the administrator did not configure");
assert.deepStrictEqual(parseDataLine("address=/ads.example/0.0.0.0"), {
	type: "address", domain: "ads.example", address: "0.0.0.0"
});
assert.deepStrictEqual(parseDataLine("address=/ads.example/203.0.113.5", "203.0.113.5"), {
	type: "address", domain: "ads.example", address: "203.0.113.5"
}, "the administrator-configured sink address should remain supported");
assert.deepStrictEqual(parseDataLine("local=ads.example/"), null, "local directive prefix must be exact");
assert.deepStrictEqual(parseDataLine("local=/ads.example/"), { type: "local", domain: "ads.example" });
assert.deepStrictEqual(parseDataLine("server=/ok.example/#"), { type: "server", domain: "ok.example" }, "allowlist server=/d/# must survive sanitization");
assert.strictEqual(parseDataLine("server=/ok.example/1.1.1.1"), null, "only the standard-server allowlist form is accepted");
assert(sanitizer.includes('strcmp(separator, "/#")') && sanitizer.includes('"server=/"') && sanitizer.includes('"/#\\n"'), "C sanitizer must accept and re-emit server=/d/#");
assert(
	start.indexOf("eval(\"dnsmasq\", \"--log-async\")") < start.indexOf("if (update_blocklist)"),
	"startup should launch the worker only after dnsmasq starts"
);
assert(!start.includes("update_dnsmasq_blocklist();") || start.indexOf("update_dnsmasq_blocklist();") > start.indexOf("if (update_blocklist)"),
	"startup must not wait for a fetch before launching dnsmasq");

for (const [option, value] of [
	["--max-time", "300"],
	["--speed-limit", "1"],
	["--speed-time", "30"]
]) {
	assert(worker.includes(`"${option}"`) && worker.includes(`"${value}"`), `missing curl bound ${option} ${value}`);
}
assert(worker.includes('renameat(dirfd, new_name, dirfd, "blockinglist.conf") != 0'), "publication must check descriptor-relative atomic rename failure");
assert(worker.includes("blocklist_open_directory(blocklist_dir)"), "worker should reject an untrusted storage directory");
assert(worker.includes('blocklist_create_temp_file(dirfd, "blockinglist.download"'), "download should use an exclusive private temporary file");
assert(worker.includes('blocklist_create_temp_file(dirfd, "blockinglist.conf.new"'), "generated output should use an exclusive private temporary file");
assert(worker.includes("blocklist_download(argv, download_fd)"), "curl should write into the already-open download descriptor");
assert(worker.includes("lseek(download_fd, 0, SEEK_SET)") && worker.includes('fdopen(download_fd, "r")'), "download should be parsed through its original descriptor");
assert(worker.includes("renameat(dirfd, new_name, dirfd, \"blockinglist.conf\")"), "publication should stay relative to the pinned directory");
assert(!worker.includes("fopen(temp_file") && !worker.includes("fopen(new_file") && !worker.includes("unlink(temp_file)"), "worker must not reopen or unlink attacker-selected fixed paths");
assert(worker.includes("if (ferror(in))") && worker.includes("if (ferror(out))"), "stream errors must block publication");
assert(worker.includes("updated = 1;") && worker.includes("return updated;"), "worker should report successful publication");
assert(worker.indexOf("blocklist_build_runtime_config(dirfd)") > worker.indexOf("updated = 1;"),
	"worker should prevalidate the published list so the restart can reuse it");

const allowset = source.slice(
	source.indexOf("struct blocklist_allowset {"),
	source.indexOf("static int update_dnsmasq_blocklist_worker(void)")
);
assert(!allowset.includes("rewind(") && allowset.includes("bsearch(") && allowset.includes("qsort("),
	"allowlist must be loaded once and probed by binary search, not rescanned per entry");
assert(worker.includes("blocklist_allowset_load(allow, &allowset)") && !worker.includes("rewind("),
	"worker must load the allowlist before the per-entry loop");
assert(!/fprintf\(out/.test(worker), "per-entry worker output should avoid format parsing");

// Old semantics: line matches if "/<domain>/" follows the first '/'. Model the C set against it.
function oldAllowed(domain, lines) {
	return lines.some(line => {
		const i = line.indexOf("/");
		if (i < 0) return false;
		const p = line.slice(i + 1);
		return p.startsWith(domain) && p[domain.length] === "/";
	});
}
function loadSet(lines) {
	const names = [];
	for (const line of lines) {
		const i = line.indexOf("/");
		if (i < 0) continue;
		const end = line.indexOf("/", i + 1);
		if (end < 0) continue;
		names.push(line.slice(i + 1, end));
	}
	return names.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}
function setAllowed(domain, names) {
	let lo = 0, hi = names.length;
	while (lo < hi) {
		const mid = (lo + hi) >> 1;
		if (names[mid] === domain) return true;
		if (names[mid] < domain) lo = mid + 1; else hi = mid;
	}
	return false;
}
const allowLines = ["server=/ok.example/#", "address=/keep.example/0.0.0.0", "local=/x.test/", "# comment", "junk", "address=/nested.ok.example/#"];
const names = loadSet(allowLines);
for (const domain of ["ok.example", "keep.example", "x.test", "ads.example", "ok", "nested.ok.example", "example", "ok.example.evil"]) {
	assert.strictEqual(setAllowed(domain, names), oldAllowed(domain, allowLines), `allowlist semantics changed for ${domain}`);
}

assert(lock.includes("fcntl(fd, F_SETLK, &lock)"), "worker lock should be nonblocking");
assert(dispatch.includes("pid = fork()"), "PID 1 should fork the updater");
assert(dispatch.includes("update_dnsmasq_blocklist_worker()"), "child should run the updater");
assert(!dispatch.includes("waitpid("), "PID 1 must not wait for the worker");
assert(dispatch.includes("notify_rc(\"start_dnsmasq\")") && !dispatch.includes("restart_dnsmasq"),
	"publication should use start_dnsmasq so validation runs before the old instance stops");
assert(dispatch.includes("signal(sig, SIG_DFL)") && dispatch.includes("sigprocmask(SIG_SETMASK, &set, NULL)") &&
	dispatch.indexOf("signal(sig, SIG_DFL)") < dispatch.indexOf("update_dnsmasq_blocklist_worker()"),
	"worker must drop PID 1's SIGCHLD reaper and blocked signal mask before running curl");
assert(dispatch.includes("if (updated)"), "failed fetches must not restart dnsmasq");

console.log("dnsmasq blocklist async contracts: PASS");