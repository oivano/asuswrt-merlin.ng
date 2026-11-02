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
	source.indexOf("#endif", source.indexOf("static int blocklist_build_runtime_config("))
);

assert(start.includes("blocklist_prepare_directory(blocklist_dir)"), "startup should require a private blocklist directory");
assert(start.includes("blocklist_prepare_file(blocklist_file, 1)"), "startup should create an empty initial list safely");
assert(start.includes("if (missing_blocklist)"), "only a successfully prepared missing list should trigger a rebuild");
assert(start.includes("blocklist_build_runtime_config(blocklist_dir, blocklist_file"), "startup should sanitize USB data before use");
assert(start.includes('fprintf(fp, "conf-file=%s\\n", blocklist_config)'), "dnsmasq should include only the root-owned generated config");
assert(!start.includes("conf-file=%s\\nconf-file=%s\\nconf-file=%s"), "USB files must not be loaded as general dnsmasq config");
assert(trust.includes("O_NOFOLLOW") && trust.includes("st_uid != 0"), "blocklist paths must reject symlinks and non-root ownership");
assert(trust.includes("open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)") && trust.includes("return fd"), "worker should pin the validated storage directory");
assert(trust.includes("mkdir(dir, 0700)") && trust.includes("st_uid == 0") && trust.includes("(st.st_mode & 07777) == 0700"), "blocklist directory must be root-owned and exactly 0700");
assert(sanitizer.includes("fchmod(fd, 0600)"), "blocklist files must have restrictive permissions");
assert(tempCreation.includes("openat(dirfd, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW") &&
	tempCreation.includes("st_uid == 0") && tempCreation.includes("st_nlink == 1"), "temporary files must be exclusive, no-follow, and validated by descriptor");
assert(download.includes("dup2(output_fd, STDOUT_FILENO)") && download.includes("execv(argv[0], argv)"), "curl should stream into the held download descriptor");
assert(sanitizer.includes('"local=/"') && sanitizer.includes('"address=/"'), "only supported data records should be accepted");
assert(sanitizer.includes("blocklist_safe_config_path") && sanitizer.includes("*p < 0x20") && sanitizer.includes("*p == '#'"), "USB-derived paths must not inject runtime config lines");
assert(sanitizer.includes("*p == '\\\\'"), "USB-derived backslashes must not escape runtime config syntax");
assert(sanitizer.includes("O_CREAT | O_EXCL | O_NOFOLLOW") && sanitizer.includes("blocklist_create_data_file"), "generated files must be created without following removable-media links");
assert(sanitizer.includes("inet_pton(AF_INET") && sanitizer.includes("inet_pton(AF_INET6"), "address records must contain literal IP addresses");
assert(sanitizer.includes('"addn-hosts=%s\\n"') && sanitizer.includes('"%s %s\\n"'), "large address lists should use hosts-format data, not config parsing");
assert(sanitizer.includes('"/tmp/dnsmasq-blocklist/runtime.conf"') || source.includes('#define DNSMASQ_BLOCKLIST_RUNTIME_CONF\tDNSMASQ_BLOCKLIST_RUNTIME_DIR "/runtime.conf"'), "generated config must live on internal storage");

const net = require("net");
function parseDataLine(line) {
	line = line.trim();
	let match = /^local=\/([A-Za-z0-9.-]+)\/$/.exec(line);
	if (match) return validDomain(match[1]) ? { type: "local", domain: match[1] } : null;
	match = /^address=\/([^/]+)\/([^/]+)$/.exec(line);
	if (!match || !validDomain(match[1]) || !net.isIP(match[2])) return null;
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
assert.deepStrictEqual(parseDataLine("address=/ads.example/0.0.0.0"), {
	type: "address", domain: "ads.example", address: "0.0.0.0"
});
assert.deepStrictEqual(parseDataLine("local=ads.example/"), null, "local directive prefix must be exact");
assert.deepStrictEqual(parseDataLine("local=/ads.example/"), { type: "local", domain: "ads.example" });
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

assert(lock.includes("fcntl(fd, F_SETLK, &lock)"), "worker lock should be nonblocking");
assert(dispatch.includes("pid = fork()"), "PID 1 should fork the updater");
assert(dispatch.includes("update_dnsmasq_blocklist_worker()"), "child should run the updater");
assert(!dispatch.includes("waitpid("), "PID 1 must not wait for the worker");
assert(dispatch.includes("notify_rc(\"restart_dnsmasq\")"), "successful publication should restart dnsmasq");
assert(dispatch.includes("if (updated)"), "failed fetches must not restart dnsmasq");

console.log("dnsmasq blocklist async contracts: PASS");