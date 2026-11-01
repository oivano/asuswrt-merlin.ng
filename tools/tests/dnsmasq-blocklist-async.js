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
	source.indexOf("static int blocklist_prepare_directory(const char *dir)"),
	source.indexOf("static int blocklist_external_path(const char *path)")
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
assert(trust.includes("st_mode & S_ISVTX"), "blocklist storage parent must prevent child-directory replacement");
assert(trust.includes("fchmod(fd, 0700)") && trust.includes("fchmod(fd, 0600)"), "blocklist storage must have restrictive permissions");
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
assert(worker.includes("rename(new_file, blocklist_file) != 0"), "publication must check atomic rename failure");
assert(worker.includes("blocklist_prepare_directory(blocklist_dir)"), "worker should reject an untrusted storage directory");
assert(worker.includes("blocklist_prepare_file(temp_file, 0)"), "downloaded files should be validated before parsing");
assert(worker.includes("if (ferror(in))") && worker.includes("if (ferror(out))"), "stream errors must block publication");
assert(worker.includes("return 1;"), "worker should report successful publication");

assert(lock.includes("fcntl(fd, F_SETLK, &lock)"), "worker lock should be nonblocking");
assert(dispatch.includes("pid = fork()"), "PID 1 should fork the updater");
assert(dispatch.includes("update_dnsmasq_blocklist_worker()"), "child should run the updater");
assert(!dispatch.includes("waitpid("), "PID 1 must not wait for the worker");
assert(dispatch.includes("notify_rc(\"restart_dnsmasq\")"), "successful publication should restart dnsmasq");
assert(dispatch.includes("if (updated)"), "failed fetches must not restart dnsmasq");

console.log("dnsmasq blocklist async contracts: PASS");