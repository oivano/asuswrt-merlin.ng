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

assert(start.includes("blocklist_prepare_directory(blocklist_dir)"), "startup should require a private blocklist directory");
assert(start.includes("blocklist_prepare_file(blocklist_file, 1)"), "startup should create an empty initial list safely");
assert(start.includes("if (missing_blocklist)"), "only a successfully prepared missing list should trigger a rebuild");
assert(start.indexOf("if (have_blocklist &&") < start.indexOf("conf-file=%s\\nconf-file=%s\\nconf-file=%s"), "list includes must require all files to be trusted");
assert(trust.includes("O_NOFOLLOW") && trust.includes("st_uid != 0"), "blocklist paths must reject symlinks and non-root ownership");
assert(trust.includes("st_mode & S_ISVTX"), "blocklist storage parent must prevent child-directory replacement");
assert(trust.includes("fchmod(fd, 0700)") && trust.includes("fchmod(fd, 0600)"), "blocklist storage must have restrictive permissions");
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