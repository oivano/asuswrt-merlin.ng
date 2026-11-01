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

assert(start.includes("fopen(blocklist_file, \"w\")"), "startup should create an empty initial list");
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
assert(worker.includes("if (ferror(in))") && worker.includes("if (ferror(out))"), "stream errors must block publication");
assert(worker.includes("return 1;"), "worker should report successful publication");

assert(lock.includes("fcntl(fd, F_SETLK, &lock)"), "worker lock should be nonblocking");
assert(dispatch.includes("pid = fork()"), "PID 1 should fork the updater");
assert(dispatch.includes("update_dnsmasq_blocklist_worker()"), "child should run the updater");
assert(!dispatch.includes("waitpid("), "PID 1 must not wait for the worker");
assert(dispatch.includes("notify_rc(\"restart_dnsmasq\")"), "successful publication should restart dnsmasq");
assert(dispatch.includes("if (updated)"), "failed fetches must not restart dnsmasq");

console.log("dnsmasq blocklist async contracts: PASS");