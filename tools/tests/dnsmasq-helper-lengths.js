const assert = require("assert");
const fs = require("fs");

const source = fs.readFileSync("release/src/router/dnsmasq/src/helper.c", "utf8");
const validation = source.indexOf("if (data.clid_len < 0 || data.clid_len > MAXDNAMESTR ||");
assert(validation >= 0, "helper must reject negative and oversized client ID lengths");

const validationPath = source.slice(validation, source.indexOf("/* CLID into packet", validation));
assert(validationPath.includes("data.hostname_len < 0 || data.hostname_len > MAXDNAMESTR"),
	"helper must bound hostname length independently");
assert(validationPath.includes("data.ed_len < 0 || data.ed_len > MAXDNAMESTR"),
	"helper must bound extra-data length independently");
assert(validationPath.indexOf("data_len = (size_t)") > validationPath.indexOf("continue;"),
	"payload arithmetic must follow field validation");
assert(validationPath.includes("malloc(data_len)"), "heap allocation must use the validated payload size");
assert(validationPath.includes("read_write(pipefd[0], buf, data_len, RW_READ)"),
	"pipe read must use the validated payload size");

function checkedPayloadLength(lengths) {
	if (lengths.some((length) => !Number.isInteger(length) || length < 0 || length > 503))
		return null;
	return lengths.reduce((total, length) => total + length, 0);
}

assert.strictEqual(checkedPayloadLength([0, 101, -100]), null,
	"signed cancellation with a positive aggregate must be rejected");
assert.strictEqual(checkedPayloadLength([0, 2147483647, -2147483646]), null,
	"extreme signed values must be rejected before summing");
assert.strictEqual(checkedPayloadLength([0, -2147483648, 2147483647]), null,
	"minimum signed values must be rejected before summing");
assert.strictEqual(checkedPayloadLength([0, 0, 0]), 0, "empty records remain valid");
assert.strictEqual(checkedPayloadLength([503, 0, 0]), 503, "single-field maximum remains valid");
assert.strictEqual(checkedPayloadLength([503, 503, 503]), 1509,
	"valid individually bounded fields retain the exact heap-buffer size");

console.log("dnsmasq helper length contracts: PASS");