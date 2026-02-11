/**
 * FRR Configuration JavaScript Functions
 * AsusWRT-Merlin FRR WebUI Support
 */

// Additional validation helper for FRR-specific fields
function validate_frr_as_number(obj) {
	var as_num = parseInt(obj.value);
	if (isNaN(as_num) || as_num < 1 || as_num > 4294967295) {
		alert("AS number must be between 1 and 4294967295");
		obj.focus();
		return false;
	}
	return true;
}

// Validate OSPF area ID (can be dotted decimal or number)
function validate_ospf_area(obj) {
	var area = obj.value;
	if (area == "") {
		return true; // Empty is OK, will use default
	}
	
	// Check if it's a dotted decimal (like 0.0.0.0)
	if (area.indexOf('.') != -1) {
		return validator.ipAddrFinal(obj, '');
	}
	
	// Otherwise should be a number
	var area_num = parseInt(area);
	if (isNaN(area_num) || area_num < 0 || area_num > 4294967295) {
		alert("OSPF area must be a valid IP address or number (0-4294967295)");
		obj.focus();
		return false;
	}
	
	return true;
}

// Parse OSPF networks textarea (one network per line)
function parse_ospf_networks(text) {
	var lines = text.split('\n');
	var networks = [];
	
	for (var i = 0; i < lines.length; i++) {
		var line = lines[i].trim();
		if (line == "") continue;
		
		// Expected format: 192.168.1.0/24 or 192.168.1.0 255.255.255.0
		var parts = line.split(/[\s\/]+/);
		if (parts.length >= 1) {
			networks.push(line);
		}
	}
	
	return networks;
}

// Format OSPF networks for NVRAM storage (> separated)
function format_ospf_networks_for_nvram(textarea) {
	var networks = parse_ospf_networks(textarea.value);
	return networks.join('>');
}

// Show/hide sections with animation
function showhide(element_id, show) {
	var obj = document.getElementById(element_id);
	if (obj) {
		if (show) {
			obj.style.display = "";
		} else {
			obj.style.display = "none";
		}
	}
}

// Helper to check if FRR daemons are running via AJAX
function check_frr_running(callback) {
	$.ajax({
		url: '/ajax_frr_status.asp',
		dataType: 'json',
		timeout: 2000,
		success: function(data) {
			if (callback) callback(data);
		},
		error: function() {
			if (callback) callback(null);
		}
	});
}

// Format uptime string
function format_uptime(seconds) {
	if (!seconds || seconds <= 0) return "N/A";
	
	var days = Math.floor(seconds / 86400);
	var hours = Math.floor((seconds % 86400) / 3600);
	var mins = Math.floor((seconds % 3600) / 60);
	
	var result = "";
	if (days > 0) result += days + "d ";
	if (hours > 0) result += hours + "h ";
	if (mins > 0) result += mins + "m";
	
	return result || "< 1m";
}

// Validate IP address with CIDR notation
function validate_network_cidr(obj) {
	var value = obj.value.trim();
	if (value == "") return false;
	
	var parts = value.split('/');
	if (parts.length != 2) {
		alert("Network must be in CIDR format (e.g., 192.168.1.0/24)");
		obj.focus();
		return false;
	}
	
	// Validate IP part
	var ip_parts = parts[0].split('.');
	if (ip_parts.length != 4) {
		alert("Invalid IP address format");
		obj.focus();
		return false;
	}
	
	for (var i = 0; i < 4; i++) {
		var num = parseInt(ip_parts[i]);
		if (isNaN(num) || num < 0 || num > 255) {
			alert("Invalid IP address");
			obj.focus();
			return false;
		}
	}
	
	// Validate prefix length
	var prefix = parseInt(parts[1]);
	if (isNaN(prefix) || prefix < 0 || prefix > 32) {
		alert("Prefix length must be between 0 and 32");
		obj.focus();
		return false;
	}
	
	return true;
}

// Export functions for external use
if (typeof module !== 'undefined' && module.exports) {
	module.exports = {
		validate_frr_as_number: validate_frr_as_number,
		validate_ospf_area: validate_ospf_area,
		parse_ospf_networks: parse_ospf_networks,
		format_ospf_networks_for_nvram: format_ospf_networks_for_nvram,
		validate_network_cidr: validate_network_cidr,
		format_uptime: format_uptime
	};
}
