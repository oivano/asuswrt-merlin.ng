<!DOCTYPE html
	PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<html xmlns:v>

<head>
	<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
	<meta HTTP-EQUIV="Expires" CONTENT="-1">
	<link rel="shortcut icon" href="images/favicon.png">
	<link rel="icon" href="images/favicon.png">
	<title>
		<#Web_Title#> - <#menu5_2_4#>
	</title>
	<link rel="stylesheet" type="text/css" href="index_style.css">
	<link rel="stylesheet" type="text/css" href="form_style.css">
	<link rel="stylesheet" type="text/css" href="css/icon.css">
	<script type="text/javascript" src="/js/jquery.js"></script>
	<script type="text/javascript" src="/switcherplugin/jquery.iphone-switch.js"></script>
	<script language="JavaScript" type="text/javascript" src="/state.js"></script>
	<script language="JavaScript" type="text/javascript" src="/general.js"></script>
	<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
	<script type="text/javascript" language="JavaScript" src="/help.js"></script>
	<script type="text/javascript" language="JavaScript" src="/validator.js"></script>
	<script type="text/javascript" language="JavaScript" src="/js/frr_config.js"></script>
	<script>
		var frr_bgp_neighbor_status_map = <% get_frr_bgp_neighbor_status_map(); %>;
		var frr_bgp_status_time = frr_bgp_neighbor_status_map ? Date.now() : 0;
		var frr_bgp_config = <% get_frr_bgp_config(); %>;
		var frrDefaultConfigDir = '/jffs/configs/frr';
		var frrInitialConfig = '';
		var frr_bgp_edit_source = '';
		var frr_bgp_edit_enabled = '1';
		var frr_bfd_edit_options = '';
		var frr_bfd_edit_enabled = '1';

		function frr_html_escape(value) {
			return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;')
				.replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
		}

		function frr_valid_cidr(value) {
			if (!/^(\d{1,3}\.){3}\d{1,3}\/(3[0-2]|[12]?\d)$/.test(value))
				return false;
			var octets = value.split('/')[0].split('.');
			for (var i = 0; i < octets.length; i++)
				if (Number(octets[i]) > 255) return false;
			return true;
		}

		function frr_valid_interval(value) {
			return /^\d+$/.test(value) && Number(value) >= 10 && Number(value) <= 60000;
		}

		function frr_valid_area(value) {
			if (value == '') return true;
			if (/^\d+$/.test(value)) return Number(value) <= 4294967295;
			return frr_valid_cidr(value + '/32');
		}

		function frr_config_signature() {
			return JSON.stringify(frr_collect_config());
		}

		function frr_peer_state_only_changed(original, current) {
			var peerMaps = ['bgp_peers', 'bfd_peers'];
			var stateChanged = false;
			var key;
			for (key in original) {
				if (Object.prototype.hasOwnProperty.call(original, key) && key != 'bgp_peers' && key != 'bfd_peers' &&
					original[key] !== current[key]) return false;
			}
			for (key in current) {
				if (Object.prototype.hasOwnProperty.call(current, key) && key != 'bgp_peers' && key != 'bfd_peers' &&
					original[key] !== current[key]) return false;
			}
			for (var mapIndex = 0; mapIndex < peerMaps.length; mapIndex++) {
				var mapName = peerMaps[mapIndex];
				var oldPeers = original[mapName] || {};
				var newPeers = current[mapName] || {};
				for (var ip in oldPeers) {
					if (!Object.prototype.hasOwnProperty.call(oldPeers, ip)) continue;
					if (!Object.prototype.hasOwnProperty.call(newPeers, ip)) return false;
					for (key in oldPeers[ip]) {
						if (Object.prototype.hasOwnProperty.call(oldPeers[ip], key) && key != 'enabled' &&
							oldPeers[ip][key] !== newPeers[ip][key]) return false;
					}
					for (key in newPeers[ip]) {
						if (Object.prototype.hasOwnProperty.call(newPeers[ip], key) && key != 'enabled' &&
							oldPeers[ip][key] !== newPeers[ip][key]) return false;
					}
					if (oldPeers[ip].enabled !== newPeers[ip].enabled) stateChanged = true;
				}
				for (ip in newPeers) {
					if (Object.prototype.hasOwnProperty.call(newPeers, ip) &&
						!Object.prototype.hasOwnProperty.call(oldPeers, ip)) return false;
				}
			}
			return stateChanged;
		}

		function frr_collect_config() {
			var fields = ['frr_enable', 'frr_passwd', 'frr_enpasswd', 'frr_allow_lan',
				'frr_bgp_enable', 'frr_bgp_as', 'frr_bgp_networks', 'frr_ospf_enable',
				'frr_ospf_area', 'frr_ospf_networks', 'frr_bfd_enable', 'frr_config_dir'];
			var values = {bgp_peers: {}, bfd_peers: {}};
			for (var i = 0; i < fields.length; i++)
				values[fields[i]] = document.form[fields[i]].value;
			values.frr_config_dir = values.frr_config_dir || frrDefaultConfigDir;
			var table = document.getElementById('bgp_neighbor_table');
			for (var row = 0; row < table.rows.length; row++) {
				if (table.rows[row].cells.length < 7) continue;
				var ip = frr_cell_value(table.rows[row].cells[1]);
				values.bgp_peers[ip] = {
					as_number: frr_cell_value(table.rows[row].cells[2]),
					description: frr_cell_value(table.rows[row].cells[3]),
					source: table.rows[row].getAttribute('data-update-source') || '',
					enabled: table.rows[row].getAttribute('data-enabled') || '1'
				};
			}
			var bfd = document.getElementById('bfd_peer_table');
			for (var peer = 0; peer < bfd.rows.length; peer++) {
				if (bfd.rows[peer].cells.length < 7) continue;
				values.bfd_peers[frr_cell_value(bfd.rows[peer].cells[1])] = {
					tx: frr_cell_value(bfd.rows[peer].cells[2]) || '300',
					rx: frr_cell_value(bfd.rows[peer].cells[3]) || '300',
					options: bfd.rows[peer].getAttribute('data-options') || '',
					enabled: bfd.rows[peer].getAttribute('data-enabled') || '1'
				};
			}
			return values;
		}

		function frr_cell_value(cell) {
			var input = cell.querySelector('input[type="text"]');
			return input ? input.value : cell.textContent;
		}

		function frr_peer_row_from_action(obj) {
			while (obj && obj.tagName && obj.tagName.toLowerCase() != 'tr')
				obj = obj.parentNode;
			return obj;
		}

		function bgp_status_badge(status) {
			var s = (status || 'Configured').toString();
			var l = s.toLowerCase();
			var state = 'configured';

			if (l == 'established' || l == 'up')
				state = 'up';
			else if (l == 'active' || l == 'connect')
				state = 'connecting';
			else if (l == 'idle' || l == 'down' || l == 'shutdown' || l == 'stopped')
				state = 'down';

			return '<span class="frr-peer-status frr-peer-status-' + state + '">'
				+ frr_html_escape(s) + '</span>';
		}

		function frr_peer_toggle(enabled) {
			var isEnabled = enabled != '0';
			var stateClass = isEnabled ? 'check' : 'cancel';
			var iconClass = isEnabled ? 'icon_check' : 'icon_cancel';
			var label = isEnabled ? 'Disable peer' : 'Enable peer';
			return '<div class="frr-peer-toggle ' + stateClass + '" role="button" tabindex="0"'
				+ ' aria-pressed="' + (isEnabled ? 'true' : 'false') + '" title="' + label + '"'
				+ ' onclick="toggle_frr_peer(this);"><div class="' + iconClass + '"></div></div>';
		}

		function frr_set_peer_enabled(row, enabled) {
			var value = enabled ? '1' : '0';
			row.setAttribute('data-enabled', value);
			row.className = enabled ? '' : 'frr-peer-disabled';
			var toggle = row.cells[0].getElementsByTagName('div')[0];
			toggle.className = 'frr-peer-toggle ' + (enabled ? 'check' : 'cancel');
			toggle.setAttribute('aria-pressed', enabled ? 'true' : 'false');
			toggle.title = enabled ? 'Disable peer' : 'Enable peer';
			toggle.getElementsByTagName('div')[0].className = enabled ? 'icon_check' : 'icon_cancel';
			row.cells[4].innerHTML = bgp_status_badge(enabled ? 'Configured' : 'Shutdown');
			row.cells[5].textContent = 'N/A';
		}

		function frr_update_peer_all(table_id, control_id) {
			var table = document.getElementById(table_id);
			var control = document.getElementById(control_id);
			var allEnabled = true;
			var count = 0;
			for (var row = 0; row < table.rows.length; row++) {
				if (table.rows[row].cells.length < 7) continue;
				count++;
				if (table.rows[row].getAttribute('data-enabled') == '0') allEnabled = false;
			}
			control.className = 'frr-peer-all ' + (count && !allEnabled ? 'all_enable' : 'all_disable');
		}

		function frr_toggle_all_peers(table_id, control_id) {
			var table = document.getElementById(table_id);
			var control = document.getElementById(control_id);
			var enable = control.className.indexOf('all_enable') >= 0;
			for (var row = 0; row < table.rows.length; row++) {
				if (table.rows[row].cells.length < 7) continue;
				frr_set_peer_enabled(table.rows[row], enable);
			}
			frr_update_peer_all(table_id, control_id);
		}

		function toggle_frr_peer(obj) {
			var row = obj.parentNode.parentNode;
			var enabled = row.getAttribute('data-enabled') == '0';
			frr_set_peer_enabled(row, enabled);
			var table_id = row.parentNode.id;
			frr_update_peer_all(table_id, table_id == 'bgp_neighbor_table' ? 'bgp_peer_toggle_all' : 'bfd_peer_toggle_all');
		}

		function initial() {
			show_menu();
			$('#divRoutingSwitchMenu').html(gen_switch_menu({
				'Routing Table': ['Routing Table', 'Main_RouteStatus_Content.asp'],
				'Dynamic Routing': ['Dynamic Routing', 'Advanced_FRR_Content.asp']
			}, 'Dynamic Routing'));
			var fields = ['frr_passwd', 'frr_enpasswd', 'frr_bgp_enable', 'frr_bgp_as',
				'frr_bgp_networks', 'frr_ospf_enable', 'frr_ospf_area', 'frr_ospf_networks',
				'frr_bfd_enable', 'frr_allow_lan', 'frr_config_dir'];
			for (var i = 0; i < fields.length; i++)
				document.form[fields[i]].value = frr_bgp_config[fields[i]] || '';
			normalize_frr_config_dir();

			// Show/hide protocol sections based on enable status
			showhide("frr_settings", (document.form.frr_enable.value == "1"));

			// Load BGP neighbor table
			show_bgp_neighbor_list();
			show_bfd_peer_list();
			frrInitialConfig = frr_config_signature();

			// Start status refresh (will show stopped if FRR disabled)
			setTimeout(refresh_frr_status, 1000);
		}

		function normalize_frr_config_dir() {
			var cfgField = document.form.frr_config_dir;

			if (!cfgField)
				return;

			// Clear the field when it holds the default so the placeholder shows instead
			if (cfgField.value == '' || cfgField.value == '/etc' || cfgField.value == frrDefaultConfigDir)
				cfgField.value = '';
		}

		function applyRule() {
			if (frr_bgp_config.error) {
				alert(frr_bgp_config.error);
				return false;
			}
			if (!validate_frr_config())
				return false;
			var regenerate = document.form.frr_force_regen_choice.value == '1';
			var changed = frr_config_signature() != frrInitialConfig;
			var config = frr_collect_config();
			var original = JSON.parse(frrInitialConfig || '{}');
			var peerStateOnly = !regenerate && changed && frr_peer_state_only_changed(original, config);
			config.frr_passwd_changed = config.frr_passwd != original.frr_passwd ? '1' : '0';
			config.frr_enpasswd_changed = config.frr_enpasswd != original.frr_enpasswd ? '1' : '0';
			delete config.frr_passwd;
			delete config.frr_enpasswd;
			var request = JSON.stringify(config);
			if (unescape(encodeURIComponent(request)).length > 8191) {
				alert('FRR settings exceed the supported request size');
				return false;
			}
			document.form.frr_ui_request.value = request;
			// Restore default before submit if the field was left empty
			var cfgField = document.form.frr_config_dir;
			if (cfgField && cfgField.value == '')
				cfgField.value = frrDefaultConfigDir;

			document.form.frr_force_regen.value = regenerate ? "1" : (peerStateOnly ? "3" : (changed ? "2" : "0"));

			showLoading();
			document.form.submit();
		}

		function validate_frr_config() {
			if (document.form.frr_enable.value == "0") {
				return true; // No validation needed if disabled
			}

			var cfg_dir = document.form.frr_config_dir.value;
			if (cfg_dir != "") {
				if (cfg_dir.charAt(0) != "/") {
					alert("Custom configuration directory must be an absolute path");
					document.form.frr_config_dir.focus();
					return false;
				}
				if (cfg_dir.indexOf("..") != -1) {
					alert("Custom configuration directory cannot contain '..'");
					document.form.frr_config_dir.focus();
					return false;
				}
			}

			// Validate BGP AS number if BGP is enabled
			if (document.form.frr_bgp_enable.value == "1") {
				var as_num = document.form.frr_bgp_as.value;
				var bgp_networks = document.form.frr_bgp_networks ? document.form.frr_bgp_networks.value : "";
				if (!/^\d+$/.test(as_num) || Number(as_num) < 1 || Number(as_num) > 4294967295) {
					alert("Please enter a valid BGP AS number (1-4294967295)");
					document.form.frr_bgp_as.focus();
					return false;
				}
				if (bgp_networks != "") {
					var nets = bgp_networks.split(/\s+/);
					for (var n = 0; n < nets.length; n++) {
						if (nets[n] == "")
							continue;
						if (!frr_valid_cidr(nets[n])) {
							alert("BGP networks must be in CIDR format (example: 192.168.0.0/24)");
							document.form.frr_bgp_networks.focus();
							return false;
						}
					}
				}
			}

			if (document.form.frr_ospf_enable.value == '1') {
				if (!frr_valid_area(document.form.frr_ospf_area.value)) {
					alert('OSPF area must be an IPv4 address or integer between 0 and 4294967295');
					document.form.frr_ospf_area.focus();
					return false;
				}
				var ospf_networks = document.form.frr_ospf_networks.value.split(/[\s>]+/);
				for (var o = 0; o < ospf_networks.length; o++) {
					if (ospf_networks[o] && !frr_valid_cidr(ospf_networks[o])) {
						alert('OSPF networks must be valid IPv4 CIDR prefixes');
						document.form.frr_ospf_networks.focus();
						return false;
					}
				}
			}

			var config = frr_collect_config();
			for (var ip in config.bgp_peers) {
				var peer = config.bgp_peers[ip];
				var asn = peer.as_number;
				if ((!/^\d+$/.test(asn) || Number(asn) < 1 || Number(asn) > 4294967295) &&
					asn != 'internal' && asn != 'external') {
					alert('Each BGP peer requires a valid remote AS');
					return false;
				}
				if (/[\r\n]/.test(peer.description)) {
					alert('Peer descriptions cannot contain line breaks');
					return false;
				}
			}
			for (var address in config.bfd_peers) {
				var bfd = config.bfd_peers[address];
				if (!frr_valid_interval(bfd.tx) || !frr_valid_interval(bfd.rx)) {
					alert('BFD intervals must be integers between 10 and 60000 ms');
					return false;
				}
			}
			if (/[\r\n]/.test(document.form.frr_passwd.value + document.form.frr_enpasswd.value)) {
				alert('Passwords cannot contain line breaks');
				return false;
			}

			return true;
		}

		function show_bgp_neighbor_list() {
			var bgp_neighbors = [];
			var configured = frr_bgp_config.bgp_peers || {};
			for (var ip in configured) {
				if (!Object.prototype.hasOwnProperty.call(configured, ip) || !configured[ip].is_peer) continue;
				var entry = configured[ip];
				entry.ip = ip;
				bgp_neighbors.push(entry);
			}
			var status_map = frr_bgp_neighbor_status_map || {};
			var code = "";

			if (bgp_neighbors.length == 0) {
				code = '<tr><td colspan="7" class="hint-color" style="text-align:center;"><#IPConnection_VSList_Norule#></td></tr>';
			} else {
				for (var i = 0; i < bgp_neighbors.length; i++) {
					if (bgp_neighbors[i].ip) {
						var peer = bgp_neighbors[i];
						var n_ip = peer.ip;
						var peer_info = status_map[n_ip] || {};
						var enabled = peer.enabled || '1';
						var n_status = enabled == '0' ? 'shutdown' : (peer_info.status || (frr_bgp_neighbor_status_map ? 'Configured' : 'Unknown'));
						code += '<tr data-enabled="' + enabled + '" data-update-source="' + frr_html_escape(peer.source || '') + '" class="' + (enabled == '0' ? 'frr-peer-disabled' : '') + '">';
						code += '<td width="6%">' + frr_peer_toggle(enabled) + '</td>';
						code += '<td width="18%">' + frr_html_escape(n_ip) + '</td>';
						code += '<td width="14%">' + frr_html_escape(peer.as_number || '') + '</td>';
						code += '<td width="24%">' + frr_html_escape(peer.description || '') + '</td>';
						code += '<td width="13%">' + bgp_status_badge(n_status) + '</td>';
						code += '<td width="13%" class="frr-peer-uptime">' + (enabled == '0' ? 'N/A' : format_peer_uptime(peer_info.uptime)) + '</td>';
						code += '<td width="12%"><div class="frr-peer-actions"><input type="button" class="edit_btn" onclick="edit_bgp_neighbor(this);" value=""/><div class="remove" role="button" tabindex="0" title="Delete peer" onclick="del_bgp_neighbor(this);"></div></div></td>';
						code += '</tr>';
					}
				}
			}

			document.getElementById('bgp_neighbor_table').innerHTML = code;
			frr_update_peer_all('bgp_neighbor_table', 'bgp_peer_toggle_all');
		}

		function add_bgp_neighbor() {
			var neighbor_ip = document.form.frr_bgp_neighbor_ip_x.value;
			var neighbor_as = document.form.frr_bgp_neighbor_as_x.value;
			var neighbor_desc = document.form.frr_bgp_neighbor_desc_x.value;

			// Validate IP address
			if (!validator.validIPForm(document.form.frr_bgp_neighbor_ip_x, 0)) {
				return false;
			}

			// Validate AS number
			if (!/^\d+$/.test(neighbor_as) || Number(neighbor_as) < 1 || Number(neighbor_as) > 4294967295) {
				alert("Please enter a valid AS number (1-4294967295)");
				document.form.frr_bgp_neighbor_as_x.focus();
				return false;
			}

			if (/[\r\n]/.test(neighbor_desc)) {
				alert("Description cannot contain line breaks");
				document.form.frr_bgp_neighbor_desc_x.focus();
				return false;
			}

			// Check for duplicates
			var table = document.getElementById('bgp_neighbor_table');
			for (var i = 0; i < table.rows.length; i++) {
				if (table.rows[i].cells[1] && table.rows[i].cells[1].textContent == neighbor_ip) {
					alert("This BGP neighbor already exists");
					return false;
				}
			}

			// Add new row
			var enabled = frr_bgp_edit_enabled || '1';
			var row_code = '<tr data-enabled="' + enabled + '" data-update-source="' + frr_html_escape(frr_bgp_edit_source || '') + '" class="' + (enabled == '0' ? 'frr-peer-disabled' : '') + '">';
			row_code += '<td width="6%">' + frr_peer_toggle(enabled) + '</td>';
			row_code += '<td width="18%">' + frr_html_escape(neighbor_ip) + '</td>';
			row_code += '<td width="14%">' + frr_html_escape(neighbor_as) + '</td>';
			row_code += '<td width="24%">' + frr_html_escape(neighbor_desc) + '</td>';
			row_code += '<td width="13%">' + bgp_status_badge(enabled == '0' ? 'shutdown' : 'Configured') + '</td>';
			row_code += '<td width="13%" class="frr-peer-uptime">N/A</td>';
			row_code += '<td width="12%"><div class="frr-peer-actions"><input type="button" class="edit_btn" onclick="edit_bgp_neighbor(this);" value=""/><div class="remove" role="button" tabindex="0" title="Delete peer" onclick="del_bgp_neighbor(this);"></div></div></td>';
			frr_bgp_edit_source = '';
			frr_bgp_edit_enabled = '1';
			row_code += '</tr>';

			if (table.rows.length == 1 && table.rows[0].cells.length == 1) {
				// Replace "no rules" message
				document.getElementById('bgp_neighbor_table').innerHTML = row_code;
			} else {
				document.getElementById('bgp_neighbor_table').innerHTML += row_code;
			}
			frr_update_peer_all('bgp_neighbor_table', 'bgp_peer_toggle_all');

			// Clear input fields
			document.form.frr_bgp_neighbor_ip_x.value = "";
			document.form.frr_bgp_neighbor_as_x.value = "";
			document.form.frr_bgp_neighbor_desc_x.value = "";
		}

		function edit_bgp_neighbor(obj) {
			var row = frr_peer_row_from_action(obj);
			if (!row) return false;
			var cells = row.cells;
			document.form.frr_bgp_neighbor_ip_x.value = cells[1].textContent;
			document.form.frr_bgp_neighbor_as_x.value = cells[2].textContent;
			document.form.frr_bgp_neighbor_desc_x.value = cells[3].textContent;
			frr_bgp_edit_source = row.getAttribute('data-update-source') || '';
			frr_bgp_edit_enabled = row.getAttribute('data-enabled') || '1';
			del_bgp_neighbor(obj);
			document.form.frr_bgp_neighbor_ip_x.focus();
		}

		function del_bgp_neighbor(obj) {
			var row = frr_peer_row_from_action(obj);
			if (!row) return false;
			row.parentNode.removeChild(row);

			// If table is empty, show "no rules" message
			var table = document.getElementById('bgp_neighbor_table');
			if (table.rows.length == 0) {
				table.innerHTML = '<tr><td colspan="7" class="hint-color" style="text-align:center;"><#IPConnection_VSList_Norule#></td></tr>';
			}
			frr_update_peer_all('bgp_neighbor_table', 'bgp_peer_toggle_all');
		}

		function bfd_peer_row(ip, tx, rx, options, enabled) {
			enabled = enabled || '1';
			return '<tr data-enabled="' + enabled + '" data-options="' + frr_html_escape(options || '') + '" class="' + (enabled == '0' ? 'frr-peer-disabled' : '') + '">'
				+ '<td width="6%">' + frr_peer_toggle(enabled) + '</td>'
				+ '<td width="24%">' + frr_html_escape(ip) + '</td>'
				+ '<td width="12%">' + frr_html_escape(tx || '300') + '</td>'
				+ '<td width="12%">' + frr_html_escape(rx || '300') + '</td>'
				+ '<td width="14%">' + bgp_status_badge(enabled == '0' ? 'shutdown' : 'Configured') + '</td>'
				+ '<td width="20%" class="frr-bfd-uptime">N/A</td>'
				+ '<td width="12%"><div class="frr-peer-actions"><input type="button" class="edit_btn" onclick="edit_bfd_peer(this);" value="" />'
				+ '<div class="remove" role="button" tabindex="0" title="Delete peer" onclick="del_bfd_peer(this);"></div></div></td></tr>';
		}

		function show_bfd_peer_list() {
			var peers = frr_bgp_config.bfd_peers || {};
			var code = '';
			for (var ip in peers) {
				if (Object.prototype.hasOwnProperty.call(peers, ip))
					code += bfd_peer_row(ip, peers[ip].tx, peers[ip].rx, peers[ip].options, peers[ip].enabled);
			}
			document.getElementById('bfd_peer_table').innerHTML = code;
			frr_update_peer_all('bfd_peer_table', 'bfd_peer_toggle_all');
		}

		function add_bfd_peer() {
			var ip = document.form.frr_bfd_peer_x;
			var tx = document.form.frr_bfd_tx_x.value || '300';
			var rx = document.form.frr_bfd_rx_x.value || '300';
			if (!validator.validIPForm(ip, 0)) return false;
			if (!frr_valid_interval(tx) || !frr_valid_interval(rx)) {
				alert('BFD intervals must be integers between 10 and 60000 ms');
				return false;
			}
			var table = document.getElementById('bfd_peer_table');
			for (var row = 0; row < table.rows.length; row++) {
				if (frr_cell_value(table.rows[row].cells[1]) == ip.value) {
					alert('This BFD peer already exists');
					return false;
				}
			}
			table.insertAdjacentHTML('beforeend', bfd_peer_row(ip.value, tx, rx, frr_bfd_edit_options, frr_bfd_edit_enabled));
			frr_bfd_edit_options = '';
			frr_bfd_edit_enabled = '1';
			frr_update_peer_all('bfd_peer_table', 'bfd_peer_toggle_all');
			ip.value = '';
		}

		function edit_bfd_peer(obj) {
			var row = frr_peer_row_from_action(obj);
			if (!row) return false;
			var cells = row.cells;
			document.form.frr_bfd_peer_x.value = cells[1].textContent;
			document.form.frr_bfd_tx_x.value = cells[2].textContent;
			document.form.frr_bfd_rx_x.value = cells[3].textContent;
			frr_bfd_edit_options = row.getAttribute('data-options') || '';
			frr_bfd_edit_enabled = row.getAttribute('data-enabled') || '1';
			row.parentNode.removeChild(row);
			frr_update_peer_all('bfd_peer_table', 'bfd_peer_toggle_all');
			document.form.frr_bfd_peer_x.focus();
		}

		function del_bfd_peer(obj) {
			var row = frr_peer_row_from_action(obj);
			if (!row) return false;
			row.parentNode.removeChild(row);
			frr_update_peer_all('bfd_peer_table', 'bfd_peer_toggle_all');
		}

		function update_peer_status(table_id, statuses, fallback) {
			var table = document.getElementById(table_id);
			for (var row = 0; row < table.rows.length; row++) {
				if (table.rows[row].cells.length < 7) continue;
				var ip = frr_cell_value(table.rows[row].cells[1]);
				var peer = (statuses || {})[ip];
				var status = peer && typeof peer == 'object' ? peer.status : peer;
				if (table.rows[row].getAttribute('data-enabled') == '0') status = 'shutdown';
				table.rows[row].cells[4].innerHTML = bgp_status_badge(status || fallback);
			}
		}

		function format_peer_uptime(seconds) {
			if (typeof seconds != 'number' || seconds < 0)
				return 'N/A';

			var days = Math.floor(seconds / 86400);
			var hours = Math.floor((seconds % 86400) / 3600);
			var minutes = Math.floor((seconds % 3600) / 60);
			var remaining = seconds % 60;
			var parts = [];
			if (days) parts.push(days + 'd');
			if (hours || days) parts.push(hours + 'h');
			if (minutes || hours || days) parts.push(minutes + 'm');
			parts.push(remaining + 's');
			return parts.join(' ');
		}

		function update_peer_uptime(table_id, peers) {
			var table = document.getElementById(table_id);
			for (var row = 0; row < table.rows.length; row++) {
				if (table.rows[row].cells.length < 7) continue;
				var ip = frr_cell_value(table.rows[row].cells[1]);
				var peer = (peers || {})[ip];
				table.rows[row].cells[5].textContent = table.rows[row].getAttribute('data-enabled') == '0'
					? 'N/A' : format_peer_uptime(peer && peer.uptime);
			}
		}

		function update_bgp_status(peers, running) {
			var table = document.getElementById('bgp_neighbor_table');
			if (running !== false && !peers) {
				table.title = 'BGP status unavailable; last successful update is stale';
				if (frr_bgp_status_time && Date.now() - frr_bgp_status_time < 15000)
					return;
				update_peer_status('bgp_neighbor_table', {}, 'Unknown');
				update_peer_uptime('bgp_neighbor_table', {});
				return;
			}
			table.title = '';
			frr_bgp_status_time = Date.now();
			update_peer_status('bgp_neighbor_table', running === false ? {} : peers,
				running === false ? 'Stopped' : 'Configured');
			update_peer_uptime('bgp_neighbor_table', running === false ? {} : peers);
		}

		function refresh_frr_status() {
			$.ajax({
				url: '/ajax_frr_status.asp',
				dataType: 'json',
				cache: false,
				timeout: 5000,
				error: function (xhr) {
					update_bgp_status(null);
					update_peer_status('bfd_peer_table', {}, 'Unknown');
						update_peer_uptime('bfd_peer_table', {});
					setTimeout(refresh_frr_status, 5000);
				},
				success: function (data) {
					update_bgp_status(data.bgp_peers, !!data.bgpd_running);
						update_peer_status('bfd_peer_table', data.bfd_peers, 'Configured');
						update_peer_uptime('bfd_peer_table', data.bfd_peers);
					// Update status indicators
					if (data.zebra_running) {
						document.getElementById('zebra_status').innerHTML = '<span class="frr-running">Running</span>';
					} else {
						document.getElementById('zebra_status').innerHTML = '<span class="frr-stopped">Stopped</span>';
					}

					if (data.bgpd_running) {
						document.getElementById('bgpd_status').innerHTML = '<span class="frr-running">Running</span>';
					} else {
						document.getElementById('bgpd_status').innerHTML = '<span class="frr-stopped">Stopped</span>';
					}

					if (data.ospfd_running) {
						document.getElementById('ospfd_status').innerHTML = '<span class="frr-running">Running</span>';
					} else {
						document.getElementById('ospfd_status').innerHTML = '<span class="frr-stopped">Stopped</span>';
					}

					if (data.staticd_running) {
						document.getElementById('staticd_status').innerHTML = '<span class="frr-running">Running</span>';
					} else {
						document.getElementById('staticd_status').innerHTML = '<span class="frr-stopped">Stopped</span>';
					}

					if (data.bfdd_running) {
						document.getElementById('bfdd_status').innerHTML = '<span class="frr-running">Running</span>';
					} else {
						document.getElementById('bfdd_status').innerHTML = '<span class="frr-stopped">Stopped</span>';
					}

					if (data.watchfrr_running) {
						document.getElementById('watchfrr_status').innerHTML = '<span class="frr-running">Running</span>';
					} else {
						document.getElementById('watchfrr_status').innerHTML = '<span class="frr-stopped">Stopped</span>';
					}

					// Schedule next refresh
					setTimeout(refresh_frr_status, 5000);
				}
			});
		}
	</script>
	<style type="text/css">
		input[name="frr_config_dir"]::placeholder { color: #888; }
		.FormTable_table td .frr-peer-status {
			display: inline-block;
			padding: 1px 7px;
			border-radius: 9px;
			color: #1b1b1b;
			font-size: 11px;
			font-weight: 600;
		}
		.FormTable_table td .frr-peer-status-configured { background: #FFCC66; }
		.FormTable_table td .frr-peer-status-up { background: #7CFC7C; }
		.FormTable_table td .frr-peer-status-connecting { background: #6ED0FF; }
		.FormTable_table td .frr-peer-status-down { background: #FF9A9A; }
		.frr-peer-toggle {
			width: 22px;
			height: 22px;
			margin: 0 auto;
			border-radius: 50%;
			cursor: pointer;
			transition: .35s;
		}
		.frr-peer-toggle.check { border: 2px solid #093; background: #093; }
		.frr-peer-toggle.cancel { border: 2px solid #898989; background: #898989; }
		.frr-peer-toggle:active { transform: scale(1.5); opacity: .5; transition: 0; }
		.frr-peer-toggle > div { width: 16px; height: 16px; margin: 3px auto; }
		.frr-peer-disabled td { color: #A0A0A0; }
		.frr-peer-all {
			width: 40px;
			margin: auto;
			cursor: pointer;
		}
		.frr-peer-all.all_enable { border: 1px solid #393; color: #393; }
		.frr-peer-all.all_disable { border: 1px solid #999; color: #999; }
		.frr-peer-actions {
			display: flex;
			align-items: center;
			justify-content: center;
			gap: 4px;
			min-height: 32px;
		}
		.frr-peer-actions .edit_btn,
		.frr-peer-actions .remove { flex: 0 0 auto; margin: 0; }
		table.FormTable_table.frr-bgp-table thead th { color: #FFFFFF; }
		table.FormTable_table.frr-bfd-table thead th { color: #FFFFFF; }
		.frr-daemon-status { display: inline-block; min-width: 125px; color: #FFFFFF; }
		.FormTable td .frr-running { color: #7CFC7C; }
		.FormTable td .frr-stopped { color: #FF9A9A; }
	</style>
</head>

<body onload="initial();" onunLoad="return unload_body();" class="bg">
	<div id="TopBanner"></div>
	<div id="Loading" class="popup_bg"></div>

	<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>

	<form method="post" name="form" action="/start_apply.htm" target="hidden_frame">
		<input type="hidden" name="current_page" value="Advanced_FRR_Content.asp">
		<input type="hidden" name="next_page" value="Advanced_FRR_Content.asp">
		<input type="hidden" name="modified" value="0">
		<input type="hidden" name="action_mode" value="apply">
		<input type="hidden" name="action_script" value="restart_frr">
		<input type="hidden" name="action_wait" value="10">
		<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>">
		<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">
		<input type="hidden" name="frr_force_regen" value="0">
		<input type="hidden" name="frr_ui_request" value="">

		<table class="content" align="center" cellpadding="0" cellspacing="0">
			<tr>
				<td width="17">&nbsp;</td>
				<td valign="top" width="202">
					<div id="mainMenu"></div>
					<div id="subMenu"></div>
				</td>
				<td valign="top">
					<div id="tabMenu" class="submenuBlock"></div>

					<!--===================================Beginning of Main Content===========================================-->
					<table width="98%" border="0" align="left" cellpadding="0" cellspacing="0">
						<tr>
							<td align="left" valign="top">
								<table width="98%" style="max-width:760px;" border="0" cellpadding="5" cellspacing="0" class="FormTitle"
									id="FormTitle">
									<tbody>
										<tr>
											<td bgcolor="#4D595D" valign="top">
												<div>&nbsp;</div>
												<div class="formfonttitle">
													<#menu5_2#> - <#menu5_2_4#>
												</div>
													<div id="divRoutingSwitchMenu" style="margin-top:-40px;float:right;"></div>
												<div style="margin:10px 0 10px 5px;" class="splitLine"></div>
												<div class="formfontdesc">
													<#FRR_desc#>
												</div>

												<!-- Enable FRR -->
												<table width="100%" border="1" align="center" cellpadding="4"
													cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
													<thead>
														<tr>
															<td colspan="2">
																<#t2BC#>
															</td>
														</tr>
													</thead>
													<tr>
														<th>
															<#FRR_enable#>
														</th>
														<td>
															<input type="hidden" name="frr_enable" value="<% nvram_get("frr_enable"); %>">
															<div align="center" class="left" style="width:94px; float:left; cursor:pointer;" id="radio_frr_enable"></div>
															<div class="iphone_switch_container" style="height:32px; width:74px; position:relative; overflow:hidden;">
																<script type="text/javascript">
																	$('#radio_frr_enable').iphoneSwitch(document.form.frr_enable.value,
																		function() {
																			document.form.frr_enable.value = 1;
																			showhide('frr_settings', 1);
																		},
																		function() {
																			document.form.frr_enable.value = 0;
																			showhide('frr_settings', 0);
																		},
																		{
																			switch_on_container_path: '/switcherplugin/iphone_switch_container_off.png'
																		});
																</script>
															</div>
														</td>
													</tr>
												</table>

												<!-- FRR Settings -->
												<div id="frr_settings" style="display:none;">
													<!-- Basic Settings -->
													<table width="100%" border="1" align="center" cellpadding="4"
														cellspacing="0" bordercolor="#6b8fa3" class="FormTable"
														style="margin-top:8px;">
														<thead>
															<tr>
																<td colspan="2">
																	<#FRR_basic_settings#>
																</td>
															</tr>
														</thead>
														<tr>
															<th width="40%">
																<#FRR_password#>
															</th>
															<td>
																<input type="password" maxlength="64"
																	class="input_25_table" name="frr_passwd"
																		value=""
																autocomplete="off" autocorrect="off"
																autocapitalize="off">
															</td>
														</tr>
														<tr>
															<th>
																<#FRR_enable_password#>
															</th>
															<td>
																<input type="password" maxlength="64"
																	class="input_25_table" name="frr_enpasswd"
																			value=""
																autocomplete="off" autocorrect="off"
																autocapitalize="off">
															</td>
														</tr>
														<tr>
															<th>
																<#FRR_allow_lan#>
															</th>
															<td>
																<input type="radio" value="1" name="frr_allow_lan"
																	class="input" <% nvram_match("frr_allow_lan", "1"
																	, "checked" ); %>><#checkbox_Yes#>
																	<input type="radio" value="0" name="frr_allow_lan"
																		class="input" <%
																		nvram_match("frr_allow_lan", "0" , "checked" );
																		%>><#checkbox_No#>
																		<span class="hint-color">
																			<#FRR_allow_lan_hint#>
																		</span>
															</td>
														</tr>
													</table>

													<!-- BGP Configuration -->
													<table width="100%" border="1" align="center" cellpadding="4"
														cellspacing="0" bordercolor="#6b8fa3" class="FormTable"
														style="margin-top:8px;">
														<thead>
															<tr>
																<td colspan="2">
																	<#FRR_bgp_title#>
																</td>
															</tr>
														</thead>
														<tr>
															<th width="40%">
																<#FRR_bgp_enable#>
															</th>
															<td>
																<input type="radio" value="1" name="frr_bgp_enable"
																	class="input" <% nvram_match("frr_bgp_enable", "1"
																	, "checked" ); %>><#checkbox_Yes#>
																	<input type="radio" value="0" name="frr_bgp_enable"
																		class="input" <%
																		nvram_match("frr_bgp_enable", "0" , "checked" );
																		%>><#checkbox_No#>
															</td>
														</tr>
														<tr>
															<th>
																<#FRR_bgp_as#>
															</th>
															<td>
																<input type="text" maxlength="10" class="input_12_table"
																		name="frr_bgp_as" value="" onKeyPress="return
																validator.isNumber(this,event);">
																<span class="hint-color"> (1-4294967295)</span>
																<div
																	class="hint-color" style="font-size:11px;margin-top:4px;">
																	Supports multiple neighbors. Runtime-discovered
																	peers appear when FRR daemons are running.</div>
															</td>
														</tr>
													<tr>
														<th>
															BGP Networks
														</th>
														<td>
															<span class="hint-color">CIDR, space/newline separated, e.g. 192.168.0.0/24</span><br>
															<textarea name="frr_bgp_networks"
																class="textarea_ssh_table"
																style="width:98%;height:56px;"
																autocomplete="off" autocorrect="off"
																		autocapitalize="off"></textarea>
														</td>
													</tr>
													</table>
												<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable_table frr-bgp-table" style="margin-top:8px;">
													<thead>
														<tr><td colspan="7"><#FRR_bgp_neighbor_list#></td></tr>
														<tr>
															<th width="6%"><div id="bgp_peer_toggle_all" class="frr-peer-all all_disable" onclick="frr_toggle_all_peers('bgp_neighbor_table','bgp_peer_toggle_all');"><#All#></div></th>
															<th width="18%"><#FRR_neighbor_ip#></th>
															<th width="14%"><#FRR_neighbor_as#></th>
															<th width="24%">Description</th>
															<th width="13%">Status</th>
															<th width="13%">Uptime</th>
															<th width="12%"><#list_add_delete#></th>
														</tr>
													</thead>
													<tbody id="bgp_neighbor_form">
													<tr>
														<td></td>
														<td><input type="text" maxlength="15" class="input_15_table" name="frr_bgp_neighbor_ip_x" placeholder="192.168.0.1" onKeyPress="return validator.isIPAddr(this,event);"></td>
														<td><input type="text" maxlength="10" class="input_12_table" name="frr_bgp_neighbor_as_x" placeholder="65001" onKeyPress="return validator.isNumber(this,event);"></td>
														<td><input type="text" maxlength="63" class="input_20_table" name="frr_bgp_neighbor_desc_x" placeholder="ROUTER"></td>
														<td></td>
														<td></td>
														<td><input type="button" class="add_btn" onClick="add_bgp_neighbor();" value=""></td>
													</tr>
													</tbody>
													<tbody id="bgp_neighbor_table"></tbody>
												</table>

													<!-- OSPF Configuration -->
													<table width="100%" border="1" align="center" cellpadding="4"
														cellspacing="0" bordercolor="#6b8fa3" class="FormTable"
														style="margin-top:8px;">
														<thead>
															<tr>
																<td colspan="2">
																	<#FRR_ospf_title#>
																</td>
															</tr>
														</thead>
														<tr>
															<th width="40%">
																<#FRR_ospf_enable#>
															</th>
															<td>
																<input type="radio" value="1" name="frr_ospf_enable"
																	class="input" <% nvram_match("frr_ospf_enable", "1"
																	, "checked" ); %>><#checkbox_Yes#>
																	<input type="radio" value="0" name="frr_ospf_enable"
																		class="input" <%
																		nvram_match("frr_ospf_enable", "0" , "checked"
																		); %>><#checkbox_No#>
															</td>
														</tr>
														<tr>
															<th>
																<#FRR_ospf_area#>
															</th>
															<td>
																<input type="text" maxlength="15" class="input_15_table"
																		name="frr_ospf_area" value=""
																placeholder="0.0.0.0">
															</td>
														</tr>
														<tr>
															<th>
																<#FRR_ospf_networks#>
															</th>
															<td>
																<textarea name="frr_ospf_networks"
																	class="textarea_ssh_table"
																	style="width:98%;height:80px;" autocomplete="off"
																	autocorrect="off"
																			autocapitalize="off"></textarea>
																<span class="hint-color">
																	<#FRR_ospf_networks_hint#>
																</span>
																<div
																	class="hint-color" style="font-size:11px;margin-top:4px;">
																	One CIDR per line. Learned OSPF routes are labeled
																	on the Routing Table page.</div>
															</td>
														</tr>
													</table>

													<!-- BFD Configuration -->
													<table width="100%" border="1" align="center" cellpadding="4"
														cellspacing="0" bordercolor="#6b8fa3" class="FormTable"
														style="margin-top:8px;">
														<thead>
															<tr>
																<td colspan="2">
																	<#FRR_bfd_title#>
																</td>
															</tr>
														</thead>
														<tr>
															<th width="40%">
																<#FRR_bfd_enable#>
															</th>
															<td>
																<input type="radio" value="1" name="frr_bfd_enable"
																	class="input" <% nvram_match("frr_bfd_enable", "1"
																	, "checked" ); %>><#checkbox_Yes#>
																	<input type="radio" value="0" name="frr_bfd_enable"
																		class="input" <%
																		nvram_match("frr_bfd_enable", "0" , "checked" );
																		%>><#checkbox_No#>
																	<div class="hint-color" style="font-size:11px;margin-top:4px;">
																		BFD is critical for fast failure detection with dynamic routing peers.
																	</div>
															</td>
														</tr>
													</table>
														<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable_table frr-bfd-table" style="margin-top:8px;">
															<thead>
																<tr><td colspan="7">BFD Peers</td></tr>
																<tr>
																	<th width="6%"><div id="bfd_peer_toggle_all" class="frr-peer-all all_disable" onclick="frr_toggle_all_peers('bfd_peer_table','bfd_peer_toggle_all');"><#All#></div></th>
																	<th width="24%">Peer</th>
																	<th width="12%">TX(ms)</th>
																	<th width="12%">RX(ms)</th>
																	<th width="14%">Status</th>
																	<th width="20%">Uptime</th>
																	<th width="12%"><#list_add_delete#></th>
																</tr>
															</thead>
															<tbody id="bfd_peer_form">
																<tr>
																	<td></td>
																	<td><input type="text" maxlength="15" class="input_15_table" name="frr_bfd_peer_x" placeholder="192.168.0.2" onKeyPress="return validator.isIPAddr(this,event);"></td>
																	<td><input type="text" maxlength="5" class="input_6_table" name="frr_bfd_tx_x" onKeyPress="return validator.isNumber(this,event);"></td>
																	<td><input type="text" maxlength="5" class="input_6_table" name="frr_bfd_rx_x" onKeyPress="return validator.isNumber(this,event);"></td>
																	<td></td>
																	<td></td>
																	<td><input type="button" class="add_btn" onclick="add_bfd_peer();" value=""></td>
																</tr>
															</tbody>
															<tbody id="bfd_peer_table"></tbody>
														</table>

													<!-- Status Display -->
													<table width="100%" border="1" align="center" cellpadding="4"
														cellspacing="0" bordercolor="#6b8fa3" class="FormTable"
														style="margin-top:8px;">
														<thead>
															<tr>
																<td colspan="2">
																	<#FRR_status#>
																</td>
															</tr>
														</thead>
														<tr>
															<th width="40%"><#FRR_status#></th>
															<td style="line-height:1.8;">
																<span class="frr-daemon-status">Zebra: <span id="zebra_status"><#Status_Checking#></span></span>
																<span class="frr-daemon-status">BGP: <span id="bgpd_status"><#Status_Checking#></span></span>
																<span class="frr-daemon-status">OSPF: <span id="ospfd_status"><#Status_Checking#></span></span><br>
																<span class="frr-daemon-status">Static: <span id="staticd_status"><#Status_Checking#></span></span>
																<span class="frr-daemon-status">BFD: <span id="bfdd_status"><#Status_Checking#></span></span>
																<span class="frr-daemon-status">Watchfrr: <span id="watchfrr_status"><#Status_Checking#></span></span>
															</td>
														</tr>
													</table>

													<!-- Advanced Settings -->
													<table width="100%" border="1" align="center" cellpadding="4"
														cellspacing="0" bordercolor="#6b8fa3" class="FormTable"
														style="margin-top:8px;">
														<thead>
															<tr>
																<td colspan="2">
																	<#FRR_advanced#>
																</td>
															</tr>
														</thead>
														<tr>
															<th width="40%">
																<#FRR_force_regen#>
															</th>
															<td>
																<input type="radio" value="1" name="frr_force_regen_choice"
																	class="input">
																<#checkbox_Yes#>
																	<input type="radio" value="0" name="frr_force_regen_choice"
																		class="input" checked>
																	<#checkbox_No#>
																		<span class="hint-color">
																			<#FRR_force_regen_hint#>
																		</span>
															</td>
														</tr>
														<tr>
															<th>
																<#FRR_custom_config#>
															</th>
															<td>
																<input type="text" maxlength="128"
																	class="input_32_table" name="frr_config_dir"
																		value="<% nvram_get("frr_config_dir"); %>"																	placeholder="/jffs/configs/frr"																autocomplete="off" autocorrect="off"
																autocapitalize="off">
																<span class="hint-color">
																	<#FRR_custom_config_hint#>
																</span>
																<div
																	class="hint-color" style="font-size:11px;margin-top:4px;">
																	External integrated config: place <span
																		style="color:#FFCC00;">frr.conf</span> in this
																		directory. Optional companion file is <span
																			style="color:#FFCC00;">daemons</span>.
																</div>
															</td>
														</tr>
													</table>
												</div>

												<div class="apply_gen">
													<input class="button_gen" onclick="applyRule();" type="button"
														value="<#CTL_apply#>" />
												</div>
											</td>
										</tr>
									</tbody>
								</table>
							</td>
						</tr>
					</table>
					<!--===================================Ending of Main Content===========================================-->
				</td>
				<td width="10" align="center" valign="top">&nbsp;</td>
			</tr>
		</table>

		<div id="footer"></div>
	</form>
</body>

</html>