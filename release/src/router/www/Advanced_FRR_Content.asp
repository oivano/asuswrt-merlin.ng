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
	<script type="text/javascript" src="/js/jquery.js"></script>
	<script language="JavaScript" type="text/javascript" src="/state.js"></script>
	<script language="JavaScript" type="text/javascript" src="/general.js"></script>
	<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
	<script type="text/javascript" language="JavaScript" src="/help.js"></script>
	<script type="text/javascript" language="JavaScript" src="/validator.js"></script>
	<script type="text/javascript" language="JavaScript" src="/js/frr_config.js"></script>
	<script>
		var frr_bgp_neighbor_status_map = <% get_frr_bgp_neighbor_status_map(); %>;
		var frr_bgp_config = <% get_frr_bgp_config(); %>;
		var frrDefaultConfigDir = '/jffs/configs/frr';
		var frrInitialConfig = '';

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
				if (table.rows[row].cells.length < 5) continue;
				var ip = frr_cell_value(table.rows[row].cells[1]);
				values.bgp_peers[ip] = {
					as_number: frr_cell_value(table.rows[row].cells[2]),
					description: frr_cell_value(table.rows[row].cells[3]),
					source: table.rows[row].getAttribute('data-update-source') || ''
				};
			}
			var bfd = document.getElementById('bfd_peer_table');
			for (var peer = 0; peer < bfd.rows.length; peer++) {
				if (bfd.rows[peer].cells.length < 4) continue;
				values.bfd_peers[frr_cell_value(bfd.rows[peer].cells[1])] = {
					tx: frr_cell_value(bfd.rows[peer].cells[2]) || '300',
					rx: frr_cell_value(bfd.rows[peer].cells[3]) || '300',
					options: bfd.rows[peer].getAttribute('data-options') || ''
				};
			}
			return values;
		}

		function frr_cell_value(cell) {
			var input = cell.querySelector('input[type="text"]');
			return input ? input.value : cell.textContent;
		}

		function bgp_status_badge(status) {
			var s = (status || 'Configured').toString();
			var l = s.toLowerCase();
			var color = '#FFCC66';

			if (l == 'established' || l == 'up')
				color = '#7CFC7C';
			else if (l == 'active' || l == 'connect')
				color = '#6ED0FF';
			else if (l == 'idle' || l == 'down' || l == 'shutdown')
				color = '#FF9A9A';

			return '<span style="display:inline-block;padding:1px 7px;border-radius:9px;'
				+ 'background:' + color + ';color:#1b1b1b;font-size:11px;font-weight:600;">'
				+ frr_html_escape(s) + '</span>';
		}

		function initial() {
			show_menu();
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

		function routeStatusLink() {
			location.href = 'Main_RouteStatus_Content.asp';
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

			document.form.frr_force_regen.value = regenerate ? "1" : (changed ? "2" : "0");

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
				code = '<tr><td colspan="5" style="text-align:center;color:#FFCC00;"><#IPConnection_VSList_Norule#></td></tr>';
			} else {
				for (var i = 0; i < bgp_neighbors.length; i++) {
					if (bgp_neighbors[i].ip) {
						var peer = bgp_neighbors[i];
						var n_ip = peer.ip;
						var n_status = status_map[n_ip] || 'Configured';
						code += '<tr data-update-source="' + frr_html_escape(peer.source || '') + '">';
						code += '<td width="5%"><input type="button" class="remove_btn" onclick="del_bgp_neighbor(this);" value=""/></td>';
						code += '<td width="25%">' + frr_html_escape(n_ip) + '</td>';
						code += '<td width="15%"><input type="text" maxlength="10" style="width:95%;" value="' + frr_html_escape(peer.as_number || '') + '" /></td>';
						code += '<td width="35%"><input type="text" maxlength="63" style="width:95%;" value="' + frr_html_escape(peer.description || '') + '" /></td>';
						code += '<td width="20%">' + bgp_status_badge(n_status) + '</td>';
						code += '</tr>';
					}
				}
			}

			document.getElementById('bgp_neighbor_table').innerHTML = code;
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
			var row_code = '<tr>';
			row_code += '<td width="5%"><input type="button" class="remove_btn" onclick="del_bgp_neighbor(this);" value=""/></td>';
			row_code += '<td width="25%">' + frr_html_escape(neighbor_ip) + '</td>';
			row_code += '<td width="15%">' + frr_html_escape(neighbor_as) + '</td>';
			row_code += '<td width="35%">' + frr_html_escape(neighbor_desc) + '</td>';
			row_code += '<td width="20%">' + bgp_status_badge('Configured') + '</td>';
			row_code += '</tr>';

			if (table.rows.length == 1 && table.rows[0].cells.length == 1) {
				// Replace "no rules" message
				document.getElementById('bgp_neighbor_table').innerHTML = row_code;
			} else {
				document.getElementById('bgp_neighbor_table').innerHTML += row_code;
			}

			// Clear input fields
			document.form.frr_bgp_neighbor_ip_x.value = "";
			document.form.frr_bgp_neighbor_as_x.value = "";
			document.form.frr_bgp_neighbor_desc_x.value = "";
		}

		function del_bgp_neighbor(obj) {
			var row = obj.parentNode.parentNode;
			row.parentNode.removeChild(row);

			// If table is empty, show "no rules" message
			var table = document.getElementById('bgp_neighbor_table');
			if (table.rows.length == 0) {
				table.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#FFCC00;"><#IPConnection_VSList_Norule#></td></tr>';
			}
		}

		function bfd_peer_row(ip, tx, rx, options) {
			return '<tr data-options="' + frr_html_escape(options || '') + '">'
				+ '<td><input type="button" class="remove_btn" onclick="this.parentNode.parentNode.parentNode.removeChild(this.parentNode.parentNode);" value="" /></td>'
				+ '<td>' + frr_html_escape(ip) + '</td>'
				+ '<td><input type="text" maxlength="5" style="width:70px;" value="' + frr_html_escape(tx || '300') + '" /></td>'
				+ '<td><input type="text" maxlength="5" style="width:70px;" value="' + frr_html_escape(rx || '300') + '" /></td>'
				+ '<td>' + bgp_status_badge('Configured') + '</td></tr>';
		}

		function show_bfd_peer_list() {
			var peers = frr_bgp_config.bfd_peers || {};
			var code = '';
			for (var ip in peers) {
				if (Object.prototype.hasOwnProperty.call(peers, ip))
					code += bfd_peer_row(ip, peers[ip].tx, peers[ip].rx, peers[ip].options);
			}
			document.getElementById('bfd_peer_table').innerHTML = code;
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
			table.insertAdjacentHTML('beforeend', bfd_peer_row(ip.value, tx, rx, ''));
			ip.value = '';
		}

		function update_peer_status(table_id, statuses, fallback) {
			var table = document.getElementById(table_id);
			for (var row = 0; row < table.rows.length; row++) {
				if (table.rows[row].cells.length < 5) continue;
				var ip = frr_cell_value(table.rows[row].cells[1]);
				table.rows[row].cells[4].innerHTML = bgp_status_badge((statuses || {})[ip] || fallback);
			}
		}

		function refresh_frr_status() {
			$.ajax({
				url: '/ajax_frr_status.asp',
				dataType: 'json',
				cache: false,
				timeout: 5000,
				error: function (xhr) {
					update_peer_status('bgp_neighbor_table', {}, 'Unknown');
					update_peer_status('bfd_peer_table', {}, 'Unknown');
					setTimeout(refresh_frr_status, 5000);
				},
				success: function (data) {
					update_peer_status('bgp_neighbor_table', data.bgp_peer_status, 'Configured');
					update_peer_status('bfd_peer_table', data.bfd_peer_status, 'Configured');
					// Update status indicators
					if (data.zebra_running) {
						document.getElementById('zebra_status').innerHTML = '<span style="color:#0F0;">Running</span>';
					} else {
						document.getElementById('zebra_status').innerHTML = '<span style="color:#F00;">Stopped</span>';
					}

					if (data.bgpd_running) {
						document.getElementById('bgpd_status').innerHTML = '<span style="color:#0F0;">Running</span>';
					} else {
						document.getElementById('bgpd_status').innerHTML = '<span style="color:#F00;">Stopped</span>';
					}

					if (data.ospfd_running) {
						document.getElementById('ospfd_status').innerHTML = '<span style="color:#0F0;">Running</span>';
					} else {
						document.getElementById('ospfd_status').innerHTML = '<span style="color:#F00;">Stopped</span>';
					}

					if (data.staticd_running) {
						document.getElementById('staticd_status').innerHTML = '<span style="color:#0F0;">Running</span>';
					} else {
						document.getElementById('staticd_status').innerHTML = '<span style="color:#F00;">Stopped</span>';
					}

					if (data.bfdd_running) {
						document.getElementById('bfdd_status').innerHTML = '<span style="color:#0F0;">Running</span>';
					} else {
						document.getElementById('bfdd_status').innerHTML = '<span style="color:#F00;">Stopped</span>';
					}

					if (data.watchfrr_running) {
						document.getElementById('watchfrr_status').innerHTML = '<span style="color:#0F0;">Running</span>';
					} else {
						document.getElementById('watchfrr_status').innerHTML = '<span style="color:#F00;">Stopped</span>';
					}

					// Schedule next refresh
					setTimeout(refresh_frr_status, 5000);
				}
			});
		}
	</script>
	<style>
		input[name="frr_config_dir"]::placeholder { color: #888; }
	</style>
</head>

<body onload="initial();" onunLoad="return unload_body();">
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
								<table width="760px" border="0" cellpadding="5" cellspacing="0" class="FormTitle"
									id="FormTitle">
									<tbody>
										<tr>
											<td bgcolor="#4D595D" valign="top">
												<div>&nbsp;</div>
												<div class="formfonttitle">
													<#menu5_2#> - <#menu5_2_4#>
												</div>
												<div style="margin:10px 0 10px 5px;" class="splitLine"></div>
												<div class="formfontdesc">
													<#FRR_desc#>
												</div>
												<div style="margin:6px 0 10px 5px;">
													<input type="button" class="button_gen" value="Routing Table"
														onclick="routeStatusLink();" style="width:220px;">
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
															<input type="radio" value="1" name="frr_enable"
																class="input" <% nvram_match("frr_enable", "1"
																, "checked" ); %> onclick="showhide('frr_settings',
															1);"><#checkbox_Yes#>
																<input type="radio" value="0" name="frr_enable"
																	class="input" <% nvram_match("frr_enable", "0"
																	, "checked" ); %> onclick="showhide('frr_settings',
																0);"><#checkbox_No#>
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
																	class="input_32_table" name="frr_passwd"
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
																	class="input_32_table" name="frr_enpasswd"
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
																		<span style="color:#FFCC00;">
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
																<span style="color:#888;"> (1-4294967295)</span>
																<div
																	style="color:#9FAFB8;font-size:11px;margin-top:4px;">
																	Supports multiple neighbors. Runtime-discovered
																	peers appear when FRR daemons are running.</div>
															</td>
														</tr>
														<tr>
															<th>
																<#FRR_bgp_neighbors#>
															</th>
															<td>
																<table width="100%" border="1" align="center"
																	cellpadding="4" cellspacing="0"
																	class="FormTable_table" style="margin-top:8px;">
																	<thead>
																		<tr>
																			<td colspan="5">
																				<#FRR_bgp_neighbor_list#>
																			</td>
																		</tr>
																	</thead>
																	<tr>
																		<th width="5%">
																			<#list_add_delete#>
																		</th>
																		<th width="25%">
																			<#FRR_neighbor_ip#>
																		</th>
																		<th width="15%">
																			<#FRR_neighbor_as#>
																		</th>
																		<th width="35%">Description</th>
																		<th width="20%">Status</th>
																	</tr>
																	<tbody id="bgp_neighbor_table"></tbody>
																</table>
																<div style="margin-top:8px;">
																	<input type="text" maxlength="15"
																		class="input_15_table"
																		name="frr_bgp_neighbor_ip_x"
																		placeholder="192.168.0.1"
																		onKeyPress="return validator.isIPAddr(this,event);">
																	<input type="text" maxlength="10"
																		class="input_12_table"
																		name="frr_bgp_neighbor_as_x" placeholder="65001"
																		onKeyPress="return validator.isNumber(this,event);">
																	<input type="text" maxlength="63"
																		class="input_20_table"
																		name="frr_bgp_neighbor_desc_x"
																		placeholder="ROUTER">

																	<input type="button" class="add_btn"
																		onClick="add_bgp_neighbor();" value="">
																</div>
																<div style="margin-top:8px;">
																	<span style="color:#888;">BGP Networks (CIDR,
																		space/newline separated, e.g.
																		192.168.0.0/24)</span><br>
																	<textarea name="frr_bgp_networks"
																		class="textarea_ssh_table"
																		style="width:98%;height:56px;"
																		autocomplete="off" autocorrect="off"
																				autocapitalize="off"></textarea>
																</div>
															</td>
														</tr>
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
																<span style="color:#888;">
																	<#FRR_ospf_networks_hint#>
																</span>
																<div
																	style="color:#9FAFB8;font-size:11px;margin-top:4px;">
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
																		<div
																			style="color:#9FAFB8;font-size:11px;margin-top:4px;">
																			BFD is critical for fast failure detection
																			with dynamic routing peers.</div>
																		<div style="margin-top:8px;">
																			Peer: <input type="text" maxlength="15"
																				class="input_15_table"
																				name="frr_bfd_peer_x"
																				value="" placeholder="192.168.0.2"
																			onKeyPress="return
																			validator.isIPAddr(this,event);">
																			TX(ms): <input type="text" maxlength="5"
																				class="input_6_table" name="frr_bfd_tx_x"
																				value=""
																			onKeyPress="return
																			validator.isNumber(this,event);">
																			RX(ms): <input type="text" maxlength="5"
																				class="input_6_table" name="frr_bfd_rx_x"
																				value=""
																			onKeyPress="return
																			validator.isNumber(this,event);">
																			<input type="button" class="add_btn" onclick="add_bfd_peer();" value="">
																		</div>
																		<table class="FormTable_table" width="100%"><thead><tr><th></th><th>Peer</th><th>TX(ms)</th><th>RX(ms)</th><th>Status</th></tr></thead><tbody id="bfd_peer_table"></tbody></table>
															</td>
														</tr>
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
																<span style="display:inline-block;min-width:125px;color:#FFFFFF;">Zebra: <span id="zebra_status"><#Status_Checking#></span></span>
																<span style="display:inline-block;min-width:150px;color:#FFFFFF;">BGP: <span id="bgpd_status"><#Status_Checking#></span></span>
																<span style="display:inline-block;min-width:150px;color:#FFFFFF;">OSPF: <span id="ospfd_status"><#Status_Checking#></span></span><br>
																<span style="display:inline-block;min-width:125px;color:#FFFFFF;">Static: <span id="staticd_status"><#Status_Checking#></span></span>
																<span style="display:inline-block;min-width:150px;color:#FFFFFF;">BFD: <span id="bfdd_status"><#Status_Checking#></span></span>
																<span style="display:inline-block;min-width:150px;color:#FFFFFF;">Watchfrr: <span id="watchfrr_status"><#Status_Checking#></span></span>
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
																		<span style="color:#888;">
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
																<span style="color:#888;">
																	<#FRR_custom_config_hint#>
																</span>
																<div
																	style="color:#9FAFB8;font-size:11px;margin-top:4px;">
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