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
		var frr_bgp_neighbor_array = '<% get_frr_bgp_neighbor_list(); %>';
		var frr_bgp_neighbor_as_array = '<% get_frr_bgp_neighbor_as_list(); %>';
		var frr_bgp_neighbor_desc_array = '<% get_frr_bgp_neighbor_desc_list(); %>';
		var frr_bgp_neighbor_src_array = '<% get_frr_bgp_neighbor_src_list(); %>';
		var frr_bgp_neighbor_status_map = <% get_frr_bgp_neighbor_status_map(); %>;
		var frr_bfd_config = <% get_frr_bfd_config(); %>;
		var frrDefaultConfigDir = '/jffs/configs/frr';

		function bgp_status_badge(status) {
			var s = (status || 'Configured').toString();
			var l = s.toLowerCase();
			var color = '#FFCC66';

			if (l == 'established')
				color = '#7CFC7C';
			else if (l == 'active' || l == 'connect')
				color = '#6ED0FF';
			else if (l == 'idle')
				color = '#FF9A9A';

			return '<span style="display:inline-block;padding:1px 7px;border-radius:9px;'
				+ 'background:' + color + ';color:#1b1b1b;font-size:11px;font-weight:600;">'
				+ s + '</span>';
		}

		function initial() {
			show_menu();
			normalize_frr_config_dir();

			// Show/hide protocol sections based on enable status
			showhide("frr_settings", (document.form.frr_enable.value == "1"));

			// Load BGP neighbor table
			show_bgp_neighbor_list();
			apply_bfd_config();

			// Start status refresh (will show stopped if FRR disabled)
			setTimeout(refresh_frr_status, 1000);
		}

		function apply_bfd_config() {
			if (!document.form || !frr_bfd_config)
				return;

			if (document.form.frr_bfd_peer && document.form.frr_bfd_peer.value == '' && frr_bfd_config.peer)
				document.form.frr_bfd_peer.value = frr_bfd_config.peer;

			if (document.form.frr_bfd_tx && document.form.frr_bfd_tx.value == '' && frr_bfd_config.tx)
				document.form.frr_bfd_tx.value = frr_bfd_config.tx;

			if (document.form.frr_bfd_rx && document.form.frr_bfd_rx.value == '' && frr_bfd_config.rx)
				document.form.frr_bfd_rx.value = frr_bfd_config.rx;
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
			// Restore default before submit if the field was left empty
			var cfgField = document.form.frr_config_dir;
			if (cfgField && cfgField.value == '')
				cfgField.value = frrDefaultConfigDir;

			if (!validate_frr_config()) {
				return false;
			}

			// Build BGP neighbor lists
			var neighbor_list = "";
			var neighbor_as_list = "";
			var neighbor_desc_list = "";
			var table = document.getElementById('bgp_neighbor_table');
			var rule_num = table ? table.rows.length : 0;

			for (var i = 0; i < rule_num; i++) {
				// Skip "no rules" message row (has only 1 cell with colspan)
				if (!table.rows[i].cells || table.rows[i].cells.length < 2) continue;

				if (neighbor_list != "") {
					neighbor_list += ">";
					neighbor_as_list += ">";
					neighbor_desc_list += ">";
				}
				neighbor_list += table.rows[i].cells[1].textContent;
				neighbor_as_list += table.rows[i].cells[2].textContent;
				neighbor_desc_list += table.rows[i].cells[3].textContent;
			}

			document.form.frr_bgp_neighbor.value = neighbor_list;
			document.form.frr_bgp_neighbor_as.value = neighbor_as_list;
			document.form.frr_bgp_neighbor_desc.value = neighbor_desc_list;
			document.form.frr_bgp_neighbor_src.value = "";

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
				var cidr_re = /^(\d{1,3}\.){3}\d{1,3}\/(3[0-2]|[12]?\d)$/;
				if (as_num == "" || as_num == "0") {
					alert("Please enter a valid BGP AS number (1-4294967295)");
					document.form.frr_bgp_as.focus();
					return false;
				}
				if (parseInt(as_num) < 1 || parseInt(as_num) > 4294967295) {
					alert("BGP AS number must be between 1 and 4294967295");
					document.form.frr_bgp_as.focus();
					return false;
				}
				if (bgp_networks != "") {
					var nets = bgp_networks.split(/\s+/);
					for (var n = 0; n < nets.length; n++) {
						if (nets[n] == "")
							continue;
						if (!cidr_re.test(nets[n])) {
							alert("BGP networks must be in CIDR format (example: 192.168.0.0/24)");
							document.form.frr_bgp_networks.focus();
							return false;
						}
					}
				}
			}

			if (document.form.frr_bfd_enable.value == "1") {
				if (document.form.frr_bfd_peer.value != "" && !validator.validIPForm(document.form.frr_bfd_peer, 0))
					return false;

				if (document.form.frr_bfd_tx.value != "" && parseInt(document.form.frr_bfd_tx.value, 10) <= 0) {
					alert("BFD transmit interval must be a positive number");
					document.form.frr_bfd_tx.focus();
					return false;
				}

				if (document.form.frr_bfd_rx.value != "" && parseInt(document.form.frr_bfd_rx.value, 10) <= 0) {
					alert("BFD receive interval must be a positive number");
					document.form.frr_bfd_rx.focus();
					return false;
				}
			}

			return true;
		}

		function show_bgp_neighbor_list() {
			var bgp_neighbors = frr_bgp_neighbor_array.split('>');
			var bgp_neighbor_as = frr_bgp_neighbor_as_array.split('>');
			var bgp_neighbor_desc = frr_bgp_neighbor_desc_array.split('>');
			var status_map = frr_bgp_neighbor_status_map || {};
			var code = "";

			if (bgp_neighbors.length == 0 || bgp_neighbors[0] == "") {
				code = '<tr><td colspan="5" style="text-align:center;color:#FFCC00;"><#IPConnection_VSList_Norule#></td></tr>';
			} else {
				for (var i = 0; i < bgp_neighbors.length; i++) {
					if (bgp_neighbors[i] != "") {
						var n_ip = bgp_neighbors[i];
						var n_status = status_map[n_ip] || 'Configured';
						code += '<tr>';
						code += '<td width="5%"><input type="button" class="remove_btn" onclick="del_bgp_neighbor(this);" value=""/></td>';
						code += '<td width="25%">' + n_ip + '</td>';
						code += '<td width="15%">' + (bgp_neighbor_as[i] || '') + '</td>';
						code += '<td width="35%">' + (bgp_neighbor_desc[i] || '') + '</td>';
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
			if (neighbor_as == "" || parseInt(neighbor_as) < 1 || parseInt(neighbor_as) > 4294967295) {
				alert("Please enter a valid AS number (1-4294967295)");
				document.form.frr_bgp_neighbor_as_x.focus();
				return false;
			}

			if (neighbor_desc.indexOf(">") != -1) {
				alert("Description cannot contain '>' character");
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
			row_code += '<td width="25%">' + neighbor_ip + '</td>';
			row_code += '<td width="15%">' + neighbor_as + '</td>';
			row_code += '<td width="35%">' + neighbor_desc + '</td>';
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

		function refresh_frr_status() {
			$.ajax({
				url: '/ajax_frr_status.asp',
				dataType: 'json',
				error: function (xhr) {
					setTimeout(refresh_frr_status, 5000);
				},
				success: function (data) {
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
		<input type="hidden" name="frr_bgp_neighbor" value="">
		<input type="hidden" name="frr_bgp_neighbor_as" value="">
		<input type="hidden" name="frr_bgp_neighbor_desc" value="">
		<input type="hidden" name="frr_bgp_neighbor_src" value="">
		<input type="hidden" name="frr_force_regen" value="0">

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
																		value="<% nvram_get("frr_passwd"); %>"
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
																		value="<% nvram_get("frr_enpasswd"); %>"
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
																	name="frr_bgp_as" value="<% nvram_get("
																	frr_bgp_as"); %>" onKeyPress="return
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
																		autocapitalize="off"><% nvram_get("frr_bgp_networks"); %></textarea>
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
																	name="frr_ospf_area" value="<% nvram_get("frr_ospf_area"); %>"
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
																	autocapitalize="off"><% nvram_get("frr_ospf_networks"); %></textarea>
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
																				name="frr_bfd_peer"
																				value="<% nvram_get("frr_bfd_peer");
																				%>" placeholder="192.168.0.2"
																			onKeyPress="return
																			validator.isIPAddr(this,event);">
																			TX(ms): <input type="text" maxlength="5"
																				class="input_6_table" name="frr_bfd_tx"
																				value="<% nvram_get("frr_bfd_tx"); %>"
																			onKeyPress="return
																			validator.isNumber(this,event);">
																			RX(ms): <input type="text" maxlength="5"
																				class="input_6_table" name="frr_bfd_rx"
																				value="<% nvram_get("frr_bfd_rx"); %>"
																			onKeyPress="return
																			validator.isNumber(this,event);">
																		</div>
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
																<input type="radio" value="1" name="frr_force_regen"
																	class="input">
																<#checkbox_Yes#>
																	<input type="radio" value="0" name="frr_force_regen"
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