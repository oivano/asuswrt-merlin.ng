<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<html xmlns:v>
<head>
<meta http-equiv="X-UA-Compatible" content="IE=Edge"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">
<title><#Web_Title#> - OpenConnect VPN Client</title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<link rel="stylesheet" type="text/css" href="usp_style.css">
<script type="text/javascript" src="/state.js"></script>
<script type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" src="/general.js"></script>
<script type="text/javascript" src="/help.js"></script>
<script type="text/javascript" src="/js/jquery.js"></script>
<script type="text/javascript" src="/validator.js"></script>
<script type="text/javascript" src="/switcherplugin/jquery.iphone-switch.js"></script>
<script language="JavaScript" type="text/javascript" src="/client_function.js"></script>
<script language="JavaScript" type="text/javascript" src="/js/httpApi.js"></script>

<style>
.FormTable th {
	width: 20%;
}
.contentM_qis {
	position: fixed;
	-webkit-border-radius: 5px;
	-moz-border-radius: 5px;
	border-radius:10px;
	z-index: 200;
	background-color:#2B373B;
	margin-left: 20%;
	margin-top: 10px;
	width: 740px;
	box-shadow: 3px 3px 10px #000;
	display: none;
}
</style>

<script>
var openconnect_client_unit = '<% nvram_get("openconnect_client_unit"); %>';
openconnect_client_unit = (openconnect_client_unit == "" ? "1" : openconnect_client_unit);

var client_state = 0;
switch (openconnect_client_unit) {
	case "1":
		client_state = (<% sysinfo("pid.openconnect1"); %> > 0 ? 2 : 0);
		break;
	case "2":
		client_state = (<% sysinfo("pid.openconnect2"); %> > 0 ? 2 : 0);
		break;
	default:
		client_state = 0;
		break;
}

var protocol_list = [
	["anyconnect", "Cisco AnyConnect"],
	["nc", "Juniper Network Connect"],
	["pulse", "Pulse Secure"],
	["gp", "Palo Alto GlobalProtect"],
	["f5", "F5 Big-IP"],
	["fortinet", "Fortinet"]
];

function initial(){
	show_menu();
	
	if(vpnc_support || ipsec_cli_support) {
		var vpn_client_array = {"OpenVPN" : ["OpenVPN", "Advanced_OpenVPNClient_Content.asp"], "IPSec" : ["IPSec", "Advanced_VPNClient_Content.asp"], "OpenConnect" : ["OpenConnect", "Advanced_OpenConnect_Content.asp"]};
		$('#divSwitchMenu').html(gen_switch_menu(vpn_client_array, "OpenConnect"));
		document.getElementById("divSwitchMenu").style.display = "";
	}
	
	load_openconnect_config();
	
	// Initialize protocol dropdown
	add_protocol_options();
	
	// Initialize service state switch
	$('#radio_openconnect_enable').iphoneSwitch((client_state > 0),
		function() {
			document.form.action_script.value = "start_openconnect_client" + openconnect_client_unit;
			document.form.action_wait.value = 10;
			if (applyRule(1) == false) {
				$('#iphone_switch').animate({backgroundPosition: -37}, "slow", function() {});
				return false;
			} else {
				parent.showLoading();
				return true;
			}
		},
		function() {
			document.form.action_script.value = "stop_openconnect_client" + openconnect_client_unit;
			document.form.action_wait.value = 10;
			if (applyRule(1)) {
				parent.showLoading();
				return true;
			} else
				return false;
		},
		{
			switch_on_container_path: '/switcherplugin/iphone_switch_container_off.png'
		}
	);
}

function add_protocol_options(){
	var obj = document.getElementById("openconnect_client_protocol");
	obj.options.length = 0;
	for(var i = 0; i < protocol_list.length; i++){
		obj.options[i] = new Option(protocol_list[i][1], protocol_list[i][0]);
	}
}

function load_openconnect_config(){
	var unit = parseInt(openconnect_client_unit);
	
	// Load configuration from NVRAM
	document.form.openconnect_client_enable.value = '<% nvram_get("openconnect_client' + unit + '_enable"); %>';
	document.form.openconnect_client_server.value = '<% nvram_get("openconnect_client' + unit + '_server"); %>';
	document.form.openconnect_client_port.value = '<% nvram_get("openconnect_client' + unit + '_port"); %>';
	document.form.openconnect_client_protocol.value = '<% nvram_get("openconnect_client' + unit + '_protocol"); %>';
	document.form.openconnect_client_username.value = '<% nvram_get("openconnect_client' + unit + '_username"); %>';
	document.form.openconnect_client_password.value = '<% nvram_get("openconnect_client' + unit + '_password"); %>';
	document.form.openconnect_client_authgroup.value = '<% nvram_get("openconnect_client' + unit + '_authgroup"); %>';
	document.form.openconnect_client_interface.value = '<% nvram_get("openconnect_client' + unit + '_interface"); %>';
	document.form.openconnect_client_disable_ipv6.value = '<% nvram_get("openconnect_client' + unit + '_disable_ipv6"); %>';
	document.form.openconnect_client_reconnect_timeout.value = '<% nvram_get("openconnect_client' + unit + '_reconnect_timeout"); %>';
	document.form.openconnect_client_background.value = '<% nvram_get("openconnect_client' + unit + '_background"); %>';
	
	// Load certificates
	document.getElementById("openconnect_client_ca_textarea").value = decodeURIComponent('<% nvram_char_to_ascii("", "openconnect_client' + unit + '_ca"); %>').replace(/&#10/g, "\n").replace(/&#13/g, "\r");
	document.getElementById("openconnect_client_cert_textarea").value = decodeURIComponent('<% nvram_char_to_ascii("", "openconnect_client' + unit + '_cert"); %>').replace(/&#10/g, "\n").replace(/&#13/g, "\r");
	document.getElementById("openconnect_client_key_textarea").value = decodeURIComponent('<% nvram_char_to_ascii("", "openconnect_client' + unit + '_key"); %>').replace(/&#10/g, "\n").replace(/&#13/g, "\r");
	
	// Set automatic start at boot time
	var openconnect_clientx_eas = '<% nvram_get("openconnect_clientx_eas"); %>';
	var autostart = (openconnect_clientx_eas.indexOf('' + unit) >= 0) ? "1" : "0";
	setRadioValue(document.form.openconnect_client_x_eas, autostart);
	
	update_visibility();
}

function update_visibility(){
	var protocol = document.form.openconnect_client_protocol.value;
	
	// Some protocols may not need certain fields - customize visibility based on protocol
	// For now, show all fields for all protocols
}

function switch_openconnect_unit(unit){
	if(unit < 1 || unit > 2) return;
	
	openconnect_client_unit = unit.toString();
	document.form.openconnect_client_unit.value = openconnect_client_unit;
	
	// Save current config before switching
	applyRule(0);
}

function validate_form(){
	if(document.form.openconnect_client_server.value == ""){
		alert("Please enter a VPN server address!");
		document.form.openconnect_client_server.focus();
		return false;
	}
	
	if(!validator.validIPForm(document.form.openconnect_client_server, 0) && 
	   validator.domainName(document.form.openconnect_client_server) != ""){
		alert("Invalid server address format!");
		document.form.openconnect_client_server.focus();
		return false;
	}
	
	if(document.form.openconnect_client_port.value != ""){
		if(!validator.range(document.form.openconnect_client_port, 1, 65535)){
			alert("Port must be between 1 and 65535!");
			document.form.openconnect_client_port.focus();
			return false;
		}
	}
	
	if(document.form.openconnect_client_reconnect_timeout.value != ""){
		if(!validator.range(document.form.openconnect_client_reconnect_timeout, 0, 86400)){
			alert("Reconnect timeout must be between 0 and 86400 seconds!");
			document.form.openconnect_client_reconnect_timeout.focus();
			return false;
		}
	}
	
	return true;
}

function applyRule(manual_switch){
	if(!validate_form()) return false;
	
	if (manual_switch == 0) {
		showLoading();
	}
	
	var unit = parseInt(openconnect_client_unit);
	
	// Update automatic start at boot time setting
	var tmp_value = "";
	for (var i = 1; i <= 2; i++) {
		if (i == unit) {
			if (getRadioValue(document.form.openconnect_client_x_eas) == 1)
				tmp_value += "" + i + ",";
		} else {
			if (document.form.openconnect_clientx_eas.value.indexOf('' + (i)) >= 0)
				tmp_value += "" + i + ",";
		}
	}
	document.form.openconnect_clientx_eas.value = tmp_value;
	
	// Update enable/disable based on button state
	document.form["openconnect_client" + unit + "_enable"].disabled = false;
	document.form["openconnect_client" + unit + "_enable"].value = document.form.openconnect_client_enable.value;
	
	// Update all settings
	document.form["openconnect_client" + unit + "_server"].disabled = false;
	document.form["openconnect_client" + unit + "_server"].value = document.form.openconnect_client_server.value;
	
	document.form["openconnect_client" + unit + "_port"].disabled = false;
	document.form["openconnect_client" + unit + "_port"].value = document.form.openconnect_client_port.value;
	
	document.form["openconnect_client" + unit + "_protocol"].disabled = false;
	document.form["openconnect_client" + unit + "_protocol"].value = document.form.openconnect_client_protocol.value;
	
	document.form["openconnect_client" + unit + "_username"].disabled = false;
	document.form["openconnect_client" + unit + "_username"].value = document.form.openconnect_client_username.value;
	
	document.form["openconnect_client" + unit + "_password"].disabled = false;
	document.form["openconnect_client" + unit + "_password"].value = document.form.openconnect_client_password.value;
	
	document.form["openconnect_client" + unit + "_authgroup"].disabled = false;
	document.form["openconnect_client" + unit + "_authgroup"].value = document.form.openconnect_client_authgroup.value;
	
	document.form["openconnect_client" + unit + "_interface"].disabled = false;
	document.form["openconnect_client" + unit + "_interface"].value = document.form.openconnect_client_interface.value;
	
	document.form["openconnect_client" + unit + "_disable_ipv6"].disabled = false;
	document.form["openconnect_client" + unit + "_disable_ipv6"].value = document.form.openconnect_client_disable_ipv6.value;
	
	document.form["openconnect_client" + unit + "_reconnect_timeout"].disabled = false;
	document.form["openconnect_client" + unit + "_reconnect_timeout"].value = document.form.openconnect_client_reconnect_timeout.value;
	
	document.form["openconnect_client" + unit + "_background"].disabled = false;
	document.form["openconnect_client" + unit + "_background"].value = document.form.openconnect_client_background.value;
	
	// Update certificates
	document.form["openconnect_client" + unit + "_ca"].disabled = false;
	document.form["openconnect_client" + unit + "_ca"].value = document.getElementById("openconnect_client_ca_textarea").value;
	
	document.form["openconnect_client" + unit + "_cert"].disabled = false;
	document.form["openconnect_client" + unit + "_cert"].value = document.getElementById("openconnect_client_cert_textarea").value;
	
	document.form["openconnect_client" + unit + "_key"].disabled = false;
	document.form["openconnect_client" + unit + "_key"].value = document.getElementById("openconnect_client_key_textarea").value;
	
	document.form.submit();
}

function cal_panel_block(){
	var blockmarginLeft;
	if (window.innerWidth)
		winWidth = window.innerWidth;
	else if ((document.body) && (document.body.clientWidth))
		winWidth = document.body.clientWidth;
		
	if (document.documentElement  && document.documentElement.clientHeight && document.documentElement.clientWidth){
		winWidth = document.documentElement.clientWidth;
	}

	if(winWidth >1050){	
		winPadding = (winWidth-1050)/2;	
		winWidth = 1105;
		blockmarginLeft= (winWidth*0.15)+winPadding;
	}
	else if(winWidth <=1050){
		blockmarginLeft= (winWidth)*0.15+document.body.scrollLeft;	

	}

	document.getElementById("cert_panel").style.marginLeft = blockmarginLeft+"px";
}

function show_cert_panel(){
	cal_panel_block();
	$("#cert_panel").fadeIn(300);
}

function hide_cert_panel(){
	$("#cert_panel").fadeOut(300);
}

function save_cert_panel(){
	// Certificate values are already in the textareas, just close the panel
	$("#cert_panel").fadeOut(300);
}
</script>
</head>

<body onload="initial();" onunLoad="return unload_body();" class="bg">

<!-- Certificate/Key Panel -->
<div id="cert_panel" class="contentM_qis" style="box-shadow: 3px 3px 10px #000;">
	<table class="QISform_wireless" border="0" align="center" cellpadding="5" cellspacing="0">
		<tr>
			<td>
				<div class="description_down">Keys and Certificates</div>
			</td>
		</tr>
		<tr>
			<td>
				<div style="margin-left:30px; margin-top:10px;">
					<p>OpenConnect VPN Client certificates and keys. Paste the PEM-encoded certificates below.</p>
					<p>Limit: 8000 characters per field</p>
				</div>
				<div style="margin:5px;width: 730px; height: 2px;" class="splitLine"></div>
			</td>
		</tr>
		<tr>
			<td valign="top">
				<table width="700px" border="0" cellpadding="4" cellspacing="0">
					<tbody>
						<tr>
							<td valign="top">
								<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable">
									<tr>
										<th>CA Certificate<br><br><i>(Optional)</i></th>
										<td>
											<textarea rows="8" class="textarea_ssh_table" spellcheck="false" id="openconnect_client_ca_textarea" cols="65" maxlength="8000"></textarea>
										</td>
									</tr>
									<tr>
										<th>Client Certificate<br><br><i>(Optional)</i></th>
										<td>
											<textarea rows="8" class="textarea_ssh_table" spellcheck="false" id="openconnect_client_cert_textarea" cols="65" maxlength="8000"></textarea>
										</td>
									</tr>
									<tr>
										<th>Client Private Key<br><br><i>(Optional)</i></th>
										<td>
											<textarea rows="8" class="textarea_ssh_table" spellcheck="false" id="openconnect_client_key_textarea" cols="65" maxlength="8000"></textarea>
										</td>
									</tr>
								</table>
							</td>
						</tr>
					</tbody>
				</table>
				<div style="margin-top:5px;width:100%;text-align:center;">
					<input class="button_gen" type="button" onclick="hide_cert_panel();" value="<#CTL_Cancel#>">
					<input class="button_gen" type="button" onclick="save_cert_panel();" value="<#CTL_ok#>">
				</div>
			</td>
		</tr>
	</table>
</div>

<div id="TopBanner"></div>
<div id="Loading" class="popup_bg"></div>

<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>

<form method="post" name="form" id="ruleForm" action="/start_apply.htm" target="hidden_frame">
<input type="hidden" name="productid" value="<% nvram_get("productid"); %>">
<input type="hidden" name="current_page" value="Advanced_OpenConnect_Content.asp">
<input type="hidden" name="next_page" value="Advanced_OpenConnect_Content.asp">
<input type="hidden" name="modified" value="0">
<input type="hidden" name="action_mode" value="apply">
<input type="hidden" name="action_script" value="restart_openconnect">
<input type="hidden" name="action_wait" value="5">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>">
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">
<input type="hidden" name="openconnect_clientx_eas" value="<% nvram_get("openconnect_clientx_eas"); %>">
<input type="hidden" name="openconnect_client_unit" value="">
<input type="hidden" name="openconnect_client_enable" value="">

<!-- Hidden inputs for both units -->
<input type="hidden" name="openconnect_client1_enable" value="<% nvram_get("openconnect_client1_enable"); %>" disabled>
<input type="hidden" name="openconnect_client1_server" value="<% nvram_get("openconnect_client1_server"); %>" disabled>
<input type="hidden" name="openconnect_client1_port" value="<% nvram_get("openconnect_client1_port"); %>" disabled>
<input type="hidden" name="openconnect_client1_protocol" value="<% nvram_get("openconnect_client1_protocol"); %>" disabled>
<input type="hidden" name="openconnect_client1_username" value="<% nvram_get("openconnect_client1_username"); %>" disabled>
<input type="hidden" name="openconnect_client1_password" value="<% nvram_get("openconnect_client1_password"); %>" disabled>
<input type="hidden" name="openconnect_client1_authgroup" value="<% nvram_get("openconnect_client1_authgroup"); %>" disabled>
<input type="hidden" name="openconnect_client1_interface" value="<% nvram_get("openconnect_client1_interface"); %>" disabled>
<input type="hidden" name="openconnect_client1_disable_ipv6" value="<% nvram_get("openconnect_client1_disable_ipv6"); %>" disabled>
<input type="hidden" name="openconnect_client1_reconnect_timeout" value="<% nvram_get("openconnect_client1_reconnect_timeout"); %>" disabled>
<input type="hidden" name="openconnect_client1_background" value="<% nvram_get("openconnect_client1_background"); %>" disabled>
<input type="hidden" name="openconnect_client1_ca" value="" disabled>
<input type="hidden" name="openconnect_client1_cert" value="" disabled>
<input type="hidden" name="openconnect_client1_key" value="" disabled>

<input type="hidden" name="openconnect_client2_enable" value="<% nvram_get("openconnect_client2_enable"); %>" disabled>
<input type="hidden" name="openconnect_client2_server" value="<% nvram_get("openconnect_client2_server"); %>" disabled>
<input type="hidden" name="openconnect_client2_port" value="<% nvram_get("openconnect_client2_port"); %>" disabled>
<input type="hidden" name="openconnect_client2_protocol" value="<% nvram_get("openconnect_client2_protocol"); %>" disabled>
<input type="hidden" name="openconnect_client2_username" value="<% nvram_get("openconnect_client2_username"); %>" disabled>
<input type="hidden" name="openconnect_client2_password" value="<% nvram_get("openconnect_client2_password"); %>" disabled>
<input type="hidden" name="openconnect_client2_authgroup" value="<% nvram_get("openconnect_client2_authgroup"); %>" disabled>
<input type="hidden" name="openconnect_client2_interface" value="<% nvram_get("openconnect_client2_interface"); %>" disabled>
<input type="hidden" name="openconnect_client2_disable_ipv6" value="<% nvram_get("openconnect_client2_disable_ipv6"); %>" disabled>
<input type="hidden" name="openconnect_client2_reconnect_timeout" value="<% nvram_get("openconnect_client2_reconnect_timeout"); %>" disabled>
<input type="hidden" name="openconnect_client2_background" value="<% nvram_get("openconnect_client2_background"); %>" disabled>
<input type="hidden" name="openconnect_client2_ca" value="" disabled>
<input type="hidden" name="openconnect_client2_cert" value="" disabled>
<input type="hidden" name="openconnect_client2_key" value="" disabled>

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
          <td valign="top">
            <table width="760px" border="0" cellpadding="4" cellspacing="0" class="FormTitle" id="FormTitle">
              <tbody>
                <tr bgcolor="#4D595D">
                  <td valign="top">
                    <div>&nbsp;</div>
                    <div class="formfonttitle">OpenConnect Client Settings</div>
                    <div id="divSwitchMenu" style="margin-top:-40px;float:right;"></div>
                    <div style="margin:10px 0 10px 5px;" class="splitLine"></div>
                    
                    <div class="formfontdesc">
                      OpenConnect is a VPN client supporting multiple enterprise VPN protocols including Cisco AnyConnect, 
                      Juniper Network Connect, Pulse Secure, Palo Alto GlobalProtect, F5 Big-IP, and Fortinet.
                    </div>
                    
                    <!-- Unit Selection -->
                    <table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable">
                      <thead>
                        <tr>
                          <td colspan="2">Client Selection</td>
                        </tr>
                      </thead>
                      <tr>
                        <th>Select Client</th>
                        <td>
                          <select name="client_unit_select" class="input_option" onchange="switch_openconnect_unit(this.value);">
                            <option value="1" selected>Client 1</option>
                            <option value="2">Client 2</option>
                          </select>
                        </td>
                      </tr>
                    </table>
                    
                    <!-- Basic Configuration -->
                    <table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable">
                      <thead>
                        <tr>
                          <td colspan="2">Basic Settings</td>
                        </tr>
                      </thead>
                      
                      <tr>
                        <th>Service state</th>
                        <td>
                          <div class="left" style="width:94px; float:left; cursor:pointer;" id="radio_openconnect_enable"></div>
                        </td>
                      </tr>
                      
                      <tr>
                        <th>Automatic start at boot time</th>
                        <td>
                          <input type="radio" name="openconnect_client_x_eas" class="input" value="1"><#checkbox_Yes#>
                          <input type="radio" name="openconnect_client_x_eas" class="input" value="0" checked><#checkbox_No#>
                        </td>
                      </tr>
                      
                      <tr>
                        <th><a class="hintstyle">VPN Server</a></th>
                        <td>
                          <input type="text" maxlength="255" class="input_32_table" name="openconnect_client_server" value="">
                          <div><span>Enter server hostname or IP address</span></div>
                        </td>
                      </tr>
                      
                      <tr>
                        <th><a class="hintstyle">Port</a></th>
                        <td>
                          <input type="text" maxlength="5" class="input_6_table" name="openconnect_client_port" value="">
                          <div><span>Leave empty for default (443)</span></div>
                        </td>
                      </tr>
                      
                      <tr>
                        <th><a class="hintstyle">Protocol</a></th>
                        <td>
                          <select name="openconnect_client_protocol" id="openconnect_client_protocol" class="input_option" onchange="update_visibility();">
                          </select>
                        </td>
                      </tr>
                      
                      <tr>
                        <th><a class="hintstyle">Username</a></th>
                        <td>
                          <input type="text" maxlength="64" class="input_25_table" name="openconnect_client_username" value="" autocomplete="off" autocorrect="off" autocapitalize="off">
                        </td>
                      </tr>
                      
                      <tr>
                        <th><a class="hintstyle">Password</a></th>
                        <td>
                          <input type="password" maxlength="64" class="input_25_table" name="openconnect_client_password" value="" autocomplete="off">
                        </td>
                      </tr>
                      
                      <tr>
                        <th><a class="hintstyle">Auth Group</a></th>
                        <td>
                          <input type="text" maxlength="64" class="input_25_table" name="openconnect_client_authgroup" value="">
                          <div><span>Group name for authentication (optional)</span></div>
                        </td>
                      </tr>
                    </table>
                    
                    <!-- Advanced Settings -->
                    <table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable">
                      <thead>
                        <tr>
                          <td colspan="2">Advanced Settings</td>
                        </tr>
                      </thead>
                      
                      <tr>
                        <th><a class="hintstyle">Interface Name</a></th>
                        <td>
                          <input type="text" maxlength="15" class="input_15_table" name="openconnect_client_interface" value="">
                          <div><span>Leave empty for auto (tun11/tun12)</span></div>
                        </td>
                      </tr>
                      
                      <tr>
                        <th><a class="hintstyle">Disable IPv6</a></th>
                        <td>
                          <select name="openconnect_client_disable_ipv6" class="input_option">
                            <option value="0">No</option>
                            <option value="1">Yes</option>
                          </select>
                        </td>
                      </tr>
                      
                      <tr>
                        <th><a class="hintstyle">Reconnect Timeout</a></th>
                        <td>
                          <input type="text" maxlength="5" class="input_6_table" name="openconnect_client_reconnect_timeout" value="">
                          <div><span>Seconds (0 = disabled, default: 300)</span></div>
                        </td>
                      </tr>
                      
                      <tr>
                        <th><a class="hintstyle">Run in Background</a></th>
                        <td>
                          <select name="openconnect_client_background" class="input_option">
                            <option value="0">No</option>
                            <option value="1" selected>Yes</option>
                          </select>
                        </td>
                      </tr>
                      
                      <tr>
                        <th><a class="hintstyle">Certificates/Keys</a></th>
                        <td>
                          <input type="button" class="button_gen" value="Edit Certificates" onclick="show_cert_panel();">
                        </td>
                      </tr>
                    </table>
                    
                    <div class="apply_gen">
                      <input name="button" type="button" class="button_gen" onclick="applyRule();" value="<#CTL_apply#>">
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
