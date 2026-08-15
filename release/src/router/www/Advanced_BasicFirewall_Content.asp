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
<title><#Web_Title#> - <#menu5_1_1#></title>
<link rel="stylesheet" type="text/css" href="index_style.css"> 
<link rel="stylesheet" type="text/css" href="form_style.css">
<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script type="text/javascript" language="JavaScript" src="/help.js"></script>
<script type="text/javascript" language="JavaScript" src="/validator.js"></script>
<script type="text/javascript" src="/js/jquery.js"></script>
<script type="text/javascript" src="/js/httpApi.js"></script>
<style>
/* Keep the entry and generated rule tables on the same column grid. */
#ipv4_firewall_div .FormTable_table{
	table-layout: fixed;
}

#ipv4_firewall_div .FormTable_table .input_12_table,
#ipv4_firewall_div .FormTable_table .input_18_table,
#ipv4_firewall_div .FormTable_table .input_option{
	box-sizing: border-box;
	width: 100%;
	max-width: 100%;
	margin-left: 0;
}

/* Keep IPv4 rule action icons visually consistent on this page only. */
#ipv4_firewall_div .ipv4_rule_btn{
	width: 32px;
	height: 32px;
	background-size: 32px 32px;
	display: inline-block;
	vertical-align: middle;
}

/* Match the input row's column split so list rows line up with headers. */
#ipv4_fw_rulelist_table .ipv4_rule_action_cell{
	width: 16%;
	text-align: center;
	vertical-align: middle;
}

/* Improve interface value alignment/readability in generated rule rows. */
#ipv4_fw_rulelist_table .ipv4_rule_iface_cell{
	text-align: left;
	padding-left: 10px;
	font-family: Arial, Helvetica, sans-serif;
	white-space: nowrap;
}
</style>
<script>
var firewall_enable = '<% nvram_get("fw_enable_x"); %>';
var ipv6_fw_enable = '<% nvram_get("ipv6_fw_enable"); %>';
var wItem = new Array(new Array("", "", "TCP"),
	new Array("FTP", "20,21", "TCP"),
	new Array("TELNET", "23", "TCP"),
	new Array("SMTP", "25", "TCP"),
	new Array("DNS", "53", "UDP"),
	new Array("FINGER", "79", "TCP"),
	new Array("HTTP", "80", "TCP"),
	new Array("POP3", "110", "TCP"),
	new Array("SNMP", "161", "UDP"),
	new Array("SNMP TRAP", "162", "UDP"));

var ipv6_fw_rulelist_array = "<% nvram_char_to_ascii("","ipv6_fw_rulelist"); %>";
var ipv4_fw_rulelist_array = "<% nvram_char_to_ascii("","ipv4_fw_rulelist"); %>";
var overlib_str0 = new Array();
var overlib_str1 = new Array();
var overlib_str2 = new Array();
var overlib_str3 = new Array();
var overlib_str0_ipv4 = new Array();
var overlib_str1_ipv4 = new Array();
var overlib_str2_ipv4 = new Array();
var overlib_str3_ipv4 = new Array();

var faq_href = "https://nw-dlcdnet.asus.com/support/forward.html?model=&type=Faq&lang="+ui_lang+"&kw=&num=104";

function initial(){
	show_menu();
	document.getElementById("faq").href=faq_href;
	loadAppOptions();
	showipv4_fw_rulelist();
	showipv6_fw_rulelist();
	change_firewall(firewall_enable);
	change_ipv6_fw(ipv6_fw_enable);
	if(WebDav_support){
		hideAll(1);
	}
}

function change_firewall(value){
	document.getElementById("ipv4_firewall_div").style.display = (value == "1") ? "" : "none";
}

function change_ipv6_fw(value){
	var show = (value == "1") ? "" : "none";
	document.getElementById("ipv6_firewall_rules_div").style.display = show;
	document.getElementById("ipv6_fw_hint").style.display = show;
}

function hideAll(_value){
	/* not allow user to change HTTP/HTTPS port */
	return false;

	document.getElementById("st_webdav_mode_tr").style.display = (_value == 0) ? "none" : "";
	document.getElementById("webdav_http_port_tr").style.display = (_value == 0) ? "none" : "";
	document.getElementById("webdav_https_port_tr").style.display = (_value == 0) ? "none" : "";
	if(_value != 0)
		showPortItem(document.form.st_webdav_mode.value);
}

function showPortItem(_value){
	if(_value == 0){
		document.getElementById("webdav_http_port_tr").style.display = "";
		document.form.webdav_http_port.disabled = false;
		document.getElementById("webdav_https_port_tr").style.display = "none";
		document.form.webdav_https_port.disabled = true;
	}
	else if(_value == 1){
		document.getElementById("webdav_http_port_tr").style.display = "none";
		document.form.webdav_http_port.disabled = true;
		document.getElementById("webdav_https_port_tr").style.display = "";
		document.form.webdav_https_port.disabled = false;
	}
	else{
		document.getElementById("webdav_http_port_tr").style.display = "";
		document.form.webdav_http_port.disabled = false;
		document.getElementById("webdav_https_port_tr").style.display = "";
		document.form.webdav_https_port.disabled = false;
	}
}

function applyRule(){
	inputRCtrl1(document.form.misc_ping_x, 1);
	
	// Collect IPv4 rules
	var rule_num_ipv4 = document.getElementById('ipv4_fw_rulelist_table').rows.length;
	var item_num_ipv4 = document.getElementById('ipv4_fw_rulelist_table').rows[0].cells.length;
	var tmp_value_ipv4 = "";

	for(i=0; i<rule_num_ipv4; i++){
		tmp_value_ipv4 += "<"		
		for(j=0; j<item_num_ipv4-1; j++){		

			if(document.getElementById('ipv4_fw_rulelist_table').rows[i].cells[j].innerHTML.lastIndexOf("...")<0){
				tmp_value_ipv4 += document.getElementById('ipv4_fw_rulelist_table').rows[i].cells[j].innerHTML;
			}else{
				tmp_value_ipv4 += document.getElementById('ipv4_fw_rulelist_table').rows[i].cells[j].title;
			}		

			if(j != item_num_ipv4-2)	
				tmp_value_ipv4 += ">";
		}
	}

	if(tmp_value_ipv4 == "<"+"<#IPConnection_VSList_Norule#>" || tmp_value_ipv4 == "<")
		tmp_value_ipv4 = "";	
	
	document.form.ipv4_fw_rulelist.value = tmp_value_ipv4;
	
	// Collect IPv6 rules
	var rule_num = document.getElementById('ipv6_fw_rulelist_table').rows.length;
	var item_num = document.getElementById('ipv6_fw_rulelist_table').rows[0].cells.length;
	var tmp_value = "";

	for(i=0; i<rule_num; i++){
		tmp_value += "<"		
		for(j=0; j<item_num-1; j++){			

			if(document.getElementById('ipv6_fw_rulelist_table').rows[i].cells[j].innerHTML.lastIndexOf("...")<0){
				tmp_value += document.getElementById('ipv6_fw_rulelist_table').rows[i].cells[j].innerHTML;
			}else{
				tmp_value += document.getElementById('ipv6_fw_rulelist_table').rows[i].cells[j].title;
			}		

			if(j != item_num-2)	
				tmp_value += ">";
		}
	}

	if(tmp_value == "<"+"<#IPConnection_VSList_Norule#>" || tmp_value == "<")
		tmp_value = "";	
	
	document.form.ipv6_fw_rulelist.value = tmp_value;	
	showLoading();
	document.form.submit();	
}

function hideport(flag){
	document.getElementById("accessfromwan_port").style.display = (flag == 1) ? "" : "none";
}

function done_validating(action){
	refreshpage();
}

function loadAppOptions(){
	free_options(document.form.KnownApps);
	add_option(document.form.KnownApps, "<#Select_menu_default#>", 0, 1);
	for(var i = 1; i < wItem.length; i++)
		add_option(document.form.KnownApps, wItem[i][0], i, 0);
}

function addRow(obj, head){
	if(head == 1)
		ipv6_fw_rulelist_array += "%3C";
	else
		ipv6_fw_rulelist_array += "%3E";

	ipv6_fw_rulelist_array += encodeURIComponent(obj.value);
	obj.value = "";
}

function addRow_ipv4(obj, head){
	if(head == 1)
		ipv4_fw_rulelist_array += "%3C";
	else
		ipv4_fw_rulelist_array += "%3E";

	ipv4_fw_rulelist_array += encodeURIComponent(obj.value);
	obj.value = "";
}

function change_wizard(o, id){
	for(var i = 0; i < wItem.length; ++i){
		if(wItem[i][0] != null && o.value == i){
			if(wItem[i][2] == "TCP")
				document.form.ipv6_fw_proto_x_0.options[0].selected = 1;
			else if(wItem[i][2] == "UDP")
				document.form.ipv6_fw_proto_x_0.options[1].selected = 1;
			else if(wItem[i][2] == "BOTH")
				document.form.ipv6_fw_proto_x_0.options[2].selected = 1;
			else if(wItem[i][2] == "OTHER")
				document.form.ipv6_fw_proto_x_0.options[3].selected = 1;

			document.form.ipv6_fw_port_x_0.value = wItem[i][1];
			document.form.ipv6_fw_desc_x_0.value = wItem[i][0]+" Server";				
			break;
		}
	}
}

function change_wizard_ipv4(o, id){
	for(var i = 0; i < wItem.length; ++i){
		if(wItem[i][0] != null && o.value == i){
			if(wItem[i][2] == "TCP")
				document.form.ipv4_fw_proto_x_0.options[0].selected = 1;
			else if(wItem[i][2] == "UDP")
				document.form.ipv4_fw_proto_x_0.options[1].selected = 1;
			else if(wItem[i][2] == "BOTH")
				document.form.ipv4_fw_proto_x_0.options[2].selected = 1;
			else if(wItem[i][2] == "OTHER")
				document.form.ipv4_fw_proto_x_0.options[3].selected = 1;

			document.form.ipv4_fw_port_x_0.value = wItem[i][1];
			document.form.ipv4_fw_desc_x_0.value = wItem[i][0]+" Server";			
			break;
		}
	}
}

function validForm(){
	if(!Block_chars(document.form.ipv6_fw_desc_x_0, ["<" ,">" ,"'" ,"%"])){
			return false;		
	}	

	if(!Block_chars(document.form.ipv6_fw_port_x_0, ["<" ,">"])){ 
			return false;		
	}	

	if(document.form.ipv6_fw_proto_x_0.value=="OTHER"){
		if (!check_multi_range(document.form.ipv6_fw_port_x_0, 1, 255, false))
			return false;
	}

	if(!check_multi_range(document.form.ipv6_fw_port_x_0, 1, 65535, true)){
		return false;
	}

	if(document.form.ipv6_fw_port_x_0.value==""){
		alert("<#JS_fieldblank#>");
		document.form.ipv6_fw_port_x_0.focus();
		document.form.ipv6_fw_port_x_0.select();		
		return false;
	}

	if(!validate_multi_range(document.form.ipv6_fw_port_x_0, 1, 65535)
		|| (document.form.ipv6_fw_lipaddr_x_0.value != "" && !ipv6_valid(document.form.ipv6_fw_lipaddr_x_0, 0))
		|| (document.form.ipv6_fw_ripaddr_x_0.value != "" && !ipv6_valid(document.form.ipv6_fw_ripaddr_x_0, 1))) {
		return false;
	}

	return true;
}

function validForm_ipv4(){
	if(!Block_chars(document.form.ipv4_fw_desc_x_0, ["<" ,">" ,"'" ,"%"])){
			return false;		
	}	

	if(!Block_chars(document.form.ipv4_fw_port_x_0, ["<" ,">"])){ 
			return false;		
	}	

	var iface_val = document.form.ipv4_fw_iface_x_0.value;
	if(iface_val != "" && !/^[a-zA-Z0-9_\-\.\+]+$/.test(iface_val)){
		alert("Interface name contains invalid characters.");
		document.form.ipv4_fw_iface_x_0.focus();
		return false;
	}

	if(document.form.ipv4_fw_proto_x_0.value=="OTHER"){
		if (!check_multi_range_ipv4(document.form.ipv4_fw_port_x_0, 1, 255, false))
			return false;
	}

	if(!check_multi_range_ipv4(document.form.ipv4_fw_port_x_0, 1, 65535, true)){
		return false;
	}

	if(document.form.ipv4_fw_port_x_0.value==""){
		alert("<#JS_fieldblank#>");
		document.form.ipv4_fw_port_x_0.focus();
		document.form.ipv4_fw_port_x_0.select();		
		return false;
	}

	if(!validate_multi_range_ipv4(document.form.ipv4_fw_port_x_0, 1, 65535)
		|| (document.form.ipv4_fw_lipaddr_x_0.value != "" && !ip_valid(document.form.ipv4_fw_lipaddr_x_0, 0))
		|| (document.form.ipv4_fw_ripaddr_x_0.value != "" && !ip_valid(document.form.ipv4_fw_ripaddr_x_0, 1))) {
		return false;
	}

	return true;
}

function addRow_Group(upper){
	if(validForm()){
		if('<% nvram_get("ipv6_fw_enable"); %>' != "1")
			document.form.ipv6_fw_enable[0].checked = true;

		var rule_num = document.getElementById('ipv6_fw_rulelist_table').rows.length;
		var item_num = document.getElementById('ipv6_fw_rulelist_table').rows[0].cells.length;	
		if(rule_num >= upper){
			alert("<#JS_itemlimit1#> " + upper + " <#JS_itemlimit2#>");
			return;
		}	

		addRow(document.form.ipv6_fw_desc_x_0 ,1);
		addRow(document.form.ipv6_fw_ripaddr_x_0, 0);
		addRow(document.form.ipv6_fw_lipaddr_x_0, 0);
		addRow(document.form.ipv6_fw_port_x_0, 0);
		addRow(document.form.ipv6_fw_proto_x_0, 0);
		document.form.ipv6_fw_proto_x_0.value="TCP";
		showipv6_fw_rulelist();
	}
}

function addRow_Group_ipv4(upper){
	if(validForm_ipv4()){
		var rule_num = document.getElementById('ipv4_fw_rulelist_table').rows.length;
		var item_num = document.getElementById('ipv4_fw_rulelist_table').rows[0].cells.length;	
		if(rule_num >= upper){
			alert("<#JS_itemlimit1#> " + upper + " <#JS_itemlimit2#>");
			return;
		}	

		addRow_ipv4(document.form.ipv4_fw_desc_x_0 ,1);
		addRow_ipv4(document.form.ipv4_fw_ripaddr_x_0, 0);
		addRow_ipv4(document.form.ipv4_fw_lipaddr_x_0, 0);
		addRow_ipv4(document.form.ipv4_fw_port_x_0, 0);
		addRow_ipv4(document.form.ipv4_fw_proto_x_0, 0);
		addRow_ipv4(document.form.ipv4_fw_iface_x_0, 0);
		document.form.ipv4_fw_proto_x_0.value="TCP";
		document.form.ipv4_fw_iface_x_0.value="";
		showipv4_fw_rulelist();
	}
}

function validate_single_range(val, min, max) {
	for(j=0; j<val.length; j++){
		if (val.charAt(j)<'0' || val.charAt(j)>'9'){
			alert('<#JS_validrange#> ' + min + ' <#JS_validrange_to#> ' + max);
			return false;
		}
	}
	if(val < min || val > max) {
		alert('<#JS_validrange#> ' + min + ' <#JS_validrange_to#> ' + max);
		return false;
	}else
		return true;
}

function validate_multi_range(val, mini, maxi){
	var rangere=new RegExp("^([0-9]{1,5})\:([0-9]{1,5})$", "gi");
	if(rangere.test(val)){
		if(!validator.eachPort(document.form.ipv6_fw_port_x_0, RegExp.$1, mini, maxi) || !validator.eachPort(document.form.ipv6_fw_port_x_0, RegExp.$2, mini, maxi)){
				return false;								
		}else if(parseInt(RegExp.$1) >= parseInt(RegExp.$2)){
				alert("<#JS_validport#>");	
				return false;												
		}else				
			return true;	
	}else{
		if(!validate_single_range(val, mini, maxi)){	
			return false;											
		}
		
		return true;								
	}	
}

function validate_multi_range_ipv4(val, mini, maxi){
	var rangere=new RegExp("^([0-9]{1,5})\:([0-9]{1,5})$", "gi");
	if(rangere.test(val)){
		if(!validator.eachPort(document.form.ipv4_fw_port_x_0, RegExp.$1, mini, maxi) || !validator.eachPort(document.form.ipv4_fw_port_x_0, RegExp.$2, mini, maxi)){
				return false;						
		}else if(parseInt(RegExp.$1) >= parseInt(RegExp.$2)){
				alert("<#JS_validport#>");	
				return false;										
		}else			
			return true;	
	}else{
		if(!validate_single_range(val, mini, maxi)){	
			return false;									
		}
		
		return true;									
	}	
}

var parse_port="";
function check_multi_range(obj, mini, maxi, allow_range){
	obj.value = document.form.ipv6_fw_port_x_0.value.replace(/[-~]/gi,":");	// "~-" to ":"
	var PortSplit = obj.value.split(",");
	for(i=0;i<PortSplit.length;i++){
		PortSplit[i] = PortSplit[i].replace(/(^\s*)|(\s*$)/g, ""); 		// "\space" to ""
		PortSplit[i] = PortSplit[i].replace(/(^0*)/g, ""); 		// "^0" to ""	
		if(PortSplit[i] == "" ||PortSplit[i] == 0){
			alert("<#JS_ipblank1#>");
			obj.focus();
			obj.select();			
			return false;
		}
		
		if(allow_range)
			res = validate_multi_range(PortSplit[i], mini, maxi);
		else	
			res = validate_single_range(PortSplit[i], mini, maxi);
		
		if(!res){
			obj.focus();
			obj.select();
			return false;
		}						

		if(i ==PortSplit.length -1)
			parse_port = parse_port + PortSplit[i];
		else
			parse_port = parse_port + PortSplit[i] + ",";

	}
	
	document.form.ipv6_fw_port_x_0.value = parse_port;
	parse_port ="";
	return true;	
}

var parse_port_ipv4="";
function check_multi_range_ipv4(obj, mini, maxi, allow_range){
	obj.value = document.form.ipv4_fw_port_x_0.value.replace(/[-~]/gi,":");	// "~-" to ":"
	var PortSplit = obj.value.split(",");
	for(i=0;i<PortSplit.length;i++){
		PortSplit[i] = PortSplit[i].replace(/(^\s*)|(\s*$)/g, ""); 		// "\space" to ""
		PortSplit[i] = PortSplit[i].replace(/(^0*)/g, ""); 		// "^0" to ""	
		if(PortSplit[i] == "" ||PortSplit[i] == 0){
			alert("<#JS_ipblank1#>");
			obj.focus();
			obj.select();			
			return false;
		}
		
		if(allow_range)
			res = validate_multi_range_ipv4(PortSplit[i], mini, maxi);
		else	
			res = validate_single_range(PortSplit[i], mini, maxi);
		
		if(!res){
			obj.focus();
			obj.select();
			return false;
		}						

		if(i ==PortSplit.length -1)
			parse_port_ipv4 = parse_port_ipv4 + PortSplit[i];
		else
			parse_port_ipv4 = parse_port_ipv4 + PortSplit[i] + ",";

	}
	
	document.form.ipv4_fw_port_x_0.value = parse_port_ipv4;
	parse_port_ipv4 ="";
	return true;	
}

function edit_Row(r){ 	
	var i=r.parentNode.parentNode.rowIndex;
	document.form.ipv6_fw_desc_x_0.value = document.getElementById('ipv6_fw_rulelist_table').rows[i].cells[0].innerHTML;
	document.form.ipv6_fw_ripaddr_x_0.value = document.getElementById('ipv6_fw_rulelist_table').rows[i].cells[1].innerHTML; 
	document.form.ipv6_fw_lipaddr_x_0.value = document.getElementById('ipv6_fw_rulelist_table').rows[i].cells[2].innerHTML;
	document.form.ipv6_fw_port_x_0.value = document.getElementById('ipv6_fw_rulelist_table').rows[i].cells[3].innerHTML;
	document.form.ipv6_fw_proto_x_0.value = document.getElementById('ipv6_fw_rulelist_table').rows[i].cells[4].innerHTML;
	del_Row(r);	
}

function edit_Row_ipv4(r){ 	
	var i=r.parentNode.parentNode.rowIndex;
	document.form.ipv4_fw_desc_x_0.value = document.getElementById('ipv4_fw_rulelist_table').rows[i].cells[0].innerHTML;
	document.form.ipv4_fw_ripaddr_x_0.value = document.getElementById('ipv4_fw_rulelist_table').rows[i].cells[1].innerHTML; 
	document.form.ipv4_fw_lipaddr_x_0.value = document.getElementById('ipv4_fw_rulelist_table').rows[i].cells[2].innerHTML;
	document.form.ipv4_fw_port_x_0.value = document.getElementById('ipv4_fw_rulelist_table').rows[i].cells[3].innerHTML;
	document.form.ipv4_fw_proto_x_0.value = document.getElementById('ipv4_fw_rulelist_table').rows[i].cells[4].innerHTML;
	document.form.ipv4_fw_iface_x_0.value = document.getElementById('ipv4_fw_rulelist_table').rows[i].cells[5].innerHTML;
	del_Row_ipv4(r);	
}

function del_Row(r){
  var i=r.parentNode.parentNode.rowIndex;
  document.getElementById('ipv6_fw_rulelist_table').deleteRow(i);

  var ipv6_fw_rulelist_value = "";
	for(k=0; k<document.getElementById('ipv6_fw_rulelist_table').rows.length; k++){
		for(j=0; j<document.getElementById('ipv6_fw_rulelist_table').rows[k].cells.length-1; j++){
			if(j == 0)	
				ipv6_fw_rulelist_value += "<";
			else
				ipv6_fw_rulelist_value += ">";

			if(document.getElementById('ipv6_fw_rulelist_table').rows[k].cells[j].innerHTML.lastIndexOf("...")<0){
				ipv6_fw_rulelist_value += document.getElementById('ipv6_fw_rulelist_table').rows[k].cells[j].innerHTML;
			}else{
				ipv6_fw_rulelist_value += document.getElementById('ipv6_fw_rulelist_table').rows[k].cells[j].title;
			}			
		}
	}

	ipv6_fw_rulelist_array = ipv6_fw_rulelist_value;
	if(ipv6_fw_rulelist_array == "")
		showipv6_fw_rulelist();
}

function del_Row_ipv4(r){
  var i=r.parentNode.parentNode.rowIndex;
  document.getElementById('ipv4_fw_rulelist_table').deleteRow(i);

  var ipv4_fw_rulelist_value = "";
	for(k=0; k<document.getElementById('ipv4_fw_rulelist_table').rows.length; k++){
		for(j=0; j<document.getElementById('ipv4_fw_rulelist_table').rows[k].cells.length-1; j++){
			if(j == 0)	
				ipv4_fw_rulelist_value += "<";
			else
				ipv4_fw_rulelist_value += ">";

			if(document.getElementById('ipv4_fw_rulelist_table').rows[k].cells[j].innerHTML.lastIndexOf("...")<0){
				ipv4_fw_rulelist_value += document.getElementById('ipv4_fw_rulelist_table').rows[k].cells[j].innerHTML;
			}else{
				ipv4_fw_rulelist_value += document.getElementById('ipv4_fw_rulelist_table').rows[k].cells[j].title;
			}			
		}
	}

	ipv4_fw_rulelist_array = ipv4_fw_rulelist_value;
	if(ipv4_fw_rulelist_array == "")
		showipv4_fw_rulelist();
}

function showipv6_fw_rulelist(){
	var ipv6_fw_rulelist_row = decodeURIComponent(ipv6_fw_rulelist_array).split('<');
	var code = "";

	code +='<table width="100%" cellspacing="0" cellpadding="4" align="center" class="list_table" id="ipv6_fw_rulelist_table">';
	if(ipv6_fw_rulelist_row.length == 1)
		code +='<tr><td style="color:#FFCC00;" colspan="6"><#IPConnection_VSList_Norule#></td></tr>';
	else{
		for(var i = 1; i < ipv6_fw_rulelist_row.length; i++){
			overlib_str0[i] ="";
			overlib_str1[i] ="";	
			overlib_str2[i] ="";	
			overlib_str3[i] ="";			
			code +='<tr id="row'+i+'">';
			var ipv6_fw_rulelist_col = ipv6_fw_rulelist_row[i].split('>');
			var wid=[15, 24, 24, 14, 11];
				for(var j = 0; j < ipv6_fw_rulelist_col.length; j++){
						if(j==0){
							if(ipv6_fw_rulelist_col[0].length >10){
								overlib_str0[i] += ipv6_fw_rulelist_col[0];
								ipv6_fw_rulelist_col[0]=ipv6_fw_rulelist_col[0].substring(0, 8)+"...";
								code +='<td width="'+wid[j]+'%" title="'+overlib_str0[i]+'">'+ ipv6_fw_rulelist_col[0] +'</td>';
							}else
								code +='<td width="'+wid[j]+'%">'+ ipv6_fw_rulelist_col[j] +'</td>';
						}else if(j==1){
							if(ipv6_fw_rulelist_col[1].length >22){
								overlib_str1[i] += ipv6_fw_rulelist_col[1];
								ipv6_fw_rulelist_col[1]=ipv6_fw_rulelist_col[1].substring(0, 20)+"...";
								code +='<td width="'+wid[j]+'%" title='+overlib_str1[i]+'>'+ ipv6_fw_rulelist_col[1] +'</td>';
							}else
								code +='<td width="'+wid[j]+'%">'+ ipv6_fw_rulelist_col[j] +'</td>';
						}else if(j==2){
							if(ipv6_fw_rulelist_col[2].length >22){
								overlib_str2[i] += ipv6_fw_rulelist_col[2];
								ipv6_fw_rulelist_col[2]=ipv6_fw_rulelist_col[2].substring(0, 20)+"...";
								code +='<td width="'+wid[j]+'%" title='+overlib_str2[i]+'>'+ ipv6_fw_rulelist_col[2] +'</td>';
							}else
								code +='<td width="'+wid[j]+'%">'+ ipv6_fw_rulelist_col[j] +'</td>';
							}else if(j==3){
								if(ipv6_fw_rulelist_col[3].length >12){
									overlib_str3[i] += ipv6_fw_rulelist_col[3];
									ipv6_fw_rulelist_col[3]=ipv6_fw_rulelist_col[3].substring(0, 10)+"...";
									code +='<td width="'+wid[j]+'%" title='+overlib_str3[i]+'>'+ ipv6_fw_rulelist_col[3] +'</td>';
								}else
									code +='<td width="'+wid[j]+'%">'+ ipv6_fw_rulelist_col[j] +'</td>';
						}else{
							code +='<td width="'+wid[j]+'%">'+ ipv6_fw_rulelist_col[j] +'</td>';
						}

				}
				code +='<td width="12%"><!--input class="edit_btn" onclick="edit_Row(this);" value=""/-->';
				code +='<input class="remove_btn" onclick="del_Row(this);" value=""/></td></tr>';
		}
	}
	code +='</table>';
	document.getElementById("ipv6_fw_rulelist_Block").innerHTML = code;	     
}

function showipv4_fw_rulelist(){
	var ipv4_fw_rulelist_row = decodeURIComponent(ipv4_fw_rulelist_array).split('<');
	var code = "";

	code +='<table width="100%" cellspacing="0" cellpadding="4" align="center" class="list_table" id="ipv4_fw_rulelist_table" style="table-layout:fixed;">';
	if(ipv4_fw_rulelist_row.length == 1)
		code +='<tr><td style="color:#FFCC00;" colspan="7"><#IPConnection_VSList_Norule#></td></tr>';
	else{
		for(var i = 1; i < ipv4_fw_rulelist_row.length; i++){
			overlib_str0_ipv4[i] ="";
			overlib_str1_ipv4[i] ="";	
			overlib_str2_ipv4[i] ="";	
			overlib_str3_ipv4[i] ="";			
			code +='<tr id="row'+i+'">';
			var ipv4_fw_rulelist_col = ipv4_fw_rulelist_row[i].split('>');
			var wid=[12, 18, 18, 12, 10, 14];
				for(var j = 0; j < ipv4_fw_rulelist_col.length; j++){
						if(j==0){
							if(ipv4_fw_rulelist_col[0].length >10){
								overlib_str0_ipv4[i] += ipv4_fw_rulelist_col[0];
								ipv4_fw_rulelist_col[0]=ipv4_fw_rulelist_col[0].substring(0, 8)+"...";
								code +='<td width="'+wid[j]+'%" title="'+overlib_str0_ipv4[i]+'">'+ ipv4_fw_rulelist_col[0] +'</td>';
							}else
								code +='<td width="'+wid[j]+'%">'+ ipv4_fw_rulelist_col[j] +'</td>';
						}else if(j==1){
							if(ipv4_fw_rulelist_col[1].length >22){
								overlib_str1_ipv4[i] += ipv4_fw_rulelist_col[1];
								ipv4_fw_rulelist_col[1]=ipv4_fw_rulelist_col[1].substring(0, 20)+"...";
								code +='<td width="'+wid[j]+'%" title='+overlib_str1_ipv4[i]+'>'+ ipv4_fw_rulelist_col[1] +'</td>';
							}else
								code +='<td width="'+wid[j]+'%">'+ ipv4_fw_rulelist_col[j] +'</td>';
						}else if(j==2){
							if(ipv4_fw_rulelist_col[2].length >22){
								overlib_str2_ipv4[i] += ipv4_fw_rulelist_col[2];
								ipv4_fw_rulelist_col[2]=ipv4_fw_rulelist_col[2].substring(0, 20)+"...";
								code +='<td width="'+wid[j]+'%" title='+overlib_str2_ipv4[i]+'>'+ ipv4_fw_rulelist_col[2] +'</td>';
							}else
								code +='<td width="'+wid[j]+'%">'+ ipv4_fw_rulelist_col[j] +'</td>';
							}else if(j==3){
								if(ipv4_fw_rulelist_col[3].length >12){
									overlib_str3_ipv4[i] += ipv4_fw_rulelist_col[3];
									ipv4_fw_rulelist_col[3]=ipv4_fw_rulelist_col[3].substring(0, 10)+"...";
									code +='<td width="'+wid[j]+'%" title='+overlib_str3_ipv4[i]+'>'+ ipv4_fw_rulelist_col[3] +'</td>';
								}else
									code +='<td width="'+wid[j]+'%">'+ ipv4_fw_rulelist_col[j] +'</td>';
						}else{
							if(j == 5)
								code +='<td width="'+wid[j]+'%" class="ipv4_rule_iface_cell">'+ ipv4_fw_rulelist_col[j] +'</td>';
							else
								code +='<td width="'+wid[j]+'%">'+ ipv4_fw_rulelist_col[j] +'</td>';
						}

				}
				code +='<td width="16%" class="ipv4_rule_action_cell"><!--input class="edit_btn" onclick="edit_Row_ipv4(this);" value=""/-->';
				code +='<input class="remove_btn ipv4_rule_btn" onclick="del_Row_ipv4(this);" value=""/></td></tr>';
		}
	}
	code +='</table>';
	document.getElementById("ipv4_fw_rulelist_Block").innerHTML = code;	     
}

function ipv4_valid_check(val) {
	// Accepts plain IPv4 (e.g. 10.0.0.62) or IPv4/CIDR (e.g. 10.0.0.0/24)
	var ipv4_re = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))?$/;
	return ipv4_re.test(val.trim());
}

function ipv6_valid_check(val) {
	// Accepts plain IPv6 or IPv6/CIDR
	var ipv6_no_cidr = /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/;
	var ipv6_cidr = /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*(\/(\d|\d\d|1[0-1]\d|12[0-8]))$/;
	return ipv6_no_cidr.test(val.trim()) || ipv6_cidr.test(val.trim());
}

function ip_valid(obj, cidr) {
	var val = obj.value.trim();
	if (val === "") return true;
	if (!ipv4_valid_check(val)) {
		alert(val + " <#JS_validip#>");
		obj.focus();
		obj.select();
		return false;
	}
	return true;
}

function ipv6_valid(obj, cidr) {
	var val = obj.value.trim();
	if (val === "") return true;
	if (!ipv6_valid_check(val)) {
		alert(val + " <#JS_validip#>");
		obj.focus();
		obj.select();
		return false;
	}
	return true;
}

</script>
</head>

<body onload="initial();" onunLoad="return unload_body();" class="bg">
<div id="TopBanner"></div>
<div id="Loading" class="popup_bg"></div>

<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>

<form method="post" name="form" id="ruleForm" action="/start_apply.htm" target="hidden_frame">
<input type="hidden" name="productid" value="<% nvram_get("productid"); %>">
<input type="hidden" name="current_page" value="Advanced_BasicFirewall_Content.asp">
<input type="hidden" name="next_page" value="">
<input type="hidden" name="modified" value="0">
<input type="hidden" name="action_wait" value="5">
<input type="hidden" name="action_mode" value="apply">
<input type="hidden" name="action_script" value="restart_firewall">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>">
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">
<input type="hidden" name="ipv6_fw_rulelist" value=''>
<input type="hidden" name="ipv4_fw_rulelist" value=''>
<table class="content" align="center" cellpadding="0" cellspacing="0">
	<tr>
		<td width="17">&nbsp;</td>	
	<!--=====Beginning of Main Menu=====-->
		<td valign="top" width="202">
			<div id="mainMenu"></div>
			<div id="subMenu"></div>
		</td>		
		<td valign="top">
			<div id="tabMenu" class="submenuBlock"></div>
		<!--===================================Beginning of Main Content===========================================-->		
			<table width="98%" border="0" align="left" cellpadding="0" cellspacing="0">
				<tr>
					<td valign="top" >				
						<table width="760px" border="0" cellpadding="5" cellspacing="0" class="FormTitle" id="FormTitle">
							<tbody>
							<tr>
								<td bgcolor="#4D595D" valign="top">
									<div>&nbsp;</div>
									<div class="formfonttitle"><#menu5_5#></div>
									<div style="margin:10px 0 10px 5px;" class="splitLine"></div>
									<div class="formfontdesc" style="font-size:14px;font-weight:bold;margin-top:10px;"><#menu5_1_1#></div>
									<div class="formfontdesc"><#FirewallConfig_display2_sectiondesc#></div>
									<div class="formfontdesc" style="margin-top:-10px;">
										<a id="faq" href="" target="_blank" style="font-family:Lucida Console;text-decoration:underline;">DoS Protection FAQ</a>	<!-- untranslated -->
									</div>
									<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
										<tr>
											<th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(8,6);"><#FirewallConfig_FirewallEnable_itemname#></a></th>
											<td>
												<input type="radio" value="1" name="fw_enable_x"  onClick="change_firewall('1'); return change_common_radio(this, 'FirewallConfig', 'fw_enable_x', '1')" <% nvram_match("fw_enable_x", "1", "checked"); %>><#checkbox_Yes#>
												<input type="radio" value="0" name="fw_enable_x"  onClick="change_firewall('0'); return change_common_radio(this, 'FirewallConfig', 'fw_enable_x', '0')" <% nvram_match("fw_enable_x", "0", "checked"); %>><#checkbox_No#>
											</td>
										</tr>
									<!-- 2008.03 James. patch for Oleg's patch. { -->
										<tr>
											<th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(8,7);"><#FirewallConfig_DoSEnable_itemname#></a></th>
											<td>
												<input type="radio" value="1" name="fw_dos_x" class="input" onClick="return change_common_radio(this, 'FirewallConfig', 'fw_dos_x', '1')" <% nvram_match("fw_dos_x", "1", "checked"); %>><#checkbox_Yes#>
												<input type="radio" value="0" name="fw_dos_x" class="input" onClick="return change_common_radio(this, 'FirewallConfig', 'fw_dos_x', '0')" <% nvram_match("fw_dos_x", "0", "checked"); %>><#checkbox_No#>
											</td>
										</tr>	
									<!-- 2008.03 James. patch for Oleg's patch. } -->
										<tr>
											<th align="right"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(8,1);"><#FirewallConfig_WanLanLog_itemname#></a></th>
											<td>
												<select name="fw_log_x" class="input_option">
													<option value="none" <% nvram_match("fw_log_x", "none","selected"); %>><#wl_securitylevel_0#></option>
													<option value="drop" <% nvram_match("fw_log_x", "drop","selected"); %>><#option_dropped#></option>
													<option value="accept" <% nvram_match("fw_log_x", "accept","selected"); %>><#option_accepted#></option>
													<option value="both" <% nvram_match("fw_log_x", "both","selected"); %>><#option_both_direction#></option>
												</select>
											</td>
										</tr>					
										<tr>
											<th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(8,5);"><#FirewallConfig_x_WanPingEnable_itemname#></a></th>
											<td>
												<input type="radio" value="1" name="misc_ping_x" class="input" onClick="return change_common_radio(this, 'FirewallConfig', 'misc_ping_x', '1')" <% nvram_match("misc_ping_x", "1", "checked"); %>><#checkbox_Yes#>
												<input type="radio" value="0" name="misc_ping_x" class="input" onClick="return change_common_radio(this, 'FirewallConfig', 'misc_ping_x', '0')" <% nvram_match("misc_ping_x", "0", "checked"); %>><#checkbox_No#>
											</td>
										</tr>   
										<tr id="st_webdav_mode_tr" style="display:none;">
											<th width="40%">Cloud Disk Configure</th>
											<td>
												<select name="st_webdav_mode" class="input_option" onChange="showPortItem(this.value);">
													<option value="0" <% nvram_match("st_webdav_mode", "0", "selected"); %>>HTTP</option>
													<option value="1" <% nvram_match("st_webdav_mode", "1", "selected"); %>>HTTPS</option>
													<option value="2" <% nvram_match("st_webdav_mode", "2", "selected"); %>>BOTH</option>
												</select>
											</td>
										</tr>  
										<tr id="webdav_http_port_tr" style="display:none;">
											<th width="40%">Cloud Disk Port (HTTP):</th>
											<td>
												<input type="text" name="webdav_http_port" class="input_6_table" maxlength="5" value="<% nvram_get("webdav_http_port"); %>" onkeypress="return validator.isNumber(this, event);" autocorrect="off" autocapitalize="off">
											</td>
										</tr>
										<tr id="webdav_https_port_tr" style="display:none;">
											<th width="40%">Cloud Disk Port (HTTPS):</th>
											<td>
												<input type="text" name="webdav_https_port" class="input_6_table" maxlength="5" value="<% nvram_get("webdav_https_port"); %>" onkeypress="return validator.isNumber(this, event);" autocorrect="off" autocapitalize="off">
											</td>
										</tr>		  
									</table>

									<!--IPv4 Inbound Firewall Rules-->								<div id="ipv4_firewall_div">									<div class="formfontdesc" style="font-size:14px;font-weight:bold;margin-top:10px;">IPv4 Firewall</div>
									<div>
										<div class="formfontdesc">All outbound traffic from hosts on your LAN is allowed, as well as related inbound traffic. Any other inbound traffic must be specifically allowed here.</div>
										<div class="formfontdesc">You can leave the IP fields empty to allow traffic from/to any source. A subnet can also be specified. (192.168.1.0/24 for example)</div>
									</div>

									<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable_table" style="table-layout:fixed;">
										<thead>
											<tr>
												<td colspan="7">Inbound Firewall Rules&nbsp;(<#List_limit#>&nbsp;128)</td>
											</tr>
										</thead>

										<tr>
											<th width="12%"><#BM_UserList1#></th>
											<th width="18%">Remote IP/CIDR</th>
											<th width="18%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,25);"><#IPConnection_VServerIP_itemname#></a></th>
											<th width="12%"><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,24);"><#FirewallConfig_LanWanSrcPort_itemname#></a></th>
											<th width="10%"><#IPConnection_VServerProto_itemname#></th>
											<th width="14%">Interface</th>
											<th width="16%"><#list_add_delete#></th>
										</tr>

										<tr>
											<td width="12%">
												<input type="text" maxlength="30" class="input_12_table" name="ipv4_fw_desc_x_0" onkeypress="return validator.isString(this, event)" autocorrect="off" autocapitalize="off"/>
											</td>
											<td width="18%">
												<input type="text" maxlength="18" class="input_18_table" name="ipv4_fw_ripaddr_x_0" align="left" style="float:left;" autocomplete="off" autocorrect="off" autocapitalize="off">
											</td>
											<td width="18%">
												<input type="text" maxlength="18" class="input_18_table" name="ipv4_fw_lipaddr_x_0" align="left" style="float:left;" autocomplete="off" autocorrect="off" autocapitalize="off">
											</td>
											<td width="12%">
												<input type="text" maxlength="" class="input_12_table" name="ipv4_fw_port_x_0" onkeypress="return validator.isPortRange(this, event)" autocorrect="off" autocapitalize="off"/>
											</td>
											<td width="10%">
												<select name="ipv4_fw_proto_x_0" class="input_option">
													<option value="TCP">TCP</option>
													<option value="UDP">UDP</option>
													<option value="BOTH">BOTH</option>
													<option value="OTHER">OTHER</option>
												</select>
											</td>
											<td width="14%">
												<input type="text" maxlength="16" class="input_12_table" name="ipv4_fw_iface_x_0" placeholder="WAN" autocorrect="off" autocapitalize="off"/>
											</td>
											<td width="16%">
												<input type="button" class="add_btn ipv4_rule_btn" onClick="addRow_Group_ipv4(128);" name="ipv4_fw_rulelist2" value="">
											</td>
										</tr>
									</table>
									<div id="ipv4_fw_rulelist_Block"></div>
								</div><!--end ipv4_firewall_div-->

									<!--IPv6 firewall-->
									<div class="formfontdesc" style="font-size:14px;font-weight:bold;margin-top:10px;"><#menu5_5_6#></div>
<div id="ipv6_fw_hint">
										<div class="formfontdesc">You can leave the IP fields empty to allow traffic from/to any remote host. A subnet can also be specified. (2001::1111:2222:3333/64 for example)</div>
									</div>

									<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable">
										<thead>
											<tr>
												<td colspan="4"><#t2BC#></td>
											</tr>
										</thead>

							          	<tr>
							            	<th><#FirewallIPv6_enable#></th>
							            	<td>
							            		<input type="radio" value="1" name="ipv6_fw_enable" onClick="change_ipv6_fw('1');" <% nvram_match("ipv6_fw_enable", "1", "checked"); %>><#checkbox_Yes#>
							            		<input type="radio" value="0" name="ipv6_fw_enable" onClick="change_ipv6_fw('0');" <% nvram_match("ipv6_fw_enable", "0", "checked"); %>><#checkbox_No#>
											</td>
										</tr>
										<tr>
											<th><#IPConnection_VSList_groupitemdesc#></th>
											<td id="ipv6_fw_rulelist">
											  	<select name="KnownApps" id="KnownApps" class="input_option" onchange="change_wizard(this, 'KnownApps');"></select>
											</td>
										</tr>
							      	</table>			
							      	
									<div id="ipv6_firewall_rules_div">
									<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable_table">
										<thead>
											<tr>
							              		<td colspan="7"><#FirewallIPv6_list#>&nbsp;(<#List_limit#>&nbsp;128)</td>
							            	</tr>
							 		  	</thead>
							 		  	
							          	<tr>
											<th><#BM_UserList1#></th>
											<th><#FirewallIPv6_remoteIP#></th>
								            		<th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,25);"><#IPConnection_VServerIP_itemname#></a></th>
											<th><a class="hintstyle" href="javascript:void(0);" onClick="openHint(7,24);"><#FirewallConfig_LanWanSrcPort_itemname#></a></th>
								            		<th><#IPConnection_VServerProto_itemname#></th>
											<th><#list_add_delete#></th>
							          	</tr>  
							          		        
							          	<tr>
							  				<td width="15%">
							  					<input type="text" maxlength="30" class="input_12_table" name="ipv6_fw_desc_x_0" onkeypress="return validator.isString(this, event)" autocorrect="off" autocapitalize="off"/>
							  				</td>
											<td width="24%">
												<input type="text" maxlength="45" class="input_18_table" name="ipv6_fw_ripaddr_x_0" align="left" style="float:left;" autocomplete="off" autocorrect="off" autocapitalize="off">
											</td>
											<td width="24%">
												<input type="text" maxlength="45" class="input_18_table" name="ipv6_fw_lipaddr_x_0" align="left" style="float:left;" autocomplete="off" autocorrect="off" autocapitalize="off">
							                                </td>
											<td width="14%">
												<input type="text" maxlength="" class="input_12_table" name="ipv6_fw_port_x_0" onkeypress="return validator.isPortRange(this, event)" autocorrect="off" autocapitalize="off"/>
											</td>
											<td width="11%">
												<select name="ipv6_fw_proto_x_0" class="input_option">
													<option value="TCP">TCP</option>
													<option value="UDP">UDP</option>
													<option value="BOTH">BOTH</option>
													<option value="OTHER">OTHER</option>
												</select>
											</td>
											<td width="12%">
												<input type="button" class="add_btn" onClick="addRow_Group(128);" name="ipv6_fw_rulelist2" value="">
											</td>
										</tr>
									</table>		
									<div id="ipv6_fw_rulelist_Block"></div>
									</div><!--end ipv6_firewall_rules_div-->

									<!--end IPv6 firewall-->
									<div class="apply_gen">
										<input name="button" type="button" class="button_gen" onclick="applyRule();" value="<#CTL_apply#>"/>
									</div>        					
								</td>
							</tr>
					</tbody>	
						</table>
					</td>
</form>
				</tr>
			</table>				
		<!--===================================Ending of Main Content===========================================-->		
		</td>
		
    <td width="10" align="center" valign="top">&nbsp;</td>
	</tr>
</table>
<div id="footer"></div>
</body>
</html>
