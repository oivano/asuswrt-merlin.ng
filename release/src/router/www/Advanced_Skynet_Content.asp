<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Cache-Control" content="no-cache" />
<title><#Web_Title#> - Skynet</title>
<link rel="stylesheet" href="index_style.css" />
<link rel="stylesheet" href="form_style.css" />
<script src="/js/jquery.js"></script>
<script src="/state.js"></script>
<script src="/general.js"></script>
<script src="/popup.js"></script>
<style>
.skynet_tabs { display:flex; flex-wrap:wrap; gap:4px; margin:14px 5px; }
.skynet_tabs .button_gen { min-width:90px; }
.skynet_tabs [aria-selected="true"] { background:#085F96; }
.skynet_view { display:none; }
.skynet_view.active { display:block; }
.skynet_status { padding:12px 0; }
#skynet_rules, #skynet_feeds { table-layout:fixed; }
#skynet_rules td, #skynet_feeds td { overflow-wrap:anywhere; padding:6px; }
.skynet_remove { width:28px; height:28px; cursor:pointer; }
.skynet_empty { padding:12px; }
</style>
<script>
var skynetBusy = false;
var skynetErrors = {
	1:'Operation failed', 2:'Invalid setting', 3:'Another operation is running',
	4:'Existing Skynet addon hooks are active', 5:'Mount changed without service restart',
	6:'USB storage or policy database unavailable', 7:'Firewall, NAT acceleration, or swap prerequisite unmet',
	8:'Router time is not synchronized', 9:'Unsupported operation'
};
function initial() {
	show_menu();
	document.form.skynet_enable.value = decodeURIComponent('<% nvram_char_to_ascii("", "skynet_enable"); %>');
	document.form.skynet_mount.value = decodeURIComponent('<% nvram_char_to_ascii("", "skynet_mount"); %>');
	document.form.skynet_filter.value = decodeURIComponent('<% nvram_char_to_ascii("", "skynet_filter"); %>');
	document.form.skynet_max_entries.value = decodeURIComponent('<% nvram_char_to_ascii("", "skynet_max_entries"); %>');
	document.form.skynet_refresh_hours.value = decodeURIComponent('<% nvram_char_to_ascii("", "skynet_refresh_hours"); %>');
	show_view('overview');
	load_status();
	window.setInterval(load_status, 5000);
}
function show_view(name) {
	['overview','rules','feeds','settings'].forEach(function(view) {
		document.getElementById('skynet_' + view + '_view').className = 'skynet_view' + (view === name ? ' active' : '');
		document.getElementById('skynet_' + view + '_tab').setAttribute('aria-selected', view === name ? 'true' : 'false');
	});
}
function done_validating() {
	skynetBusy = false;
	window.setTimeout(load_status, 1000);
}
function apply_skynet(action) {
	var form = document.form;
	if (skynetBusy) return;
	if (action === 'restart_skynet') {
		var limit = Number(form.skynet_max_entries.value);
		var hours = Number(form.skynet_refresh_hours.value);
		if (!Number.isInteger(limit) || limit < 1024 || limit > 131072 || !Number.isInteger(hours) || hours < 0 || hours > 168) {
			document.getElementById('skynet_result').textContent = 'Invalid entry limit or refresh interval';
			return;
		}
	}
	skynetBusy = true;
	document.getElementById('skynet_result').textContent = 'Operation queued';
	form.action_script.value = action;
	var settings = ['skynet_enable','skynet_mount','skynet_filter','skynet_max_entries','skynet_refresh_hours'];
	var disabled = [];
	settings.forEach(function(name) {
		var fields = form.querySelectorAll('[name="' + name + '"]');
		Array.prototype.forEach.call(fields, function(field) {
			disabled.push([field,field.disabled]);
			field.disabled = action !== 'restart_skynet';
		});
	});
	form.submit();
	disabled.forEach(function(saved) { saved[0].disabled = saved[1]; });
	window.setTimeout(function() { skynetBusy = false; load_status(); }, 5000);
}
function add_cell(row, value) {
	var cell = row.insertCell(-1);
	cell.textContent = value;
	return cell;
}
function remove_button(cell, title, action) {
	var button = document.createElement('button');
	button.type = 'button'; button.textContent = '\u00d7'; button.title = title;
	button.setAttribute('aria-label',title); button.className = 'skynet_remove';
	button.onclick = action;
	cell.appendChild(button);
}
function load_status() {
	jQuery.ajax({url:'/ext/skynet/status.json', dataType:'json', cache:false, success:function(data) {
		document.getElementById('skynet_status').textContent = (data.enabled ? 'Enabled' : 'Disabled') + ' | ' +
			(data.available ? 'Storage ready' : 'Storage unavailable');
		document.getElementById('skynet_result').textContent = data.last_error ? (skynetErrors[data.last_error] || 'Operation failed') : '';
		document.getElementById('skynet_rule_count').textContent = data.rule_count;
		document.getElementById('skynet_entry_count').textContent = data.feed_entries;
		document.getElementById('skynet_feed_count').textContent = (data.feeds || []).length;
		document.getElementById('skynet_time').textContent = data.time_ready ? 'Synchronized' : 'Pending';
		var rules = document.getElementById('skynet_rules');
		var feeds = document.getElementById('skynet_feeds');
		while (rules.rows.length > 1) rules.deleteRow(1);
		while (feeds.rows.length > 1) feeds.deleteRow(1);
		(data.rules || []).forEach(function(rule) {
			var row = rules.insertRow(-1);
			add_cell(row, rule.entry);
			add_cell(row, rule.action === 'allow' ? 'Whitelist' : 'Ban');
			add_cell(row, rule.expires ? new Date(rule.expires * 1000).toLocaleString() : 'Permanent');
			remove_button(add_cell(row,''), 'Remove rule', function() {
				document.form.skynet_entry.value = rule.entry;
				apply_skynet(rule.action === 'allow' ? 'start_skynet_unwhitelist' : 'start_skynet_unban');
			});
		});
		(data.feeds || []).forEach(function(feed) {
			var row = feeds.insertRow(-1);
			add_cell(row, feed.url);
			add_cell(row, feed.updated ? new Date(feed.updated * 1000).toLocaleString() : 'Not refreshed');
			remove_button(add_cell(row,''), 'Remove feed', function() {
				document.form.skynet_feed_url.value = feed.url;
				apply_skynet('start_skynet_feedremove');
			});
		});
		document.getElementById('skynet_rules_empty').style.display = data.rule_count ? 'none' : 'block';
		document.getElementById('skynet_feeds_empty').style.display = (data.feeds || []).length ? 'none' : 'block';
		document.getElementById('skynet_rules_count').textContent = (data.rules || []).length + ' / ' + data.rule_count;
	}, error:function() { document.getElementById('skynet_status').textContent = 'Status unavailable'; }});
}
</script>
</head>
<body onload="initial();" onunload="return unload_body();" class="bg">
<div id="TopBanner"></div><div id="Loading" class="popup_bg"></div>
<iframe name="hidden_frame" id="hidden_frame" src="about:blank" width="0" height="0" frameborder="0"></iframe>
<form method="post" name="form" action="/start_apply.htm" target="hidden_frame">
<input type="hidden" name="current_page" value="Advanced_Skynet_Content.asp" />
<input type="hidden" name="next_page" value="Advanced_Skynet_Content.asp" />
<input type="hidden" name="action_mode" value="apply" />
<input type="hidden" name="action_script" value="restart_skynet" />
<input type="hidden" name="action_wait" value="5" />
<table class="content" align="center" cellpadding="0" cellspacing="0"><tr>
<td width="17">&nbsp;</td><td valign="top" width="202"><div id="mainMenu"></div><div id="subMenu"></div></td>
<td valign="top"><div id="tabMenu" class="submenuBlock"></div>
<table width="98%" border="0" align="left" cellpadding="0" cellspacing="0"><tr><td valign="top">
<table class="FormTitle" id="FormTitle" width="760px" border="0" cellpadding="5" cellspacing="0"><tr><td bgcolor="#4D595D" valign="top">
<div>&nbsp;</div>
<div class="formfonttitle"><#menu5_5#></div>
<div style="margin:10px 0 10px 5px;" class="splitLine"></div>
<div class="formfontdesc" style="font-size:14px;font-weight:bold;margin-top:10px;">Skynet</div>
<div id="skynet_status" class="skynet_status">Status unavailable</div>
<div id="skynet_result" role="status" aria-live="polite"></div>
<div class="skynet_tabs" role="tablist" aria-label="Skynet views">
<button type="button" class="button_gen" role="tab" id="skynet_overview_tab" onclick="show_view('overview');">Overview</button>
<button type="button" class="button_gen" role="tab" id="skynet_rules_tab" onclick="show_view('rules');">Rules</button>
<button type="button" class="button_gen" role="tab" id="skynet_feeds_tab" onclick="show_view('feeds');">Feeds</button>
<button type="button" class="button_gen" role="tab" id="skynet_settings_tab" onclick="show_view('settings');">Settings</button>
</div>
<div id="skynet_overview_view" class="skynet_view">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable"><tr><th>Policy Rules</th><td id="skynet_rule_count">0</td></tr>
<tr><th>Feed Entries</th><td id="skynet_entry_count">0</td></tr><tr><th>Threat Feeds</th><td id="skynet_feed_count">0</td></tr>
<tr><th>Router Time</th><td id="skynet_time">Pending</td></tr></table>
<div class="apply_gen"><input class="button_gen" type="button" value="Refresh Status" onclick="apply_skynet('start_skynet_status');" /></div>
</div>
<div id="skynet_rules_view" class="skynet_view">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable"><tr><th><label for="skynet_entry">IP / CIDR</label></th><td>
<input id="skynet_entry" name="skynet_entry" maxlength="18" type="text" class="input_20_table" />
<input class="button_gen" type="button" value="Ban" onclick="apply_skynet('start_skynet_ban');" />
<input class="button_gen" type="button" value="Whitelist" onclick="apply_skynet('start_skynet_whitelist');" /></td></tr>
<tr><th><label for="skynet_rule_seconds">Ban Duration</label></th><td><select id="skynet_rule_seconds" name="skynet_rule_seconds" class="input_option">
<option value="0">Permanent</option><option value="3600">1 hour</option><option value="86400">1 day</option><option value="604800">1 week</option></select></td></tr></table>
<div id="skynet_rules_count" class="skynet_status"></div>
<table id="skynet_rules" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable"><tr><th>IP / CIDR</th><th>Policy</th><th>Expiry</th><th width="36"></th></tr></table>
<div id="skynet_rules_empty" class="skynet_empty">No rules</div>
</div>
<div id="skynet_feeds_view" class="skynet_view">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable"><tr><th><label for="skynet_feed_url">HTTPS Feed</label></th><td>
<input id="skynet_feed_url" name="skynet_feed_url" maxlength="1023" type="url" class="input_32_table" />
<br />
<input class="button_gen" type="button" value="Add" onclick="apply_skynet('start_skynet_feedadd');" />
<input class="button_gen" type="button" value="Refresh Feeds" onclick="apply_skynet('start_skynet_refresh');" /></td></tr></table>
<table id="skynet_feeds" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable"><tr><th width="60%">Feed</th><th>Last Refresh</th><th width="36"></th></tr></table>
<div id="skynet_feeds_empty" class="skynet_empty">No feeds</div>
</div>
<div id="skynet_settings_view" class="skynet_view">
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
<tr><th>Enable Skynet</th><td><label><input name="skynet_enable" type="radio" value="1" /><#checkbox_Yes#></label>
<label><input name="skynet_enable" type="radio" value="0" /><#checkbox_No#></label></td></tr>
<tr><th><label for="skynet_mount">USB Mount</label></th><td><input id="skynet_mount" name="skynet_mount" type="text" maxlength="127" class="input_32_table" /></td></tr>
<tr><th><label for="skynet_filter">Traffic Direction</label></th><td><select id="skynet_filter" name="skynet_filter" class="input_option">
<option value="all">Inbound and outbound</option><option value="inbound">Inbound</option><option value="outbound">Outbound</option></select></td></tr>
<tr><th><label for="skynet_max_entries">Entry Limit</label></th><td><input id="skynet_max_entries" name="skynet_max_entries" type="number" min="1024" max="131072" class="input_12_table" /></td></tr>
<tr><th><label for="skynet_refresh_hours">Feed Refresh Interval</label></th><td><select id="skynet_refresh_hours" name="skynet_refresh_hours" class="input_option">
<option value="0">Manual</option><option value="1">Hourly</option><option value="24">Daily</option><option value="168">Weekly</option></select></td></tr>
</table><div class="apply_gen"><input class="button_gen" type="button" value="<#CTL_apply#>" onclick="apply_skynet('restart_skynet');" /></div>
</div>
</td></tr></table></td></tr></table></td></tr></table>
</form><div id="footer"></div>
</body></html>