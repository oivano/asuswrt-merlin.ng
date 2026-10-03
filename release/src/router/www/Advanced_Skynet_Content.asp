<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Cache-Control" content="no-cache" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title><#Web_Title#> - Skynet</title>
<link rel="stylesheet" href="index_style.css" />
<link rel="stylesheet" href="form_style.css" />
<script src="/js/jquery.js"></script>
<script src="/state.js"></script>
<script src="/general.js"></script>
<script src="/popup.js"></script>
<style>
#FormTitle { --skynet-line:#53666d; --skynet-muted:#bdcbd0; width:100%; max-width:760px; box-sizing:border-box; }
.skynet_tabs { display:flex; flex-wrap:wrap; gap:4px; margin:14px 0; padding:4px; background:#2c3b40; border:1px solid var(--skynet-line); border-radius:5px; }
.skynet_tabs .button_gen { flex:1; min-width:90px; margin:0; height:34px; border:0; background:transparent; color:var(--skynet-muted); }
.skynet_tabs [aria-selected="true"] { background:#405963; color:#fff; box-shadow:inset 0 -2px #8fd1f5; }
.skynet_view { display:none; }
.skynet_view.active { display:block; }
.skynet_status { padding:12px 0; }
.skynet_section { padding:10px; margin:0; font-size:12px; font-weight:normal; color:#abd2df; border-left:3px solid #6da7be; background:#35484f; text-transform:uppercase; }
.skynet_toolbar { display:flex; align-items:center; flex-wrap:wrap; gap:8px; padding:12px 0; }
.skynet_toolbar input[type=text] { flex:1; min-width:150px; max-width:100%; box-sizing:border-box; }
.skynet_toolbar .button_gen { margin:0; }
.skynet_source_footer { justify-content:flex-end; border-top:1px solid var(--skynet-line); }
#skynet_sources_summary { flex:1; font-size:12px; color:var(--skynet-muted); }
#skynet_apply_sources:disabled, .skynet_view .button_gen:disabled { opacity:.5; cursor:default; }
#skynet_rules, #skynet_feeds { table-layout:fixed; }
#skynet_rules td, #skynet_feeds td { overflow-wrap:anywhere; padding:6px; }
#skynet_feeds th:nth-child(1) { width:35% !important; }
#skynet_feeds th:nth-child(2) { width:10% !important; }
#skynet_feeds th:nth-child(3) { width:24% !important; }
#skynet_feeds th:nth-child(4) { width:13% !important; }
#skynet_feeds th:nth-child(5) { width:18% !important; }
#skynet_feeds td { width:auto !important; }
#skynet_feeds td:nth-child(2) { text-align:right; }
.skynet_source { font-family:monospace; font-size:12px; }
.skynet_source_state { font-size:12px; text-transform:capitalize; }
.skynet_source_state.current { color:#a9e5bf; }
.skynet_source_state.cached { color:#f4d97b; }
.skynet_source_state.failed { color:#f2afb5; }
.skynet_source_controls { display:flex; justify-content:center; align-items:center; gap:8px; }
.skynet_source_toggle { appearance:none; width:34px; height:20px; flex-shrink:0; margin:0; border:1px solid #71858c; border-radius:10px; background:#283a41; cursor:pointer; }
.skynet_source_toggle:before { content:''; display:block; width:14px; height:14px; margin:2px; border-radius:50%; background:#bfcbd0; }
.skynet_source_toggle:checked { background:#477d94; border-color:#83bed3; }
.skynet_source_toggle:checked:before { margin-left:16px; background:#e9f7fc; }
.skynet_source_toggle:focus-visible { outline:2px solid #8fd1f5; outline-offset:2px; }
.skynet_source_toggle:disabled { opacity:.5; cursor:default; }
.skynet_remove { width:28px; height:28px; cursor:pointer; }
.skynet_empty { padding:12px; }
@media(max-width:760px) {
	.content { display:block; width:100% !important; margin:0 !important; }
	.content > tbody, .content > tbody > tr, .content > tbody > tr > td { display:block; width:100% !important; box-sizing:border-box; }
	.content > tbody > tr > td:nth-child(1), .content > tbody > tr > td:nth-child(2) { display:none; }
	.content table:not(.FormTable) { width:100% !important; max-width:100%; table-layout:fixed; }
	#FormTitle { padding:0; }
}
@media(max-width:600px) {
	#skynet_feeds, #skynet_feeds tbody, #skynet_feeds tr, #skynet_feeds td { display:block; width:auto; }
	#skynet_feeds tr:first-child { display:none; }
	#skynet_feeds tr:not(:first-child) { display:grid; grid-template-columns:minmax(0,1fr) 80px; padding:8px; border-bottom:1px solid var(--skynet-line); }
	#skynet_feeds td { border:0; min-width:0; }
	#skynet_feeds td:first-child { grid-column:1; }
	#skynet_feeds td:nth-child(2), #skynet_feeds td:nth-child(3) { grid-column:1; font-size:12px; color:var(--skynet-muted); }
	#skynet_feeds td:nth-child(2):before { content:'Entries: '; }
	#skynet_feeds td:nth-child(3):before { content:'Last success: '; }
	#skynet_feeds td:nth-child(4) { grid-column:2; grid-row:2 / 4; align-self:center; }
	#skynet_feeds td:last-child { grid-column:2; grid-row:1; }
	.skynet_view .FormTable th, .skynet_view .FormTable td { overflow-wrap:anywhere; }
}
</style>
<script>
var skynetBusy = false;
var skynetLoading = false;
var skynetRequest = '';
var skynetAction = '';
var skynetAvailable = false;
var skynetQueued = 0;
var skynetFeeds = [];
var skynetSelection = {};
var skynetSourcesDirty = false;
var skynetErrors = {
	1:'Operation failed', 2:'Invalid setting', 3:'Another operation is running',
	4:'Existing Skynet addon hooks are active', 5:'Mount changed without service restart',
	6:'USB storage or policy database unavailable', 7:'Firewall or swap prerequisite unmet',
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
}
function show_view(name) {
	['overview','rules','feeds','settings'].forEach(function(view) {
		document.getElementById('skynet_' + view + '_view').className = 'skynet_view' + (view === name ? ' active' : '');
		document.getElementById('skynet_' + view + '_tab').setAttribute('aria-selected', view === name ? 'true' : 'false');
	});
}
function done_validating() {
	if (!skynetRequest) skynetBusy = false;
	update_source_controls();
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
	skynetAction = action;
	skynetRequest = action === 'restart_skynet' ? '' : String(Date.now()) + String(Math.floor(Math.random() * 1000000000));
	skynetQueued = Date.now();
	form.skynet_request.value = skynetRequest;
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
	update_source_controls();
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
function add_feed() {
	if (skynetBusy || skynetSourcesDirty) return;
	var source = document.getElementById('skynet_custom_feed').value.trim();
	if (feed_name(source) === source && !/^(bds_atif\.ipset|cybercrime\.ipset|et_compromised\.ipset|firehol_level[23]\.netset|ipsum_3\.ipset|spamhaus_drop\.netset|IP-High-Confidence-Feed\.txt)$/.test(source)) {
		if (!/^https:\/\/[^\/\s@#]+(?:\/[^\s@#]*)?$/.test(source)) {
			document.getElementById('skynet_result').textContent = 'Enter a valid HTTPS feed URL';
			return;
		}
	}
	document.form.skynet_feed_url.value = source;
	apply_skynet('start_skynet_feedadd');
}
function feed_name(url) {
	var names = ['bds_atif.ipset','cybercrime.ipset','et_compromised.ipset','firehol_level2.netset',
		'firehol_level3.netset','ipsum_3.ipset','spamhaus_drop.netset','IP-High-Confidence-Feed.txt'];
	for (var index = 0; index < names.length; index++) {
		var name = names[index];
		var prefix = name === 'IP-High-Confidence-Feed.txt' ?
			'https://threatview.io/Downloads/' : 'https://iplists.firehol.org/files/';
		if (url === prefix + name) return name;
	}
	return url;
}
function update_source_controls() {
	document.querySelectorAll('.skynet_view button, .skynet_view input[type="button"]').forEach(function(button) {
		button.disabled = skynetBusy;
	});
	document.querySelectorAll('#skynet_feeds .skynet_remove').forEach(function(button) {
		button.disabled = skynetBusy || skynetSourcesDirty || !skynetAvailable;
	});
	document.querySelectorAll('#skynet_feeds input[type="checkbox"]').forEach(function(toggle) {
		toggle.disabled = skynetBusy || !skynetAvailable;
	});
	['skynet_add_source','skynet_default_sources','skynet_update_sources'].forEach(function(id) {
		document.getElementById(id).disabled = skynetBusy || skynetSourcesDirty || !skynetAvailable;
	});
	document.getElementById('skynet_apply_sources').disabled = skynetBusy || !skynetSourcesDirty || !skynetAvailable;
	var enabled = skynetFeeds.filter(function(feed) { return skynetSelection[feed.id]; }).length;
	document.getElementById('skynet_sources_summary').textContent = enabled + ' of ' + skynetFeeds.length +
		' sources enabled' + (skynetSourcesDirty ? ' | Unsaved changes' : '');
}
function apply_sources() {
	if (skynetBusy || !skynetSourcesDirty) return;
	var selected = skynetFeeds.filter(function(feed) { return skynetSelection[feed.id]; })
		.map(function(feed) { return feed.id; });
	if (!selected.length) {
		document.getElementById('skynet_result').textContent = 'At least one source must remain enabled';
		return;
	}
	document.form.skynet_feed_url.value = JSON.stringify(selected);
	apply_skynet('start_skynet_feedselect');
}
function default_sources() {
	if (skynetBusy || skynetSourcesDirty || !window.confirm('Replace saved sources with the eight upstream defaults? Custom sources will be removed.')) return;
	apply_skynet('start_skynet_feeddefaults');
}
function render_feeds(feeds) {
	var table = document.getElementById('skynet_feeds');
	while (table.rows.length > 1) table.deleteRow(1);
	skynetFeeds = feeds;
	feeds.forEach(function(feed) {
		if (!skynetSourcesDirty) skynetSelection[feed.id] = Boolean(feed.enabled);
		var row = table.insertRow(-1);
		var name = feed_name(feed.url);
		var source = add_cell(row, name);
		source.className = 'skynet_source'; source.title = feed.url;
		add_cell(row, Number(feed.entries || 0).toLocaleString());
		add_cell(row, feed.updated ? new Date(feed.updated * 1000).toLocaleString() : 'Never');
		var state = skynetSelection[feed.id] ? (feed.state === 'excluded' ? 'pending' : feed.state) : 'excluded';
		var health = add_cell(row, state || 'pending');
		health.className = 'skynet_source_state ' + (/^(current|cached|failed|excluded|pending)$/.test(state) ? state : 'pending');
		health.title = feed.error || '';
		var controls = document.createElement('div');
		controls.className = 'skynet_source_controls';
		var toggle = document.createElement('input');
		toggle.type = 'checkbox'; toggle.className = 'skynet_source_toggle';
		toggle.checked = Boolean(skynetSelection[feed.id]);
		toggle.title = 'Enable ' + name; toggle.setAttribute('aria-label', toggle.title);
		toggle.onchange = function() {
			skynetSelection[feed.id] = toggle.checked;
			skynetSourcesDirty = skynetFeeds.some(function(source) { return Boolean(source.enabled) !== Boolean(skynetSelection[source.id]); });
			render_feeds(skynetFeeds);
		};
		controls.appendChild(toggle);
		remove_button(controls, 'Remove ' + name, function() {
			if (!window.confirm('Remove source ' + name + '?')) return;
			document.form.skynet_feed_url.value = feed.url;
			apply_skynet('start_skynet_feedremove');
		});
		add_cell(row, '').appendChild(controls);
	});
	document.getElementById('skynet_feeds_empty').style.display = feeds.length ? 'none' : 'block';
	update_source_controls();
}
function load_status() {
	if (skynetLoading) return;
	skynetLoading = true;
	jQuery.ajax({url:'/ext/skynet/status.json', dataType:'json', cache:false, timeout:15000, success:function(data) {
		skynetAvailable = Boolean(data.available);
		document.getElementById('skynet_status').textContent = (data.enabled ? 'Enabled' : 'Disabled') + ' | ' +
			(data.available ? 'Storage ready' : 'Storage unavailable');
		if (skynetBusy && skynetRequest && data.request === skynetRequest) {
			skynetBusy = false;
			skynetRequest = '';
			if (!data.last_error && /^start_skynet_feed(add|remove|select|defaults)$/.test(skynetAction))
				skynetSourcesDirty = false;
			document.getElementById('skynet_result').textContent = data.last_error ?
				(skynetErrors[data.last_error] || 'Operation failed') : 'Operation completed';
		} else if (!skynetBusy && !skynetSourcesDirty && data.last_error) {
			document.getElementById('skynet_result').textContent = skynetErrors[data.last_error] || 'Operation failed';
		}
		if (!skynetAvailable) {
			update_source_controls();
			return;
		}
		document.getElementById('skynet_rule_count').textContent = data.rule_count;
		document.getElementById('skynet_entry_count').textContent = data.feed_entries;
		document.getElementById('skynet_feed_count').textContent = (data.feeds || []).length;
		document.getElementById('skynet_time').textContent = data.time_ready ? 'Synchronized' : 'Pending';
		var rules = document.getElementById('skynet_rules');
		while (rules.rows.length > 1) rules.deleteRow(1);
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
		render_feeds(data.feeds || []);
		document.getElementById('skynet_rules_empty').style.display = data.rule_count ? 'none' : 'block';
		document.getElementById('skynet_rules_count').textContent = (data.rules || []).length + ' / ' + data.rule_count;
	}, error:function() { document.getElementById('skynet_status').textContent = 'Status unavailable'; }, complete:function() {
		skynetLoading = false;
		if (skynetBusy && Date.now() - skynetQueued > 1200000) {
			skynetBusy = false;
			skynetRequest = '';
			document.getElementById('skynet_result').textContent = 'Completion not confirmed. Check System Log before retrying.';
			update_source_controls();
		}
		window.setTimeout(load_status, skynetBusy ? 1000 : 5000);
	}});
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
<input type="hidden" name="skynet_request" value="" />
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
<button type="button" class="button_gen" role="tab" id="skynet_feeds_tab" onclick="show_view('feeds');">Updates</button>
<button type="button" class="button_gen" role="tab" id="skynet_settings_tab" onclick="show_view('settings');">Protection</button>
<button type="button" class="button_gen" role="tab" id="skynet_rules_tab" onclick="show_view('rules');">Rules</button>
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
<h3 class="skynet_section">Updates &amp; Lists</h3>
<div class="skynet_toolbar">
<button class="button_gen" id="skynet_update_sources" type="button" onclick="apply_skynet('start_skynet_refresh');">Update Now</button>
<button class="button_gen" id="skynet_default_sources" type="button" onclick="default_sources();">Restore Default Sources</button>
</div>
<h3 class="skynet_section">Threat Feed Sources</h3>
<table id="skynet_feeds" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable"><tr><th width="35%">Source</th><th width="10%">Entries</th><th width="24%">Last Success</th><th width="13%">State</th><th width="18%">Controls</th></tr></table>
<div id="skynet_feeds_empty" class="skynet_empty">No sources</div>
<div class="skynet_toolbar">
<input id="skynet_custom_feed" maxlength="1023" type="text" class="input_32_table" aria-label="Built-in feed name or custom HTTPS URL" placeholder="https://example.com/ipv4-list.txt" />
<input id="skynet_feed_url" name="skynet_feed_url" type="hidden" />
<button class="button_gen" id="skynet_add_source" type="button" onclick="add_feed();">Add Source</button>
</div>
<div class="skynet_toolbar skynet_source_footer"><span id="skynet_sources_summary" aria-live="polite"></span>
<button class="button_gen" id="skynet_apply_sources" type="button" disabled="disabled" onclick="apply_sources();">Apply Sources</button></div>
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