<!DOCTYPE html
	PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
	<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
	<meta HTTP-EQUIV="Expires" CONTENT="-1">
	<link rel="shortcut icon" href="images/favicon.png">
	<link rel="icon" href="images/favicon.png">
	<title>
		<#Web_Title#> - <#menu5_7_6#>
	</title>
	<link rel="stylesheet" type="text/css" href="index_style.css">
	<link rel="stylesheet" type="text/css" href="form_style.css">
	<link rel="stylesheet" type="text/css" href="/js/table/table.css">
	<script type="text/javascript" src="/js/jquery.js"></script>
	<script language="JavaScript" type="text/javascript" src="/state.js"></script>
	<script language="JavaScript" type="text/javascript" src="/general.js"></script>
	<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
	<script language="JavaScript" type="text/javascript" src="/help.js"></script>
	<script language="JavaScript" type="text/javascript" src="/js/table/table.js"></script>
	<script>
		var routearray = [];
		var routev6array = [];
		var frr_route_origin_v4 = {};
		var frr_route_origin_v6 = {};
		var frr_route_overlay_enabled = 0;

		/*
		 * frrOverlayEnabled is true only when:
		 *   - FRR is compiled in (get_frr_route_origin_array registers the EJ handler)
		 *   - zebra is running and returned frr_route_overlay_enabled = 1
		 * In all other cases (FRR not compiled, FRR disabled, daemons stopped)
		 * frr_route_overlay_enabled is either undefined or 0, and this evaluates
		 * to false, falling back to the standard kernel route table.
		 */
		var frrOverlayEnabled = false;
		var sortdir_v4 = 0;
		var sortfield_v4 = 1;
		var sortdir_v6 = 0;
		var sortfield_v6 = 1;
		var refreshRate = 0;
		var timedEvent = 0;
		var routeRefreshInFlight = 0;
		var routeFirstPaintDone = 0;
		var routeFilter = {
			proto: '',
			destination: '',
			nexthop: '',
			aspath: '',
			longestMatch: 0
		};

		function update_frr_overlay_flag() {
			try {
				var v = (typeof frr_route_overlay_enabled !== 'undefined')
					? frr_route_overlay_enabled : 0;
				frrOverlayEnabled = (v === 1 || v === '1' || v === true || v === 'true');
			} catch (e) {
				frrOverlayEnabled = false;
			}
			return frrOverlayEnabled;
		}

		update_frr_overlay_flag();

		/* ── Protocol helpers ─────────────────────────────────────────────── */

		var PROTO_COLOR = {
			bgp: '#FFB347',
			ospf: '#6ED0FF',
			isis: '#8CD17D',
			rip: '#8CD17D',
			static: '#D4A8FF',
			connected: '#98FB98',
			kernel: '#8EA8B5',
			local: '#C0C0C0'
		};

		var PROTO_RANK = {
			connected: 1, local: 2, static: 3,
			kernel: 4, ospf: 5, rip: 6, isis: 7, bgp: 8
		};

		function proto_badge(proto) {
			var p = (proto || 'kernel').toLowerCase();
			var color = PROTO_COLOR[p] || '#8EA8B5';
			var label = (p == 'bgp')
				? 'BGP'
				: html_escape(p.charAt(0).toUpperCase() + p.slice(1));
			return '<span style="display:inline-block;padding:1px 7px;border-radius:9px;'
				+ 'background:' + color + ';color:#1b1b1b;font-size:11px;font-weight:600;">'
				+ label + '</span>';
		}

		function proto_rank(proto) {
			return PROTO_RANK[(proto || 'kernel').toLowerCase()] || 9;
		}

		/* ── IPv4 utilities ───────────────────────────────────────────────── */

		function ipv4_num(addr) {
			if (!addr || addr === 'default') return -1;
			var p = addr.split('.');
			if (p.length !== 4) return 0;
			var v = 0;
			for (var i = 0; i < 4; i++) v = v * 256 + parseInt(p[i], 10);
			return v;
		}

		function prefix_len(prefix) {
			var s = prefix.split('/');
			return s.length === 2 ? parseInt(s[1], 10) : 0;
		}

		function cidr_to_mask(bits) {
			var n = parseInt(bits, 10), o = [0, 0, 0, 0];
			for (var i = 0; i < 4; i++) {
				if (n >= 8) { o[i] = 255; n -= 8; }
				else if (n > 0) { o[i] = 256 - Math.pow(2, 8 - n); n = 0; }
			}
			return o.join('.');
		}

		function mask_to_prefix(mask) {
			if (!mask) return 0;
			var p = mask.split('.');
			if (p.length !== 4) return 0;
			var bits = 0;
			for (var i = 0; i < 4; i++) {
				var n = parseInt(p[i], 10);
				if (isNaN(n) || n < 0 || n > 255) return 0;
				while (n > 0) {
					bits += (n & 1);
					n = n >> 1;
				}
			}
			return bits;
		}

		function html_escape(s) {
			var str = (typeof s === 'undefined' || s === null) ? '' : String(s);
			return str
				.replace(/&/g, '&amp;')
				.replace(/</g, '&lt;')
				.replace(/>/g, '&gt;')
				.replace(/"/g, '&quot;')
				.replace(/'/g, '&#39;');
		}

		/* ── FRR route table builder ──────────────────────────────────────── */

		/*
		 * Flatten frr_route_origin_v4/v6 (prefix → [route-entries]) into a
		 * sorted flat array of row objects. Each row has:
		 *   prefix, proto, active, nhactive, nexthop, direct,
		 *   iface, dist, metric, age, aspath
		 */
		function frr_flatten_routes(origin) {
			var rows = [];
			for (var pfx in origin) {
				if (!origin.hasOwnProperty(pfx)) continue;
				var entries = origin[pfx];
				if (!Array.isArray(entries)) continue;
				for (var i = 0; i < entries.length; i++) {
					var e = entries[i];
					rows.push({
						prefix: pfx,
						proto: e.proto || 'kernel',
						active: e.active ? 1 : 0,
						nhactive: e.nhactive ? 1 : 0,
						nexthop: e.nexthop || '',
						direct: e.direct ? 1 : 0,
						iface: e.iface || '',
						dist: e.dist || 0,
						metric: e.metric || 0,
						age: e.age || '',
						aspath: e.aspath || ''
					});
				}
			}
			rows.sort(function (a, b) {
				/* active routes first */
				if (a.active !== b.active) return b.active - a.active;
				/* then by protocol */
				var rA = proto_rank(a.proto), rB = proto_rank(b.proto);
				if (rA !== rB) return rA - rB;
				/* then by prefix address numerically */
				var nA = ipv4_num(a.prefix.split('/')[0]);
				var nB = ipv4_num(b.prefix.split('/')[0]);
				if (nA !== nB) return nA - nB;
				/* then longer prefix first (more specific) */
				return prefix_len(b.prefix) - prefix_len(a.prefix);
			});
			return rows;
		}

		function route_prefix_bits(row) {
			if (!row || !row.prefix) return 0;
			if (row.prefix.indexOf('/') > -1)
				return prefix_len(row.prefix);
			if (row.mask)
				return mask_to_prefix(row.mask);
			return 0;
		}

		function route_passes_filter(row) {
			var proto = (row.proto || 'kernel').toLowerCase();
			var dest = (row.prefix || '').toLowerCase();
			var nh = (row.nexthop || '').toLowerCase();
			var aspath = (row.aspath || '').toLowerCase();

			if (routeFilter.proto && proto !== routeFilter.proto)
				return false;
			if (routeFilter.destination && dest.indexOf(routeFilter.destination) < 0)
				return false;
			if (routeFilter.nexthop && nh.indexOf(routeFilter.nexthop) < 0)
				return false;
			if (routeFilter.aspath && aspath.indexOf(routeFilter.aspath) < 0)
				return false;

			return true;
		}

		function apply_route_filter(rows) {
			var out = [];
			for (var i = 0; i < rows.length; i++) {
				if (route_passes_filter(rows[i]))
					out.push(rows[i]);
			}

			if (!routeFilter.longestMatch || out.length === 0)
				return out;

			var longest = null;
			for (var j = 0; j < out.length; j++) {
				var bits = route_prefix_bits(out[j]);
				if (longest === null || bits > longest)
					longest = bits;
			}

			var longestRows = [];
			for (var k = 0; k < out.length; k++) {
				if (route_prefix_bits(out[k]) === longest)
					longestRows.push(out[k]);
			}
			return longestRows;
		}

		function normalize_route_rows(rawRows) {
			var rows = rawRows ? rawRows.slice(0) : [];
			if (rows.length === 0)
				return rows;

			var last = rows[rows.length - 1];
			if (!last) {
				rows.pop();
				return rows;
			}

			if (Array.isArray(last)) {
				var hasData = false;
				for (var i = 0; i < last.length; i++) {
					if (last[i] !== '' && last[i] !== null && typeof last[i] !== 'undefined') {
						hasData = true;
						break;
					}
				}

				if (!hasData)
					rows.pop();
			}

			return rows;
		}

		function set_route_filter(field, obj) {
			var val = obj.value;
			if (field === 'longestMatch')
				routeFilter.longestMatch = obj.checked ? 1 : 0;
			else
				routeFilter[field] = (val || '').toLowerCase();

			show_routev4();
			show_routev6();
		}

		function set_route_loading(active) {
			var spinner = document.getElementById('route_refresh_spinner');
			if (!spinner)
				return;

			if (active && refreshRate > 0)
				spinner.style.display = '';
			else
				spinner.style.display = 'none';
		}

		function set_controls_visibility(visible) {
			var controls = document.getElementById('route_controls');
			if (controls)
				controls.style.display = visible ? '' : 'none';

			var legacyRefresh = document.getElementById('route_controls_legacy_refresh');
			if (legacyRefresh)
				legacyRefresh.style.display = visible ? 'none' : '';

			var frrButton = document.getElementById('frr_nav_button');
			if (frrButton)
				frrButton.style.display = visible ? '' : 'none';
		}

		function maybe_fadein_route_blocks() {
			if (routeFirstPaintDone)
				return;

			routeFirstPaintDone = 1;
			$('#routev4block, #routev6block').hide().fadeIn(180);
		}

		function show_route_loading_placeholders() {
			var loading = '<div style="color:#FFCC00;padding:6px 0 2px 0;">Loading route tables...</div>';
			document.getElementById('routev4block').innerHTML = loading;
			document.getElementById('routev6block').innerHTML = loading;
		}

		/* ── Table renderers ─────────────────────────────────────────────── */

		function frr_route_table_v4(rows) {
			var cols = 7;
			var totalRows = rows.length;
			rows = apply_route_filter(rows);
			var shownRows = rows.length;

			var c = '<table width="100%" border="1" cellpadding="4" cellspacing="0"'
				+ ' bordercolor="#6b8fa3" class="FormTable_table">';
			c += '<thead><tr><td colspan="' + cols + '">IPv4 Routing Table</td></tr></thead>';
			c += '<tr>'
				+ '<th width="10%" id="v4_header_0" style="cursor:pointer;" onclick="setsort_v4(0); show_routev4();">Protocol</th>'
				+ '<th width="24%" id="v4_header_1" style="cursor:pointer;font-family:monospace;" onclick="setsort_v4(1); show_routev4();">Destination</th>'
				+ '<th width="18%" id="v4_header_2" style="cursor:pointer;font-family:monospace;" onclick="setsort_v4(2); show_routev4();">Next-hop</th>'
				+ '<th width="12%" id="v4_header_3" style="cursor:pointer;" onclick="setsort_v4(3); show_routev4();">AS Path</th>'
				+ '<th width="10%" id="v4_header_4" style="cursor:pointer;" onclick="setsort_v4(4); show_routev4();">Interface</th>'
				+ '<th width="8%" id="v4_header_5" style="cursor:pointer;" onclick="setsort_v4(5); show_routev4();">[D/M]</th>'
				+ '<th width="9%" id="v4_header_6" style="cursor:pointer;" onclick="setsort_v4(6); show_routev4();">Age</th>';
			c += '</tr>';

			if (totalRows === 0) {
				c += '<tr><td colspan="' + cols + '" style="text-align:center;color:#FFCC00;">'
					+ 'No IPv4 routes.</td></tr>';
			} else if (shownRows === 0) {
				c += '<tr><td colspan="' + cols + '" style="text-align:center;color:#FFCC00;">'
					+ 'No matching IPv4 routes.</td></tr>';
				c += '<tr><td colspan="' + cols + '" class="hint-color" style="text-align:center;color:#FFCC00;">'
					+ '0 / ' + totalRows + ' routes shown.</td></tr>';
			} else {
				for (var i = 0; i < rows.length; i++) {
					var r = rows[i];
					var dm = '[' + html_escape(r.dist) + '/' + html_escape(r.metric) + ']';
					var nh = r.direct ? '<em>Direct</em>' : (r.nexthop ? html_escape(r.nexthop) : '&mdash;');
					var active_mark = r.active
						? '<span style="color:#FFFFFF;font-weight:bold;font-size:14px;">+</span>'
						: '<span style="color:#666;">&minus;</span>';
					var row_style = r.active ? '' : ' style="opacity:0.6;"';

					c += '<tr' + row_style + '>';
					c += '<td>' + proto_badge(r.proto) + '</td>';
					c += '<td style="font-family:monospace;">' + active_mark + html_escape(r.prefix) + '</td>';
					c += '<td style="font-family:monospace;">' + nh + '</td>';
					c += '<td style="font-family:monospace;font-size:11px;">' + html_escape(r.aspath || '') + '</td>';
					c += '<td>' + html_escape(r.iface) + '</td>';
					c += '<td style="font-family:monospace;">' + dm + '</td>';
					c += '<td>' + html_escape(r.age || '') + '</td>';
					c += '</tr>';
				}
				c += '<tr><td colspan="' + cols + '" class="hint-color" style="text-align:center;color:#FFCC00;">'
					+ shownRows + ' / ' + totalRows + ' routes shown.</td></tr>';
			}
			c += '</table>';
			return c;
		}

		function setsort_v4(newfield) {
			if (newfield != sortfield_v4) {
				sortdir_v4 = 0;
				sortfield_v4 = newfield;
			} else {
				sortdir_v4 = (sortdir_v4 ? 0 : 1);
			}
		}

		function age_to_seconds(age) {
			if (!age) return 0;
			var p = age.split(':');
			if (p.length != 3) return 0;
			return (parseInt(p[0], 10) || 0) * 3600 + (parseInt(p[1], 10) || 0) * 60 + (parseInt(p[2], 10) || 0);
		}

		function route_rows_sort_v4(a, b) {
			var aa = 0, bb = 0;
			var field = sortfield_v4;

			switch (field) {
				case 0:
					aa = (a.proto || '').toLowerCase();
					bb = (b.proto || '').toLowerCase();
					break;
				case 1:
					aa = ipv4_num((a.prefix || '').split('/')[0]) * 100 + prefix_len(a.prefix || '');
					bb = ipv4_num((b.prefix || '').split('/')[0]) * 100 + prefix_len(b.prefix || '');
					break;
				case 2:
					aa = ipv4_num(a.nexthop || '0.0.0.0');
					bb = ipv4_num(b.nexthop || '0.0.0.0');
					break;
				case 3:
						aa = (a.aspath || '').toLowerCase();
						bb = (b.aspath || '').toLowerCase();
						break;
					case 4:
						aa = (a.iface || '').toLowerCase();
						bb = (b.iface || '').toLowerCase();
						break;
					case 5:
					aa = (parseInt(a.dist, 10) || 0) * 100000 + (parseInt(a.metric, 10) || 0);
					bb = (parseInt(b.dist, 10) || 0) * 100000 + (parseInt(b.metric, 10) || 0);
					break;
					case 6:
					aa = age_to_seconds(a.age || '');
					bb = age_to_seconds(b.age || '');
					break;
				default:
					aa = 0;
					bb = 0;
			}

			if (aa == bb) return 0;
			if (sortdir_v4)
				return (aa > bb) ? -1 : 1;
			return (aa > bb) ? 1 : -1;
		}

		function setsort_v6(newfield) {
			if (newfield != sortfield_v6) {
				sortdir_v6 = 0;
				sortfield_v6 = newfield;
			} else {
				sortdir_v6 = (sortdir_v6 ? 0 : 1);
			}
		}

		function route_rows_sort_v6(a, b) {
			var aa = 0, bb = 0;
			var field = sortfield_v6;

			switch (field) {
				case 0:
					aa = (a.proto || '').toLowerCase();
					bb = (b.proto || '').toLowerCase();
					break;
				case 1:
					aa = (a.prefix || '').toLowerCase();
					bb = (b.prefix || '').toLowerCase();
					break;
				case 2:
					aa = (a.nexthop || '').toLowerCase();
					bb = (b.nexthop || '').toLowerCase();
					break;
				case 3:
					aa = (a.aspath || '').toLowerCase();
					bb = (b.aspath || '').toLowerCase();
					break;
				case 4:
					aa = (a.iface || '').toLowerCase();
					bb = (b.iface || '').toLowerCase();
					break;
				case 5:
					aa = (parseInt(a.dist, 10) || 0) * 100000 + (parseInt(a.metric, 10) || 0);
					bb = (parseInt(b.dist, 10) || 0) * 100000 + (parseInt(b.metric, 10) || 0);
					break;
				case 6:
					aa = age_to_seconds(a.age || '');
					bb = age_to_seconds(b.age || '');
					break;
				default:
					aa = 0;
					bb = 0;
			}

			if (aa == bb) return 0;
			if (sortdir_v6)
				return (aa > bb) ? -1 : 1;
			return (aa > bb) ? 1 : -1;
		}

		function getRefresh() {
			var val = parseInt(cookie.get('awrtm_routerefresh'));

			if ((val != 0) && (val != 10) && (val != 15) && (val != 30) && (val != 60))
				val = 0;

			document.getElementById('refreshrate').value = val;
			return val;
		}

		function setRefresh(obj) {
			refreshRate = parseInt(obj.value, 10) || 0;
			cookie.set('awrtm_routerefresh', refreshRate, 365);
			schedule_route_refresh();
		}

		function schedule_route_refresh() {
			if (timedEvent) {
				clearTimeout(timedEvent);
				timedEvent = 0;
			}

			if (refreshRate > 0 && update_frr_overlay_flag())
				timedEvent = setTimeout('get_route_status();', refreshRate * 1000);
		}

		function refresh_route_page() {
			get_route_status();
		}

		function get_route_status() {
			set_controls_visibility(frrOverlayEnabled);

			if (routeRefreshInFlight)
				return;

			if (timedEvent) {
				clearTimeout(timedEvent);
				timedEvent = 0;
			}

			routeRefreshInFlight = 1;
			set_route_loading(1);
			$.ajax({
				url: '/ajax_route_status.asp',
				dataType: 'script',
				cache: false,
				error: function (xhr) {
					update_frr_overlay_flag();
					set_controls_visibility(frrOverlayEnabled);
					show_routev4();
					show_routev6();
					routeRefreshInFlight = 0;
					set_route_loading(0);
					schedule_route_refresh();
				},
				success: function (response) {
					update_frr_overlay_flag();
					set_controls_visibility(frrOverlayEnabled);

					show_routev4();
					show_routev6();
					routeRefreshInFlight = 0;
					set_route_loading(0);
					schedule_route_refresh();
				}
			});
		}

		function frr_route_table_v6(rows) {
			var totalRows = rows.length;
			rows = apply_route_filter(rows);
			var shownRows = rows.length;

			var c = '<table width="100%" border="1" cellpadding="4" cellspacing="0"'
				+ ' bordercolor="#6b8fa3" class="FormTable_table">';
			c += '<thead><tr><td colspan="7">IPv6 Routing Table</td></tr></thead>';
			c += '<tr>'
				+ '<th width="10%" id="v6_header_0" style="cursor:pointer;" onclick="setsort_v6(0); show_routev6();">Protocol</th>'
				+ '<th width="35%" id="v6_header_1" style="cursor:pointer;font-family:monospace;" onclick="setsort_v6(1); show_routev6();">Destination</th>'
				+ '<th width="20%" id="v6_header_2" style="cursor:pointer;font-family:monospace;" onclick="setsort_v6(2); show_routev6();">Next-hop</th>'
				+ '<th width="12%" id="v6_header_3" style="cursor:pointer;" onclick="setsort_v6(3); show_routev6();">AS Path</th>'
				+ '<th width="10%" id="v6_header_4" style="cursor:pointer;" onclick="setsort_v6(4); show_routev6();">Interface</th>'
				+ '<th width="8%" id="v6_header_5" style="cursor:pointer;" onclick="setsort_v6(5); show_routev6();">[D/M]</th>'
				+ '<th width="9%" id="v6_header_6" style="cursor:pointer;" onclick="setsort_v6(6); show_routev6();">Age</th>'
				+ '</tr>';

			if (totalRows === 0) {
				c += '<tr><td colspan="7" style="text-align:center;color:#FFCC00;">'
					+ 'No IPv6 routes.</td></tr>';
			} else if (shownRows === 0) {
				c += '<tr><td colspan="7" style="text-align:center;color:#FFCC00;">'
					+ 'No matching IPv6 routes.</td></tr>';
				c += '<tr><td colspan="7" class="hint-color" style="text-align:center;color:#FFCC00;">'
					+ '0 / ' + totalRows + ' routes shown.</td></tr>';
			} else {
				for (var i = 0; i < rows.length; i++) {
					var r = rows[i];
					var dm = '[' + html_escape(r.dist) + '/' + html_escape(r.metric) + ']';
					var nh = r.direct ? '<em>Direct</em>' : (r.nexthop ? html_escape(r.nexthop) : '&mdash;');
					var active_mark = r.active
						? '<span style="color:#FFFFFF;font-weight:bold;font-size:14px;">+</span>'
						: '<span style="color:#666;">&minus;</span>';
					var row_style = r.active ? '' : ' style="opacity:0.6;"';

					c += '<tr' + row_style + '>';
					c += '<td>' + proto_badge(r.proto) + '</td>';
					c += '<td style="font-family:monospace;">' + active_mark + html_escape(r.prefix) + '</td>';
					c += '<td style="font-family:monospace;">' + nh + '</td>';
					c += '<td style="font-family:monospace;font-size:11px;">'
						+ html_escape(r.aspath || '') + '</td>';
					c += '<td>' + html_escape(r.iface) + '</td>';
					c += '<td style="font-family:monospace;">' + dm + '</td>';
					c += '<td>' + html_escape(r.age || '') + '</td>';
					c += '</tr>';
				}
				c += '<tr><td colspan="7" class="hint-color" style="text-align:center;color:#FFCC00;">'
					+ shownRows + ' / ' + totalRows + ' routes shown.</td></tr>';
			}
			c += '</table>';
			return c;
		}

		/* Strict legacy path: exact non-FRR renderer semantics */
		function legacy_show_routev4() {
			var code, i, line;
			var v4rows = normalize_route_rows(routearray || []);

			code = '<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable_table">';
			code += '<thead><tr><td colspan="8">IPv4 Routing table</td></tr></thead>';
			code += '<tr><th width="19%">Destination</th>';
			code += '<th width="19%">Gateway</th>';
			code += '<th width="16%">Genmask</th>';
			code += '<th width="11%">Flags</th>';
			code += '<th width="10%">Metric</th>';
			code += '<th width="8%">Ref</th>';
			code += '<th width="8%">Use</th>';
			code += '<th width="9%">Iface</th>';
			code += '</tr>';

			if (v4rows.length > 0) {
				for (i = 0; i < v4rows.length; ++i) {
					line = v4rows[i];

					code += '<tr>';
					code += '<td>' + html_escape(line[0]) + '</td>';
					code += '<td>' + html_escape(line[1]) + '</td>';
					code += '<td>' + html_escape(line[2]) + '</td>';
					code += '<td>' + html_escape(line[3]) + '</td>';
					code += '<td>' + html_escape(line[4]) + '</td>';
					code += '<td>' + html_escape(line[5]) + '</td>';
					code += '<td>' + html_escape(line[6]) + '</td>';
					code += '<td>' + html_escape(line[7]) + '</td>';
					code += '</tr>';
				}
			} else {
				code += '<tr><td colspan="8"><span>No IPv4 routes.</span></td></tr>';
			}

			code += '</tr></table>';
			document.getElementById('routev4block').innerHTML = code;
		}

		function legacy_show_routev6() {
			var code, i, line;
			var v6rows = normalize_route_rows(routev6array || []);

			code = '<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable_table">';
			code += '<thead><tr><td colspan="7">IPv6 Routing table</td></tr></thead>';
			code += '<tr><th width="40%">Destination<br><span style="color:#FFCC00;">Next Hop</span></th>';
			code += '<th width="10%">Flags</th>';
			code += '<th width="10%">Metric</th>';
			code += '<th width="10%">Ref</th>';
			code += '<th width="10%">Use</th>';
			code += '<th width="10%">Dev</th>';
			code += '<th width="10%">Iface</th>';
			code += '</tr>';

			if (v6rows.length > 0) {
				for (i = 0; i < v6rows.length; ++i) {
					line = v6rows[i];

					code += '<tr>';
					code += '<td>' + html_escape(line[0]) + '<br><span style="color:#FFCC00;">' + html_escape(line[1]) + '</span></td>';
					code += '<td>' + html_escape(line[2]) + '</td>';
					code += '<td>' + html_escape(line[3]) + '</td>';
					code += '<td>' + html_escape(line[4]) + '</td>';
					code += '<td>' + html_escape(line[5]) + '</td>';
					code += '<td>' + html_escape(line[6]) + '</td>';
					code += '<td>' + html_escape(line[7]) + '</td>';
					code += '</tr>';
				}
			} else {
				code += '<tr><td colspan="7"><span>No IPv6 routes.</span></td></tr>';
			}

			code += '</tr></table>';
			document.getElementById('routev6block').innerHTML = code;
		}

		/* ── Page init ───────────────────────────────────────────────────── */

		function initial() {
			show_menu();
			refreshRate = getRefresh();
			show_route_loading_placeholders();
			set_route_loading(1);
			update_frr_overlay_flag();
			setTimeout(function () { get_route_status(); }, 0);
		}

		function show_routev4() {
			if (!frrOverlayEnabled) {
				legacy_show_routev4();
				maybe_fadein_route_blocks();
				return;
			}

			var rows = frr_flatten_routes(frr_route_origin_v4 || {});
			rows.sort(route_rows_sort_v4);
			document.getElementById('routev4block').innerHTML = frr_route_table_v4(rows);

			var h = document.getElementById('v4_header_' + sortfield_v4);
			if (h && typeof sortHighlightColor !== 'undefined')
				h.style.boxShadow = sortHighlightColor + ' 0px ' + (sortdir_v4 ? '-1' : '1') + 'px 0px 0px inset';

			maybe_fadein_route_blocks();
		}

		function show_routev6() {
			if (!frrOverlayEnabled) {
				legacy_show_routev6();
				maybe_fadein_route_blocks();
				return;
			}

			var rows = frr_flatten_routes(frr_route_origin_v6 || {});
			rows.sort(route_rows_sort_v6);
			document.getElementById('routev6block').innerHTML = frr_route_table_v6(rows);

			var h = document.getElementById('v6_header_' + sortfield_v6);
			if (h && typeof sortHighlightColor !== 'undefined')
				h.style.boxShadow = sortHighlightColor + ' 0px ' + (sortdir_v6 ? '-1' : '1') + 'px 0px 0px inset';

			maybe_fadein_route_blocks();
		}

	</script>
	<style>
		@keyframes route_spin { to { transform: rotate(360deg); } }
	</style>
</head>

<body onload="initial();" class="bg">
	<div id="TopBanner"></div>
	<div id="Loading" class="popup_bg"></div>

	<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>

	<form method="post" name="form" action="apply.cgi" target="hidden_frame">
		<input type="hidden" name="current_page" value="Main_RouteStatus_Content.asp">
		<input type="hidden" name="next_page" value="Main_RouteStatus_Content">
		<input type="hidden" name="group_id" value="">
		<input type="hidden" name="modified" value="0">
		<input type="hidden" name="action_mode" value="">
		<input type="hidden" name="action_wait" value="">
		<input type="hidden" name="action_script" value="">
		<input type="hidden" name="first_time" value="">
		<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>">
		<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">

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
								<table width="760px" border="0" cellpadding="5" cellspacing="0" bordercolor="#6b8fa3"
									class="FormTitle" id="FormTitle">
									<tr bgcolor="#4D595D">
										<td valign="top">
											<div>&nbsp;</div>
											<div class="formfonttitle">
												<#System_Log#> - <#menu5_7_6#>
											</div>
											<div style="margin:10px 0 10px 5px;" class="splitLine"></div>
											<div class="formfontdesc">
												<#Route_title#>
											</div>
											<script>
												try {
													if (frrOverlayEnabled) {
														document.write('<div style="margin:6px 5px 0 5px;color:#C9D4D9;font-size:12px;">'
															+ 'FRR active &mdash; <span style="color:#7CFC7C;">+</span> = installed in FIB. '
															+ '[D/M] = admin distance\x2fmetric.'
															+ '<\/div>');
													}
												} catch (e) { }
											</script>
											<div style="margin:6px 0 10px 5px;" id="frr_nav_button">
												<input type="button" class="button_gen" value="Dynamic Routing"
													onclick="location.href='Advanced_FRR_Content.asp';"
													style="width:220px;">
											</div>
											<div id="route_controls" style="display:none;">
											<table cellpadding="4" width="100%" class="FormTable">
												<thead>
													<tr>
														<td colspan="2">Display options</td>
													</tr>
												</thead>
												<tr>
													<th>Refresh frequency</th>
													<td>
														<select name="refreshrate" class="input_option"
															onchange="setRefresh(this);" id="refreshrate">
															<option value="0" selected>No refresh</option>
															<option value="10">10 seconds</option>
															<option value="15">15 seconds</option>
															<option value="30">30 seconds</option>
															<option value="60">60 seconds</option>
														</select>
														<span id="route_refresh_spinner" style="display:none;margin-left:8px;vertical-align:middle;">
															<span style="display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,0.25);border-top-color:#fff;border-radius:50%;animation:route_spin 0.75s linear infinite;vertical-align:middle;"></span>
														</span>
													</td>
												</tr>
											</table>
											<div class="apply_gen">
												<input type="button" onClick="refresh_route_page();"
													value="<#CTL_refresh#>" class="button_gen">
											</div>

											<table cellpadding="4" width="100%" class="FormTable_table" id="route_filters">
												<thead>
													<tr>
														<td colspan="5">Filter routes</td>
													</tr>
												</thead>
												<tr>
													<th width="14%">Protocol</th>
													<th width="32%">Destination</th>
													<th width="24%">Next-hop</th>
													<th width="20%">AS Path</th>
													<th width="10%">Longest match</th>
												</tr>
												<tr>
													<td>
														<select class="input_option" onchange="set_route_filter('proto', this);">
															<option value="">any</option>
															<option value="bgp">bgp</option>
															<option value="ospf">ospf</option>
															<option value="isis">isis</option>
															<option value="rip">rip</option>
															<option value="static">static</option>
															<option value="connected">connected</option>
															<option value="local">local</option>
															<option value="kernel">kernel</option>
														</select>
													</td>
													<td><input type="text" class="input_15_table" maxlength="64" oninput="set_route_filter('destination', this);"></td>
													<td><input type="text" class="input_15_table" maxlength="64" oninput="set_route_filter('nexthop', this);"></td>
													<td><input type="text" class="input_15_table" maxlength="64" oninput="set_route_filter('aspath', this);"></td>
													<td style="text-align:center;"><input type="checkbox" onchange="set_route_filter('longestMatch', this);"></td>
												</tr>
											</table>
											</div>
											<div style="margin-top:8px">
												<div id="routev4block"></div>
											</div>
											<br>
											<div style="margin-top:8px">
												<div id="routev6block"></div>
											</div>
											<div class="apply_gen" id="route_controls_legacy_refresh" style="display:none;">
												<input type="button" onClick="refresh_route_page();"
													value="<#CTL_refresh#>" class="button_gen">
											</div>
										</td>
									</tr>
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