/* ════════════════════════════════════════════════════════════════
   Query Forge — forge.js
   Templating de queries KQL (Defender XDR), XQL (Cortex XDR) y
   CSQL (CrowdStrike) a partir de IOCs (hashes / IPs / dominios) +
   lookback. 100% en cliente, sin backend.
   ════════════════════════════════════════════════════════════════ */


/* ── Helpers compartidos ─────────────────────────────────── */

function forgeSanitize(raw) {
  var s = raw.trim();
  s = s.replace(/\[\.\]/g, '.').replace(/\[:\]/g, ':');
  s = s.replace(/^hxxps?:\/\//i, '').replace(/^https?:\/\//i, '');
  s = s.replace(/\/.*$/, '');
  s = s.replace(/:[\d]+$/, '');
  s = s.replace(/['"\(\)\[\]]/g, '').trim();
  return s;
}

function forgeClassify(ioc) {
  if (!ioc) return null;
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ioc)) return 'ip';
  if (/^[0-9a-fA-F]+$/.test(ioc)) {
    if (ioc.length === 32) return 'md5';
    if (ioc.length === 40) return 'sha1';
    if (ioc.length === 64) return 'sha256';
  }
  if (/^[a-zA-Z0-9][a-zA-Z0-9\-.]+\.[a-zA-Z]{2,}$/.test(ioc)) return 'domain';
  return null;
}


/* ════════════════════════════════════════════════════
   KQL — Defender XDR
   ════════════════════════════════════════════════════ */

var FORGE_LABELS = {ip:'IPs', domain:'Dominios', md5:'MD5', sha1:'SHA1', sha256:'SHA256'};
var FORGE_ORDER  = ['domain', 'ip', 'md5', 'sha1', 'sha256'];

function forgeTemplate(type, iocs, lb) {
  var q = iocs.map(function(i){ return '    "' + i + '"'; }).join(',\n');
  var H = 'let lookback = ' + lb + ';\n';
  var NET = 'DeviceNetworkEvents\n| where Timestamp >= ago(lookback)\n';
  var FILE = 'DeviceFileEvents\n| where Timestamp >= ago(lookback)\n';
  switch(type) {
    case 'ip':
      return H + 'let IpsIOC = dynamic([\n' + q + '\n]);\n' + NET +
        '| where RemoteIP in (IpsIOC)\n' +
        '| project Timestamp, DeviceName, RemoteIP, RemotePort, Protocol, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine\n' +
        '| order by Timestamp desc';
    case 'domain':
      return H + 'let DominiosIOC = dynamic([\n' + q + '\n]);\n' + NET +
        '| where RemoteUrl has_any (DominiosIOC)\n' +
        '| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, Protocol\n' +
        '| order by Timestamp desc';
    case 'md5':
      return H + 'let HashesMD5 = dynamic([\n' + q + '\n]);\n' + FILE +
        '| where MD5 in (HashesMD5)\n' +
        '| project Timestamp, DeviceName, FileName, FolderPath, MD5, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType\n' +
        '| order by Timestamp desc';
    case 'sha1':
      return H + 'let HashesSHA1 = dynamic([\n' + q + '\n]);\n' + FILE +
        '| where SHA1 in (HashesSHA1)\n' +
        '| project Timestamp, DeviceName, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType\n' +
        '| order by Timestamp desc';
    case 'sha256':
      return H + 'let HashesSHA256 = dynamic([\n' + q + '\n]);\n' + FILE +
        '| where SHA256 in (HashesSHA256)\n' +
        '| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType\n' +
        '| order by Timestamp desc';
  }
  return '';
}

function forgeGenerate() {
  var raw = document.getElementById('forge-input').value;
  var lb  = document.getElementById('forge-lookback').value;
  var buckets = {};
  var skipped = [];

  raw.split('\n').forEach(function(line) {
    var clean = forgeSanitize(line);
    if (!clean) return;
    var type = forgeClassify(clean);
    if (!type) { skipped.push(clean); return; }
    var val = (type !== 'ip' && type !== 'domain') ? clean.toLowerCase() : clean;
    if (!buckets[type]) buckets[type] = [];
    if (buckets[type].indexOf(val) === -1) buckets[type].push(val);
  });

  var total = 0;
  FORGE_ORDER.forEach(function(t){ if (buckets[t]) total += buckets[t].length; });

  var statsEl  = document.getElementById('forge-stats');
  var outputEl = document.getElementById('forge-output');

  if (total === 0) {
    statsEl.textContent = 'No se reconocieron IOCs validos.' +
      (skipped.length ? ' Sin clasificar: ' + skipped.slice(0,3).join(', ') : '');
    outputEl.innerHTML = '';
    return;
  }

  var found = FORGE_ORDER.filter(function(t){ return buckets[t]; });
  var statsHtml = '<span class="forge-count">' + total + ' IOCs</span> &mdash; ' +
    found.map(function(t){ return buckets[t].length + ' ' + FORGE_LABELS[t]; }).join(', ') +
    (skipped.length ? ' <span class="forge-muted"> | ' + skipped.length + ' sin clasificar</span>' : '') +
    ' <span class="forge-muted"> | lookback: ' + lb + '</span>';
  statsEl.innerHTML = statsHtml;

  forgeRenderTabs(outputEl, 'forge-kql', buckets, FORGE_ORDER, FORGE_LABELS, lb, 'lookback', 'forgeCopy', forgeTemplate);
}

function forgeCopy(id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  copyToClipboard(el.textContent).then(function(){
    var orig = btn.textContent;
    btn.textContent = 'Copiado';
    setTimeout(function(){ btn.textContent = orig; }, 1500);
  });
}

function forgeClear() {
  document.getElementById('forge-input').value = '';
  document.getElementById('forge-output').innerHTML = '';
  document.getElementById('forge-stats').textContent = 'Introduce IOCs y pulsa Generar KQL';
}


/* ════════════════════════════════════════════════════
   XQL — Cortex XDR
   ════════════════════════════════════════════════════ */

var FORGE_XQL_LABELS = {ip:'IPs', domain:'Dominios', md5:'MD5', sha1:'SHA1', sha256:'SHA256'};
var FORGE_XQL_ORDER  = ['domain', 'ip', 'sha256', 'md5', 'sha1'];

function forgeXqlTemplate(type, iocs, lb) {
  var q = iocs.map(function(i){ return '    "' + i + '"'; }).join(',\n');
  switch(type) {
    case 'domain':
      return 'config timeframe = ' + lb + '\n' +
        '| preset = network_story\n' +
        '| filter dst_action_external_hostname in (\n' + q + '\n)\n' +
        '   or dns_query_name in (\n' + q + '\n)\n' +
        '| fields _time,\n' +
        '         agent_hostname,\n' +
        '         agent_ip_addresses,\n' +
        '         action_remote_ip,\n' +
        '         action_remote_port,\n' +
        '         dst_action_external_hostname,\n' +
        '         dns_query_name,\n' +
        '         actor_process_image_name,\n' +
        '         actor_process_command_line\n' +
        '| sort desc _time';
    case 'ip':
      return 'config timeframe = ' + lb + '\n' +
        '| preset = network_story\n' +
        '| filter action_remote_ip in (\n' + q + '\n)\n' +
        '| fields _time,\n' +
        '         agent_hostname,\n' +
        '         agent_ip_addresses,\n' +
        '         action_local_ip,\n' +
        '         action_remote_ip,\n' +
        '         action_remote_port,\n' +
        '         dst_action_external_hostname,\n' +
        '         actor_process_image_name,\n' +
        '         actor_process_command_line,\n' +
        '         actor_effective_username,\n' +
        '         agent_os_type\n' +
        '| sort desc _time';
    case 'sha256':
      return 'config timeframe = ' + lb + '\n' +
        '| dataset = xdr_data\n' +
        '| filter (event_type = ENUM.FILE and action_file_sha256 in (\n' + q + '\n))\n' +
        '   or (event_type = ENUM.PROCESS and actor_process_image_sha256 in (\n' + q + '\n))\n' +
        '| fields _time,\n' +
        '         agent_hostname,\n' +
        '         agent_ip_addresses,\n' +
        '         action_file_name,\n' +
        '         action_file_path,\n' +
        '         action_file_sha256,\n' +
        '         action_file_md5,\n' +
        '         action_file_sha1,\n' +
        '         actor_process_image_name,\n' +
        '         actor_process_image_sha256,\n' +
        '         actor_process_command_line,\n' +
        '         agent_os_type\n' +
        '| sort desc _time';
    case 'md5':
      return 'config timeframe = ' + lb + '\n' +
        '| dataset = xdr_data\n' +
        '| filter event_type = ENUM.FILE\n' +
        '| filter action_file_md5 in (\n' + q + '\n)\n' +
        '| fields _time,\n' +
        '         agent_hostname,\n' +
        '         agent_ip_addresses,\n' +
        '         action_file_name,\n' +
        '         action_file_path,\n' +
        '         action_file_md5,\n' +
        '         action_file_sha256,\n' +
        '         actor_process_image_name,\n' +
        '         actor_process_command_line,\n' +
        '         agent_os_type\n' +
        '| sort desc _time';
    case 'sha1':
      return 'config timeframe = ' + lb + '\n' +
        '| dataset = xdr_data\n' +
        '| filter event_type = ENUM.FILE\n' +
        '| filter action_file_sha1 in (\n' + q + '\n)\n' +
        '| fields _time,\n' +
        '         agent_hostname,\n' +
        '         agent_ip_addresses,\n' +
        '         action_file_name,\n' +
        '         action_file_path,\n' +
        '         action_file_sha1,\n' +
        '         action_file_sha256,\n' +
        '         actor_process_image_name,\n' +
        '         actor_process_command_line,\n' +
        '         agent_os_type\n' +
        '| sort desc _time';
  }
  return '';
}

function forgeXqlGenerate() {
  var raw = document.getElementById('forge-xql-input').value;
  var lb  = document.getElementById('forge-xql-lookback').value;
  var buckets = {};
  var skipped = [];

  raw.split('\n').forEach(function(line) {
    var clean = forgeSanitize(line);
    if (!clean) return;
    var type = forgeClassify(clean);
    if (!type) { skipped.push(clean); return; }
    var val = (type !== 'ip' && type !== 'domain') ? clean.toLowerCase() : clean;
    if (!buckets[type]) buckets[type] = [];
    if (buckets[type].indexOf(val) === -1) buckets[type].push(val);
  });

  var total = 0;
  FORGE_XQL_ORDER.forEach(function(t){ if (buckets[t]) total += buckets[t].length; });

  var statsEl  = document.getElementById('forge-xql-stats');
  var outputEl = document.getElementById('forge-xql-output');

  if (total === 0) {
    statsEl.textContent = 'No se reconocieron IOCs validos.' +
      (skipped.length ? ' Sin clasificar: ' + skipped.slice(0,3).join(', ') : '');
    outputEl.innerHTML = '';
    return;
  }

  var found = FORGE_XQL_ORDER.filter(function(t){ return buckets[t]; });
  var statsHtml = '<span class="forge-count">' + total + ' IOCs</span> &mdash; ' +
    found.map(function(t){ return buckets[t].length + ' ' + FORGE_XQL_LABELS[t]; }).join(', ') +
    (skipped.length ? ' <span class="forge-muted"> | ' + skipped.length + ' sin clasificar</span>' : '') +
    ' <span class="forge-muted"> | timeframe: ' + lb + '</span>';
  statsEl.innerHTML = statsHtml;

  forgeRenderTabs(outputEl, 'forge-xql', buckets, FORGE_XQL_ORDER, FORGE_XQL_LABELS, lb, 'timeframe', 'forgeXqlCopy', forgeXqlTemplate);
}

function forgeXqlCopy(id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  copyToClipboard(el.textContent).then(function(){
    var orig = btn.textContent;
    btn.textContent = 'Copiado';
    setTimeout(function(){ btn.textContent = orig; }, 1500);
  });
}

function forgeXqlClear() {
  document.getElementById('forge-xql-input').value = '';
  document.getElementById('forge-xql-output').innerHTML = '';
  document.getElementById('forge-xql-stats').textContent = 'Introduce IOCs y pulsa Generar XQL';
}


/* ════════════════════════════════════════════════════
   CSQL — CrowdStrike (LogScale / NG-SIEM)
   ════════════════════════════════════════════════════ */

var FORGE_CS_LABELS = {ip:'IPs', domain:'Dominios', md5:'MD5', sha256:'SHA256'};
var FORGE_CS_ORDER  = ['domain', 'ip', 'sha256', 'md5'];

function forgeCsTemplate(type, iocs, lb) {
  var arr = iocs.map(function(i){ return '  "' + i + '"'; }).join(',\n');
  switch(type) {
    case 'domain':
      return 'LET lookback = ' + lb + ';\n' +
        'LET DomainsIOC = array(\n' + arr + '\n);\n\n' +
        '#event_simpleName in ("DnsRequest", "HttpRequest")\n' +
        '| @timestamp >= now() - lookback\n' +
        '| DomainName in(DomainsIOC)\n' +
        '| table([\n' +
        '    @timestamp,\n' +
        '    ComputerName,\n' +
        '    event_platform,\n' +
        '    #event_simpleName,\n' +
        '    DomainName,\n' +
        '    RemoteAddressIP4,\n' +
        '    RemotePort,\n' +
        '    ImageFileName,\n' +
        '    CommandLine\n' +
        '  ])\n' +
        '| sort(@timestamp desc)';

    case 'ip':
      return 'LET lookback = ' + lb + ';\n' +
        'LET IpsIOC = array(\n' + arr + '\n);\n\n' +
        '#event_simpleName in ("NetworkConnect", "NetworkConnectIP4")\n' +
        '| @timestamp >= now() - lookback\n' +
        '| RemoteAddressIP4 in(IpsIOC)\n' +
        '| table([\n' +
        '    @timestamp,\n' +
        '    ComputerName,\n' +
        '    event_platform,\n' +
        '    #event_simpleName,\n' +
        '    LocalAddressIP4,\n' +
        '    LocalPort,\n' +
        '    RemoteAddressIP4,\n' +
        '    RemotePort,\n' +
        '    ImageFileName,\n' +
        '    CommandLine\n' +
        '  ])\n' +
        '| sort(@timestamp desc)';

    case 'sha256':
      return 'LET lookback = ' + lb + ';\n' +
        'LET HashesSHA256 = array(\n' + arr + '\n);\n\n' +
        'event_platform = "Win"\n' +
        '| #event_simpleName in ("ProcessRollup2", "FileWritten", "FileOpenInfo")\n' +
        '| @timestamp >= now() - lookback\n' +
        '| SHA256HashData in(HashesSHA256)\n' +
        '| table([\n' +
        '    @timestamp,\n' +
        '    ComputerName,\n' +
        '    event_platform,\n' +
        '    #event_simpleName,\n' +
        '    FileName,\n' +
        '    FilePath,\n' +
        '    SHA256HashData,\n' +
        '    MD5HashData,\n' +
        '    ImageFileName,\n' +
        '    CommandLine\n' +
        '  ])\n' +
        '| sort(@timestamp desc)';

    case 'md5':
      return 'LET lookback = ' + lb + ';\n' +
        'LET HashesMD5 = array(\n' + arr + '\n);\n\n' +
        'event_platform = "Win"\n' +
        '| #event_simpleName in ("ProcessRollup2", "FileWritten", "FileOpenInfo")\n' +
        '| @timestamp >= now() - lookback\n' +
        '| MD5HashData in(HashesMD5)\n' +
        '| table([\n' +
        '    @timestamp,\n' +
        '    ComputerName,\n' +
        '    event_platform,\n' +
        '    #event_simpleName,\n' +
        '    FileName,\n' +
        '    FilePath,\n' +
        '    SHA256HashData,\n' +
        '    MD5HashData,\n' +
        '    ImageFileName,\n' +
        '    CommandLine\n' +
        '  ])\n' +
        '| sort(@timestamp desc)';

    default: return '';
  }
}

function forgeCsGenerate() {
  var raw = document.getElementById('forge-cs-input').value;
  var lb  = document.getElementById('forge-cs-lookback').value;
  var buckets = {};
  var skipped = [];

  raw.split('\n').forEach(function(line) {
    var clean = forgeSanitize(line);
    if (!clean) return;
    var type = forgeClassify(clean);
    if (!type) { skipped.push(clean); return; }
    var val = (type !== 'ip' && type !== 'domain') ? clean.toLowerCase() : clean;
    if (!buckets[type]) buckets[type] = [];
    if (buckets[type].indexOf(val) === -1) buckets[type].push(val);
  });

  // SHA1 no soportado en CrowdStrike standard events
  if (buckets['sha1']) {
    skipped = skipped.concat(buckets['sha1'].map(function(v){ return v + ' (SHA1 no soportado)'; }));
    delete buckets['sha1'];
  }

  var total = 0;
  FORGE_CS_ORDER.forEach(function(t){ if (buckets[t]) total += buckets[t].length; });

  var statsEl  = document.getElementById('forge-cs-stats');
  var outputEl = document.getElementById('forge-cs-output');

  if (total === 0) {
    statsEl.textContent = 'No se reconocieron IOCs validos.' +
      (skipped.length ? ' Sin clasificar: ' + skipped.slice(0,3).join(', ') : '');
    outputEl.innerHTML = '';
    return;
  }

  var found = FORGE_CS_ORDER.filter(function(t){ return buckets[t]; });
  var statsHtml = '<span class="forge-count">' + total + ' IOCs</span> &mdash; ' +
    found.map(function(t){ return buckets[t].length + ' ' + FORGE_CS_LABELS[t]; }).join(', ') +
    (skipped.length ? ' <span class="forge-muted"> | ' + skipped.length + ' omitido(s)</span>' : '') +
    ' <span class="forge-muted"> | lookback: ' + lb + '</span>';
  statsEl.innerHTML = statsHtml;

  forgeRenderTabs(outputEl, 'forge-cs', buckets, FORGE_CS_ORDER, FORGE_CS_LABELS, lb, 'lookback', 'forgeCsCopy', forgeCsTemplate);
}

function forgeCsCopy(id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  copyToClipboard(el.textContent).then(function() {
    var orig = btn.textContent;
    btn.textContent = 'Copiado';
    setTimeout(function(){ btn.textContent = orig; }, 1500);
  });
}

function forgeCsClear() {
  document.getElementById('forge-cs-input').value = '';
  document.getElementById('forge-cs-output').innerHTML = '';
  document.getElementById('forge-cs-stats').textContent = 'Introduce IOCs y pulsa Generar CSQL';
}


/* ════════════════════════════════════════════════════
   Render compartido — segmented control + viewer único
   ════════════════════════════════════════════════════ */

function forgeRenderTabs(outputEl, prefix, buckets, order, labels, lb, lbLabel, copyFn, tplFn) {
  var found = order.filter(function(t){ return buckets[t] && buckets[t].length; });
  if (!found.length) { outputEl.innerHTML = ''; return; }
  var tabs = '<div class="forge-tabs">';
  var panes = '<div class="forge-tab-viewer">';
  found.forEach(function(type, i) {
    var active = (i === 0) ? ' active' : '';
    var n = buckets[type].length;
    var id = prefix + '-' + type;
    var q = tplFn(type, buckets[type], lb);
    tabs += '<button class="forge-tab-btn' + active + '" data-type="' + type + '" ' +
      'onclick="forgeTabActivate(this,\'' + type + '\')">' +
      '<span class="forge-tab-name">' + labels[type] + '</span>' +
      '<span class="forge-tab-count">' + n + '</span></button>';
    panes += '<div class="forge-tab-pane' + active + '" data-type="' + type + '">' +
      '<div class="forge-tab-meta">' +
        '<span class="forge-tab-meta-text">' + n + ' ' + labels[type] + ' · ' + lbLabel + ' ' + lb + '</span>' +
        '<button class="forge-copy-btn" onclick="' + copyFn + '(\'' + id + '\',this)">Copiar</button>' +
      '</div>' +
      '<pre id="' + id + '" class="forge-pre">' + esc(q) + '</pre>' +
      '</div>';
  });
  tabs += '</div>';
  panes += '</div>';
  outputEl.innerHTML = tabs + panes;
}

function forgeTabActivate(btn, type) {
  var output = btn.closest('.forge-ws-output');
  if (!output) return;
  output.querySelectorAll('.forge-tab-btn').forEach(function(b) {
    b.classList.toggle('active', b.dataset.type === type);
  });
  output.querySelectorAll('.forge-tab-pane').forEach(function(p) {
    p.classList.toggle('active', p.dataset.type === type);
  });
}


/* ════════════════════════════════════════════════════
   Navegación sidebar — expand/collapse + tool select
   ════════════════════════════════════════════════════ */

/* Reset global — devuelve la app al estado de "primera carga".
   Llamado desde el título "Query Forge" del header. */
function forgeReset() {
  ['forge-input','forge-cs-input','forge-xql-input'].forEach(function(id){
    var el = document.getElementById(id);
    if (el) el.value = '';
  });
  ['forge-output','forge-cs-output','forge-xql-output'].forEach(function(id){
    var el = document.getElementById(id);
    if (el) el.innerHTML = '';
  });
  ['forge-stats','forge-cs-stats','forge-xql-stats'].forEach(function(id){
    var el = document.getElementById(id);
    if (el) el.textContent = '';
  });

  var kqlLb = document.getElementById('forge-lookback');     if (kqlLb) kqlLb.value = '90d';
  var csLb  = document.getElementById('forge-cs-lookback');  if (csLb)  csLb.value  = '7d';
  var xqlLb = document.getElementById('forge-xql-lookback'); if (xqlLb) xqlLb.value = '7d';

  ['kql','cs','xql'].forEach(function(lang){
    var body  = document.getElementById('forge-' + lang + '-body');
    var arrow = document.getElementById('forge-arrow-' + lang);
    if (body)  body.style.display = 'none';
    if (arrow) arrow.style.transform = '';
  });

  forgeShowEmpty();
}

function forgeShowEmpty() {
  _forgeCollapseKql();
  _forgeCollapseXql();
  _forgeCollapseCs();
  var empty = document.getElementById('forge-workspace-empty');
  if (empty) empty.style.display = 'flex';
  var pop = document.getElementById('forge-help-popover');
  if (pop) pop.hidden = true;
}

function forgeToggleHelp(btn) {
  var pop = document.getElementById('forge-help-popover');
  if (!pop) return;
  if (!pop.hidden) { pop.hidden = true; return; }
  var r = btn.getBoundingClientRect();
  pop.style.top  = (r.bottom + 8) + 'px';
  pop.style.left = (r.right - 320) + 'px';
  pop.hidden = false;
  setTimeout(function(){
    document.addEventListener('mousedown', forgeCloseHelp);
  }, 0);
}

function forgeCloseHelp(e) {
  var pop = document.getElementById('forge-help-popover');
  if (!pop || pop.hidden) {
    document.removeEventListener('mousedown', forgeCloseHelp);
    return;
  }
  if (pop.contains(e.target) || (e.target.closest && e.target.closest('.forge-help-btn'))) return;
  pop.hidden = true;
  document.removeEventListener('mousedown', forgeCloseHelp);
}

function forgeToggleLang(lang) {
  var body  = document.getElementById('forge-' + lang + '-body');
  var arrow = document.getElementById('forge-arrow-' + lang);
  if (!body) return;
  var isOpen = body.style.display !== 'none';
  body.style.display = isOpen ? 'none' : 'block';
  if (arrow) arrow.style.transform = isOpen ? '' : 'rotate(90deg)';
}

var _forgeActiveTool    = null;
var _forgeXqlActiveTool = null;
var _forgeCsActiveTool  = null;

function _forgeCollapseXql() {
  if (!_forgeXqlActiveTool) return;
  var body  = document.getElementById('forge-xql-ioc-body');
  var arrow = document.getElementById('forge-arrow-xql-ioc');
  var head  = document.getElementById('forge-xql-ioc-head');
  if (body) body.style.display = 'none';
  if (arrow) arrow.style.transform = '';
  if (head)  head.style.background = 'transparent';
  var ws = document.getElementById('forge-workspace-' + _forgeXqlActiveTool);
  if (ws) ws.classList.remove('is-active');
  _forgeXqlActiveTool = null;
}

function _forgeCollapseKql() {
  if (!_forgeActiveTool) return;
  var body  = document.getElementById('forge-ioc-body');
  var arrow = document.getElementById('forge-arrow-ioc');
  var head  = document.getElementById('forge-ioc-head');
  if (body) body.style.display = 'none';
  if (arrow) arrow.style.transform = '';
  if (head)  head.style.background = 'transparent';
  var ws = document.getElementById('forge-workspace-' + _forgeActiveTool);
  if (ws) ws.classList.remove('is-active');
  _forgeActiveTool = null;
}

function _forgeCollapseCs() {
  if (!_forgeCsActiveTool) return;
  var body  = document.getElementById('forge-cs-ioc-body');
  var arrow = document.getElementById('forge-arrow-cs-ioc');
  var head  = document.getElementById('forge-cs-ioc-head');
  if (body) body.style.display = 'none';
  if (arrow) arrow.style.transform = '';
  if (head)  head.style.background = 'transparent';
  var ws = document.getElementById('forge-workspace-' + _forgeCsActiveTool);
  if (ws) ws.classList.remove('is-active');
  _forgeCsActiveTool = null;
}

function forgeSelectTool(tool) {
  _forgeCollapseXql();
  _forgeCollapseCs();

  var body  = document.getElementById('forge-ioc-body');
  var arrow = document.getElementById('forge-arrow-ioc');
  var head  = document.getElementById('forge-ioc-head');

  if (_forgeActiveTool === tool) {
    _forgeCollapseKql();
    document.getElementById('forge-workspace-empty').style.display = 'flex';
    return;
  }

  document.getElementById('forge-workspace-empty').style.display = 'none';
  var ws = document.getElementById('forge-workspace-' + tool);
  if (ws) ws.classList.add('is-active');

  if (body)  body.style.display = 'flex';
  if (arrow) arrow.style.transform = 'rotate(90deg)';
  if (head)  head.style.background = 'rgba(var(--teal-rgb),.05)';

  _forgeActiveTool = tool;
}

function forgeXqlSelectTool(tool) {
  _forgeCollapseKql();
  _forgeCollapseCs();

  var body  = document.getElementById('forge-xql-ioc-body');
  var arrow = document.getElementById('forge-arrow-xql-ioc');
  var head  = document.getElementById('forge-xql-ioc-head');

  if (_forgeXqlActiveTool === tool) {
    _forgeCollapseXql();
    document.getElementById('forge-workspace-empty').style.display = 'flex';
    return;
  }

  document.getElementById('forge-workspace-empty').style.display = 'none';
  var ws = document.getElementById('forge-workspace-' + tool);
  if (ws) ws.classList.add('is-active');

  if (body)  body.style.display = 'flex';
  if (arrow) arrow.style.transform = 'rotate(90deg)';
  if (head)  head.style.background = 'rgba(var(--teal-rgb),.05)';

  _forgeXqlActiveTool = tool;
}

function forgeCsSelectTool(tool) {
  _forgeCollapseKql();
  _forgeCollapseXql();

  var body  = document.getElementById('forge-cs-ioc-body');
  var arrow = document.getElementById('forge-arrow-cs-ioc');
  var head  = document.getElementById('forge-cs-ioc-head');

  if (_forgeCsActiveTool === tool) {
    _forgeCollapseCs();
    document.getElementById('forge-workspace-empty').style.display = 'flex';
    return;
  }

  document.getElementById('forge-workspace-empty').style.display = 'none';
  var ws = document.getElementById('forge-workspace-' + tool);
  if (ws) ws.classList.add('is-active');

  if (body)  body.style.display = 'flex';
  if (arrow) arrow.style.transform = 'rotate(90deg)';
  if (head)  head.style.background = 'rgba(var(--teal-rgb),.05)';

  _forgeCsActiveTool = tool;
}
