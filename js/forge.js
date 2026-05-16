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
      return 'setTimeInterval(start=' + lb + ')\n' +
        'LET DomainsIOC = array(\n' + arr + '\n);\n\n' +
        '#event_simpleName in ("DnsRequest", "HttpRequest")\n' +
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
      return 'setTimeInterval(start=' + lb + ')\n' +
        'LET IpsIOC = array(\n' + arr + '\n);\n\n' +
        '#event_simpleName in ("NetworkConnect", "NetworkConnectIP4")\n' +
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
      return 'setTimeInterval(start=' + lb + ')\n' +
        'LET HashesSHA256 = array(\n' + arr + '\n);\n\n' +
        '#event_simpleName in ("ProcessRollup2", "FileWritten", "FileOpenInfo")\n' +
        '| event_platform = "Win"\n' +
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
      return 'setTimeInterval(start=' + lb + ')\n' +
        'LET HashesMD5 = array(\n' + arr + '\n);\n\n' +
        '#event_simpleName in ("ProcessRollup2", "FileWritten", "FileOpenInfo")\n' +
        '| event_platform = "Win"\n' +
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
  ['forge-output','forge-cs-output','forge-xql-output','forge-ioa-output'].forEach(function(id){
    var el = document.getElementById(id);
    if (el) el.innerHTML = '';
  });
  ['forge-stats','forge-cs-stats','forge-xql-stats','forge-ioa-stats'].forEach(function(id){
    var el = document.getElementById(id);
    if (el) el.textContent = '';
  });
  if (typeof _forgeIoaClearInputs === 'function') _forgeIoaClearInputs();

  var kqlLb = document.getElementById('forge-lookback');     if (kqlLb) kqlLb.value = '90d';
  var csLb  = document.getElementById('forge-cs-lookback');  if (csLb)  csLb.value  = '7d';
  var xqlLb = document.getElementById('forge-xql-lookback'); if (xqlLb) xqlLb.value = '7d';
  var ioaLb = document.getElementById('forge-ioa-lookback'); if (ioaLb) ioaLb.value = '90d';

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

function _forgeKqlSub(tool) {
  // 'kql-ioc' -> 'ioc' · 'kql-ioa' -> 'ioa'
  return tool.split('-')[1];
}

function _forgeCollapseKql() {
  if (!_forgeActiveTool) return;
  var sub = _forgeKqlSub(_forgeActiveTool);
  var body  = document.getElementById('forge-' + sub + '-body');
  var arrow = document.getElementById('forge-arrow-' + sub);
  var head  = document.getElementById('forge-' + sub + '-head');
  if (body) body.style.display = 'none';
  if (arrow) arrow.style.transform = '';
  if (head)  head.style.background = 'transparent';
  var ws = document.getElementById('forge-workspace-' + _forgeActiveTool);
  if (ws) ws.classList.remove('is-active');
  _forgeActiveTool = null;
}

function _forgeCollapseCs() {
  if (!_forgeCsActiveTool) return;
  var t = _forgeCsActiveTool;
  var body  = document.getElementById('forge-' + t + '-body');
  var arrow = document.getElementById('forge-arrow-' + t);
  var head  = document.getElementById('forge-' + t + '-head');
  if (body) body.style.display = 'none';
  if (arrow) arrow.style.transform = '';
  if (head)  head.style.background = 'transparent';
  var ws = document.getElementById('forge-workspace-' + t);
  if (ws) ws.classList.remove('is-active');
  _forgeCsActiveTool = null;
}

function forgeSelectTool(tool) {
  _forgeCollapseXql();
  _forgeCollapseCs();

  if (_forgeActiveTool === tool) {
    _forgeCollapseKql();
    document.getElementById('forge-workspace-empty').style.display = 'flex';
    return;
  }

  // Si hay otro sub-tool KQL abierto, ciérralo antes de abrir el nuevo
  if (_forgeActiveTool) _forgeCollapseKql();

  var sub = _forgeKqlSub(tool);
  var body  = document.getElementById('forge-' + sub + '-body');
  var arrow = document.getElementById('forge-arrow-' + sub);
  var head  = document.getElementById('forge-' + sub + '-head');

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

/* ════════════════════════════════════════════════════
   KQL — IOA Hunter (multi-tabla, 3 capas)
   ════════════════════════════════════════════════════ */

var IOA_PS_VARIANTS  = ['powershell.exe','powershell','pwsh.exe','pwsh','powershell_ise.exe'];
var IOA_PS_CANONICAL = ['powershell.exe','powershell_ise.exe','pwsh.exe','syncappvpublishingserver.exe'];

var IOA_TABLES = {
  process: {
    label: 'Proceso',
    table: 'DeviceProcessEvents',
    formId: 'forge-ioa-form-process',
    fields: [
      { id:'grandparent',    input:'ioa-grandparent',    kql:'InitiatingProcessParentFileName', kind:'name',    listName:'Abuelos'   },
      { id:'parent',         input:'ioa-parent',         kql:'InitiatingProcessFileName',       kind:'name',    listName:'Padres'    },
      { id:'parent_cmdline', input:'ioa-parent-cmdline', kql:'InitiatingProcessCommandLine',    kind:'cmdline', listName:'CmdlinePadre' },
      { id:'process',        input:'ioa-process',        kql:'FileName',                        kind:'name',    listName:'Procesos'  },
      { id:'cmdline',        input:'ioa-cmdline',        kql:'ProcessCommandLine',              kind:'cmdline', listName:'Cmdline'   },
      { id:'user',           input:'ioa-user',           kql:'AccountName',                     kind:'name',    listName:'Usuarios'  },
      { id:'path',           input:'ioa-path',           kql:'FolderPath',                      kind:'path',    listName:'Rutas'     }
    ],
    psFields: ['grandparent','parent','process'],
    project: [
      'Timestamp','DeviceName','InitiatingProcessParentFileName',
      'InitiatingProcessFileName','InitiatingProcessCommandLine',
      'FileName','ProcessCommandLine','AccountName','FolderPath'
    ],
    projectGroups: [3, 2, 4]
  },
  network: {
    label: 'Red',
    table: 'DeviceNetworkEvents',
    formId: 'forge-ioa-form-network',
    fields: [
      { id:'remote_ip',   input:'ioa-net-remote-ip',   kql:'RemoteIP',                     kind:'name',    listName:'IPs'       },
      { id:'remote_url',  input:'ioa-net-remote-url',  kql:'RemoteUrl',                    kind:'cmdline', listName:'URLs'      },
      { id:'remote_port', input:'ioa-net-remote-port', kql:'RemotePort',                   kind:'int',     listName:'Puertos'   },
      { id:'process',     input:'ioa-net-process',     kql:'InitiatingProcessFileName',    kind:'name',    listName:'Procesos'  },
      { id:'cmdline',     input:'ioa-net-cmdline',     kql:'InitiatingProcessCommandLine', kind:'cmdline', listName:'Cmdline'   },
      { id:'user',        input:'ioa-net-user',        kql:'InitiatingProcessAccountName', kind:'name',    listName:'Usuarios'  }
    ],
    psFields: ['process'],
    project: [
      'Timestamp','DeviceName','ActionType','RemoteIP','RemoteUrl',
      'RemotePort','Protocol','InitiatingProcessFileName',
      'InitiatingProcessCommandLine','InitiatingProcessAccountName'
    ],
    projectGroups: [3, 4, 3]
  },
  file: {
    label: 'Fichero',
    table: 'DeviceFileEvents',
    formId: 'forge-ioa-form-file',
    fields: [
      { id:'action',   input:'ioa-file-action',   kql:'ActionType',                   kind:'multi',   listName:'Acciones' },
      { id:'filename', input:'ioa-file-filename', kql:'FileName',                     kind:'name',    listName:'Archivos' },
      { id:'path',     input:'ioa-file-path',     kql:'FolderPath',                   kind:'path',    listName:'Rutas'    },
      { id:'sha256',   input:'ioa-file-sha256',   kql:'SHA256',                       kind:'name',    listName:'Hashes'   },
      { id:'process',  input:'ioa-file-process',  kql:'InitiatingProcessFileName',    kind:'name',    listName:'Procesos' },
      { id:'cmdline',  input:'ioa-file-cmdline',  kql:'InitiatingProcessCommandLine', kind:'cmdline', listName:'Cmdline'  },
      { id:'user',     input:'ioa-file-user',     kql:'InitiatingProcessAccountName', kind:'name',    listName:'Usuarios' }
    ],
    actionTypes: ['FileCreated','FileModified','FileRenamed','FileDeleted'],
    psFields: ['process'],
    project: [
      'Timestamp','DeviceName','ActionType',
      'FileName','FolderPath','SHA256',
      'InitiatingProcessFileName','InitiatingProcessCommandLine','InitiatingProcessAccountName'
    ],
    projectGroups: [3, 3, 3]
  },
  registry: {
    label: 'Registro',
    table: 'DeviceRegistryEvents',
    formId: 'forge-ioa-form-registry',
    fields: [
      { id:'action',     input:'ioa-reg-action',     kql:'ActionType',                   kind:'multi',   listName:'Acciones' },
      { id:'key',        input:'ioa-reg-key',        kql:'RegistryKey',                  kind:'path',    listName:'Claves'   },
      { id:'value_name', input:'ioa-reg-value-name', kql:'RegistryValueName',            kind:'name',    listName:'Nombres'  },
      { id:'value_data', input:'ioa-reg-value-data', kql:'RegistryValueData',            kind:'cmdline', listName:'Datos'    },
      { id:'process',    input:'ioa-reg-process',    kql:'InitiatingProcessFileName',    kind:'name',    listName:'Procesos' },
      { id:'cmdline',    input:'ioa-reg-cmdline',    kql:'InitiatingProcessCommandLine', kind:'cmdline', listName:'Cmdline'  },
      { id:'user',       input:'ioa-reg-user',       kql:'InitiatingProcessAccountName', kind:'name',    listName:'Usuarios' }
    ],
    actionTypes: ['RegistryKeyCreated','RegistryKeyDeleted','RegistryKeyRenamed','RegistryValueSet','RegistryValueDeleted'],
    psFields: ['process'],
    project: [
      'Timestamp','DeviceName','ActionType',
      'RegistryKey','RegistryValueName','RegistryValueData',
      'InitiatingProcessFileName','InitiatingProcessCommandLine','InitiatingProcessAccountName'
    ],
    projectGroups: [3, 3, 3]
  }
};


var _forgeIoaActive = 'process';
var _forgeIoaModes = {};  // inputId → 'any'|'all' para campos cmdline
var _forgeIoaJoins = {};  // inputId → 'or' (ausente = 'and', por defecto)


/* ── Capa 1→2: leer formulario y construir modelo ─────────── */

function _forgeIoaGetTable() {
  return IOA_TABLES[_forgeIoaActive] || IOA_TABLES.process;
}

/* Parser tolerante a comillas: separa por comas excepto si están dentro de "...".
   - Token entrecomillado → se preserva tal cual (espacios y comas literales).
   - Token sin comillas → trim normal como antes.
   El espacio entre la coma y la comilla de apertura se descarta. */
function _forgeIoaParseValues(input) {
  if (!input) return [];
  var values = [];
  var unquoted = '';
  var quoted = '';
  var inQuote = false;
  var hasQuote = false;
  function flush() {
    var v = hasQuote ? quoted : unquoted.trim();
    if (v.length > 0) values.push(v);
    unquoted = ''; quoted = ''; hasQuote = false;
  }
  for (var i = 0; i < input.length; i++) {
    var ch = input[i];
    if (ch === '"') { inQuote = !inQuote; hasQuote = true; continue; }
    if (ch === ',' && !inQuote) { flush(); continue; }
    if (inQuote) quoted += ch;
    else unquoted += ch;
  }
  flush();
  return values;
}

function _forgeIoaReadModel() {
  var tbl = _forgeIoaGetTable();
  var model = { table: tbl, lookback:'90d', filters:{}, lists:{}, modes:{}, joins:{}, meta:{} };
  var lb = document.getElementById('forge-ioa-lookback');
  if (lb && lb.value) model.lookback = lb.value;

  tbl.fields.forEach(function(f) {
    var el = document.getElementById(f.input);
    if (!el) { model.filters[f.id] = []; return; }
    var values;
    if (f.kind === 'multi') {
      values = Array.prototype.map.call(
        el.querySelectorAll('.forge-ioa-chip.active'),
        function(b){ return b.dataset.value; }
      );
    } else {
      values = _forgeIoaParseValues(el.value);
      if (f.kind === 'name') {
        var seen = {};
        values = values.filter(function(v){
          var k = v.toLowerCase();
          if (seen[k]) return false;
          seen[k] = true;
          return true;
        });
      }
    }
    model.filters[f.id] = values;
    if (f.kind === 'cmdline') {
      model.modes[f.id] = _forgeIoaModes[f.input] === 'all' ? 'all' : 'any';
    }
    model.joins[f.id] = _forgeIoaJoins[f.input] === 'or' ? 'or' : 'and';
  });

  ['hypothesis','mitre-tactic','mitre-technique','fp','noise'].forEach(function(key) {
    var el = document.getElementById('ioa-' + key);
    if (el) model.meta[key.replace('-','_')] = el.value.trim();
  });
  return model;
}

function _forgeIoaHasAnyFilter(model) {
  return model.table.fields.some(function(f){ return model.filters[f.id].length > 0; });
}

function _forgeIoaNormalizePowerShell(model) {
  model.table.psFields.forEach(function(fieldId) {
    var values = model.filters[fieldId];
    if (!values || values.length !== 1) return;
    if (IOA_PS_VARIANTS.indexOf(values[0].toLowerCase()) === -1) return;
    model.filters[fieldId] = IOA_PS_CANONICAL.slice();
    model.lists[fieldId] = 'PowerShell';
  });
}


/* ── Capa 3: renderer KQL ─────────────────────────────────── */

function _forgeIoaListName(field, model) {
  if (model.lists[field.id]) return model.lists[field.id];
  return field.listName;
}

function _forgeIoaValueList(values) {
  return values.map(function(v){ return '"' + v.replace(/"/g,'\\"') + '"'; }).join(', ');
}

function _forgeIoaBuildLets(model) {
  var lines = [];
  model.table.fields.forEach(function(f) {
    var values = model.filters[f.id];
    if (values.length < 2) return;
    if (f.kind === 'multi') return;  // ActionType y similares se rinden inline
    var name = _forgeIoaListName(f, model);
    var vals = f.kind === 'int' ? values.join(', ') : _forgeIoaValueList(values);
    lines.push('let ' + name + ' = dynamic([' + vals + ']);');
  });
  return lines;
}

function _forgeIoaBuildClause(f, values, model) {
  var multi = values.length > 1;
  var listName = _forgeIoaListName(f, model);
  var val = values[0];

  if (f.kind === 'name') {
    return multi
      ? f.kql + ' in~ (' + listName + ')'
      : f.kql + ' =~ "' + val + '"';
  }
  if (f.kind === 'multi') {
    // Lista cerrada de valores (e.g. ActionType). Inline, sin let.
    return multi
      ? f.kql + ' in~ (' + _forgeIoaValueList(values) + ')'
      : f.kql + ' =~ "' + val + '"';
  }
  if (f.kind === 'int') {
    return multi
      ? f.kql + ' in (' + listName + ')'
      : f.kql + ' == ' + val;
  }
  if (f.kind === 'cmdline') {
    if (multi) {
      var op = model.modes[f.id] === 'all' ? 'has_all' : 'has_any';
      return f.kql + ' ' + op + ' (' + listName + ')';
    }
    return f.kql + ' has "' + val + '"';
  }
  if (f.kind === 'path') {
    if (multi) {
      var ors = values.map(function(v){
        return f.kql + ' startswith "' + v.replace(/\\/g,'\\\\') + '"';
      }).join(' or ');
      return '(' + ors + ')';
    }
    return f.kql + ' startswith "' + val.replace(/\\/g,'\\\\') + '"';
  }
  return null;
}

function _forgeIoaBuildWheres(model) {
  var andLines = [];
  var orClauses = [];

  model.table.fields.forEach(function(f) {
    var values = model.filters[f.id];
    if (!values.length) return;
    var clause = _forgeIoaBuildClause(f, values, model);
    if (!clause) return;
    if (model.joins[f.id] === 'or') {
      orClauses.push(clause);
    } else {
      andLines.push('| where ' + clause);
    }
  });

  // Bloque OR (si hay 2+, se agrupa; si solo hay 1, se trata como AND)
  if (orClauses.length === 1) {
    andLines.push('| where ' + orClauses[0]);
  } else if (orClauses.length > 1) {
    var indent = '      ';  // alinea 'or' bajo '(' tras '| where '
    var orBlock = '| where (' + orClauses[0] + '\n' +
      orClauses.slice(1).map(function(c){ return indent + 'or ' + c; }).join('\n') + ')';
    andLines.push(orBlock);
  }
  return andLines;
}

function _forgeIoaBuildHeader(model) {
  var hasAny = !!(model.meta.hypothesis || model.meta.mitre_tactic ||
                  model.meta.mitre_technique || model.meta.fp || model.meta.noise);
  if (!hasAny) return '';

  var SEP = '//═══════════════════════════════════════════════════════════════';
  var lines = [SEP];
  if (model.meta.hypothesis) lines.push('// NOMBRE: ' + model.meta.hypothesis);
  if (model.meta.mitre_tactic || model.meta.mitre_technique) {
    var parts = [];
    if (model.meta.mitre_tactic)    parts.push(model.meta.mitre_tactic);
    if (model.meta.mitre_technique) parts.push(model.meta.mitre_technique);
    lines.push('// MITRE ATT&CK: ' + parts.join(' - '));
  }
  lines.push('// TABLA: ' + model.table.table);
  if (model.meta.fp) lines.push('// FALSOS POSITIVOS: ' + model.meta.fp);
  if (model.meta.noise) lines.push('// NIVEL DE RUIDO: ' + model.meta.noise);
  lines.push(SEP);
  return lines.join('\n');
}

function _forgeIoaBuildProject(model) {
  // 18 espacios = alineado con el primer campo después de "| project-reorder "
  var indent = '                  ';
  var fields = model.table.project;
  var groups = model.table.projectGroups;
  var lines = [];
  var pos = 0;
  groups.forEach(function(n, i) {
    var chunk = fields.slice(pos, pos + n).join(', ');
    var prefix = i === 0 ? '| project-reorder ' : indent;
    var suffix = (pos + n < fields.length) ? ',' : '';
    lines.push(prefix + chunk + suffix);
    pos += n;
  });
  return lines.join('\n');
}

function _forgeIoaRenderKql(model) {
  var header  = _forgeIoaBuildHeader(model);
  var lets    = _forgeIoaBuildLets(model);
  var wheres  = _forgeIoaBuildWheres(model);
  var project = _forgeIoaBuildProject(model);

  var letBlock = ['let lookback = ' + model.lookback + ';'].concat(lets).join('\n');
  var body = model.table.table + '\n| where Timestamp >= ago(lookback)\n' +
             wheres.join('\n') + '\n' +
             project + '\n' +
             '| order by Timestamp desc';

  var queryBlock = letBlock + '\n' + body;
  return header ? header + '\n\n' + queryBlock : queryBlock;
}


/* ── Controlador: generar / limpiar / copiar / display ────── */

function forgeIoaGenerate() {
  var model = _forgeIoaReadModel();

  if (!_forgeIoaHasAnyFilter(model)) {
    var statsEl = document.getElementById('forge-ioa-stats');
    var outEl   = document.getElementById('forge-ioa-output');
    if (statsEl) statsEl.textContent = 'Rellena al menos un campo de comportamiento.';
    if (outEl)   outEl.innerHTML = '';
    if (typeof toast === 'function') toast('Rellena al menos un campo de comportamiento', 'err');
    return;
  }

  _forgeIoaNormalizePowerShell(model);
  var query = _forgeIoaRenderKql(model);
  _forgeIoaDisplay(query, model);
}

function _forgeIoaDisplay(query, model) {
  var filterCount = 0;
  model.table.fields.forEach(function(f){ if (model.filters[f.id].length) filterCount++; });
  var statsEl = document.getElementById('forge-ioa-stats');
  var outEl   = document.getElementById('forge-ioa-output');
  if (statsEl) {
    statsEl.innerHTML = '<span class="forge-count">' + filterCount + ' filtro' +
      (filterCount === 1 ? '' : 's') + '</span>' +
      ' <span class="forge-muted"> | tabla: ' + model.table.table + '</span>' +
      ' <span class="forge-muted"> | lookback: ' + model.lookback + '</span>';
  }
  if (outEl) {
    outEl.innerHTML =
      '<div class="forge-tab-viewer"><div class="forge-tab-pane active">' +
        '<div class="forge-tab-meta">' +
          '<span class="forge-tab-meta-text">Query · ' + model.table.table + '</span>' +
          '<button class="forge-copy-btn" onclick="forgeIoaCopy(\'forge-ioa-pre\',this)">Copiar</button>' +
        '</div>' +
        '<pre id="forge-ioa-pre" class="forge-pre">' + esc(query) + '</pre>' +
      '</div></div>';
  }
}

function forgeIoaCopy(id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  copyToClipboard(el.textContent).then(function(){
    var orig = btn.textContent;
    btn.textContent = 'Copiado';
    setTimeout(function(){ btn.textContent = orig; }, 1500);
  });
}

function _forgeIoaClearInputs() {
  Object.keys(IOA_TABLES).forEach(function(key){
    IOA_TABLES[key].fields.forEach(function(f) {
      var el = document.getElementById(f.input);
      if (!el) return;
      if (f.kind === 'multi') {
        el.querySelectorAll('.forge-ioa-chip.active').forEach(function(b){
          b.classList.remove('active');
        });
      } else {
        el.value = '';
      }
    });
  });
  ['hypothesis','mitre-tactic','mitre-technique','fp'].forEach(function(k){
    var el = document.getElementById('ioa-' + k);
    if (el) el.value = '';
  });
  var noise = document.getElementById('ioa-noise');
  if (noise) noise.value = '';
  _forgeIoaModes = {};
  _forgeIoaJoins = {};
  _forgeIoaSyncAllToggles();
  _forgeIoaSyncAllJoinToggles();
}

function forgeIoaClear() {
  _forgeIoaClearInputs();
  var statsEl = document.getElementById('forge-ioa-stats');
  var outEl   = document.getElementById('forge-ioa-output');
  if (statsEl) statsEl.textContent = '';
  if (outEl)   outEl.innerHTML = '';
}


/* ── Selector de tabla (segmented control en header) ──────── */

function forgeIoaSelectTable(table) {
  if (!IOA_TABLES[table]) return;
  _forgeIoaActive = table;

  document.querySelectorAll('#forge-workspace-kql-ioa .forge-ioa-table-btn').forEach(function(b){
    b.classList.toggle('active', b.dataset.table === table);
  });
  Object.keys(IOA_TABLES).forEach(function(key){
    var form = document.getElementById(IOA_TABLES[key].formId);
    if (form) form.style.display = (key === table) ? '' : 'none';
  });

  var outEl = document.getElementById('forge-ioa-output');
  var statsEl = document.getElementById('forge-ioa-stats');
  if (outEl)   outEl.innerHTML = '';
  if (statsEl) statsEl.textContent = '';

  _forgeIoaSyncAllToggles();
  _forgeIoaSyncAllJoinToggles();
}


/* ── Toggle Cualquiera/Todos en campos cmdline ────────────── */

function _forgeIoaSyncToggle(inputId) {
  var input = document.getElementById(inputId);
  if (!input) return;
  var toggle = document.querySelector('.forge-ioa-mode[data-target="' + inputId + '"]');
  if (!toggle) return;
  var values = _forgeIoaParseValues(input.value);
  var visible = values.length >= 2;
  toggle.style.display = visible ? '' : 'none';
  var mode = _forgeIoaModes[inputId] || 'any';
  toggle.querySelectorAll('.forge-ioa-mode-btn').forEach(function(b){
    b.classList.toggle('active', b.dataset.mode === mode);
  });
}

function _forgeIoaSyncAllToggles() {
  document.querySelectorAll('.forge-ioa-mode').forEach(function(el){
    var inputId = el.dataset.target;
    if (inputId) _forgeIoaSyncToggle(inputId);
  });
}

function forgeIoaSetMode(inputId, mode) {
  _forgeIoaModes[inputId] = mode;
  _forgeIoaSyncToggle(inputId);
}

function forgeIoaBindToggles() {
  document.querySelectorAll('.forge-ioa-mode').forEach(function(el){
    var inputId = el.dataset.target;
    var input = document.getElementById(inputId);
    if (input) {
      input.addEventListener('input', function(){ _forgeIoaSyncToggle(inputId); });
    }
    el.querySelectorAll('.forge-ioa-mode-btn').forEach(function(btn){
      btn.addEventListener('click', function(){
        forgeIoaSetMode(inputId, btn.dataset.mode);
      });
    });
  });
  _forgeIoaSyncAllToggles();
  forgeIoaBindJoinToggles();
  forgeIoaBindChips();
}

/* ── Chips multi-select (ActionType en File/Registry) ─────── */

function forgeIoaBindChips() {
  document.querySelectorAll('.forge-ioa-chips .forge-ioa-chip').forEach(function(btn){
    btn.addEventListener('click', function(){
      btn.classList.toggle('active');
    });
  });
}

/* ── Toggle Y/O (combinar campo a nivel de query) ─────────── */

function _forgeIoaSyncJoinToggle(inputId) {
  var toggle = document.querySelector('.forge-ioa-join[data-target="' + inputId + '"]');
  if (!toggle) return;
  var join = _forgeIoaJoins[inputId] === 'or' ? 'or' : 'and';
  toggle.querySelectorAll('.forge-ioa-join-btn').forEach(function(b){
    b.classList.toggle('active', b.dataset.join === join);
  });
}

function _forgeIoaSyncAllJoinToggles() {
  document.querySelectorAll('.forge-ioa-join').forEach(function(el){
    var inputId = el.dataset.target;
    if (inputId) _forgeIoaSyncJoinToggle(inputId);
  });
}

function forgeIoaSetJoin(inputId, join) {
  if (join === 'or') _forgeIoaJoins[inputId] = 'or';
  else delete _forgeIoaJoins[inputId];
  _forgeIoaSyncJoinToggle(inputId);
}

function forgeIoaBindJoinToggles() {
  document.querySelectorAll('.forge-ioa-join').forEach(function(el){
    var inputId = el.dataset.target;
    el.querySelectorAll('.forge-ioa-join-btn').forEach(function(btn){
      btn.addEventListener('click', function(){
        forgeIoaSetJoin(inputId, btn.dataset.join);
      });
    });
  });
  _forgeIoaSyncAllJoinToggles();
}


/* ── Help popover ─────────────────────────────────────────── */

function forgeIoaToggleHelp(btn) {
  var pop = document.getElementById('forge-ioa-help-popover');
  if (!pop) return;
  if (!pop.hidden) { pop.hidden = true; return; }
  var r = btn.getBoundingClientRect();
  pop.style.top  = (r.bottom + 8) + 'px';
  pop.style.left = (r.right - 320) + 'px';
  pop.hidden = false;
  setTimeout(function(){
    document.addEventListener('mousedown', forgeIoaCloseHelp);
  }, 0);
}

function forgeIoaCloseHelp(e) {
  var pop = document.getElementById('forge-ioa-help-popover');
  if (!pop || pop.hidden) {
    document.removeEventListener('mousedown', forgeIoaCloseHelp);
    return;
  }
  if (pop.contains(e.target) || (e.target.closest && e.target.closest('.forge-help-btn'))) return;
  pop.hidden = true;
  document.removeEventListener('mousedown', forgeIoaCloseHelp);
}


/* ════════════════════════════════════════════════════
   LQL — IOA Hunter (CrowdStrike Falcon LogScale, 3 capas)
   ════════════════════════════════════════════════════
   Comparte modelo (Capa 2), parser de comillas y globals
   _forgeIoaModes / _forgeIoaJoins con el IOA Hunter de KQL.
   Solo cambia la Capa 3: regex case-insensitive, sin operadores
   discretos. Lookback se rinde como setTimeInterval(start=Xd). */

var IOA_LQL = {
  eventType: 'ProcessRollup2',
  fields: [
    { id:'parent',  input:'ioa-lql-parent',  kql:'ParentBaseFileName', kind:'lql-exact' },
    { id:'process', input:'ioa-lql-process', kql:'ImageFileName',      kind:'lql-image' },
    { id:'cmdline', input:'ioa-lql-cmdline', kql:'CommandLine',        kind:'lql-cmdline' },
    { id:'user',    input:'ioa-lql-user',    kql:'UserName',           kind:'lql-exact' },
    { id:'path',    input:'ioa-lql-path',    kql:'ImageFileName',      kind:'lql-path' }
  ],
  selectFields: [
    '@timestamp','aid','ComputerName','UserName',
    'ParentBaseFileName','ImageFileName','CommandLine','SHA256HashData'
  ]
};


/* ── Capa 1→2: leer formulario y construir modelo ─────────── */

function _forgeIoaLqlReadModel() {
  var model = {
    eventType: IOA_LQL.eventType,
    lookback:  '7d',
    platform:  'Win',
    filters:{}, modes:{}, joins:{}, meta:{}
  };
  var lb = document.getElementById('forge-ioa-lql-lookback');
  if (lb && lb.value) model.lookback = lb.value;
  var pf = document.getElementById('forge-ioa-lql-platform');
  if (pf && pf.value) model.platform = pf.value;

  IOA_LQL.fields.forEach(function(f) {
    var el = document.getElementById(f.input);
    if (!el) { model.filters[f.id] = []; return; }
    var values = _forgeIoaParseValues(el.value);
    var seen = {};
    values = values.filter(function(v){
      var k = v.toLowerCase();
      if (seen[k]) return false;
      seen[k] = true;
      return true;
    });
    model.filters[f.id] = values;
    if (f.kind === 'lql-cmdline') {
      model.modes[f.id] = _forgeIoaModes[f.input] === 'all' ? 'all' : 'any';
    }
    model.joins[f.id] = _forgeIoaJoins[f.input] === 'or' ? 'or' : 'and';
  });

  ['hypothesis','mitre-tactic','mitre-technique','description','fp','noise'].forEach(function(key) {
    var el = document.getElementById('ioa-lql-' + key);
    if (el) model.meta[key.replace(/-/g,'_')] = el.value.trim();
  });
  return model;
}

function _forgeIoaLqlHasAnyFilter(model) {
  return IOA_LQL.fields.some(function(f){
    return model.filters[f.id] && model.filters[f.id].length > 0;
  });
}


/* ── Capa 3: renderer LQL ─────────────────────────────────── */

/* Escapado para uso dentro de regex literal /…/i:
   - barra invertida \  → \\\\  (en LQL el string regex usa \\ como literal de \)
   - punto . y resto de metachars → escapados
   - barra / cierra la regex literal → escapada */
function _forgeIoaLqlEscapeRegex(v) {
  return v.replace(/\\/g, '\\\\')
          .replace(/\//g, '\\/')
          .replace(/[.*+?^${}()|[\]]/g, '\\$&');
}

function _forgeIoaLqlBuildClause(f, values, model) {
  var multi = values.length > 1;
  var esc = values.map(_forgeIoaLqlEscapeRegex);

  if (f.kind === 'lql-exact') {
    // ParentBaseFileName, UserName: nombre completo con anclas ^$
    var inner = multi ? '(' + esc.join('|') + ')' : esc[0];
    return f.kql + '=/^' + inner + '$/i';
  }
  if (f.kind === 'lql-image') {
    // ImageFileName (ruta completa): ancla \binario al final
    var inner2 = multi ? '(' + esc.join('|') + ')' : esc[0];
    return f.kql + '=/\\\\' + inner2 + '$/i';
  }
  if (f.kind === 'lql-cmdline') {
    // CommandLine: contains. 'any' = alternancia; 'all' = N filtros separados con AND.
    if (!multi) return f.kql + '=/' + esc[0] + '/i';
    if (model.modes[f.id] === 'all') {
      return esc.map(function(v){ return f.kql + '=/' + v + '/i'; }).join('\n| ');
    }
    return f.kql + '=/' + esc.join('|') + '/i';
  }
  if (f.kind === 'lql-path') {
    // ImageFileName como subcadena (sin anclas). Multi = alternancia.
    if (!multi) return f.kql + '=/' + esc[0] + '/i';
    return f.kql + '=/' + esc.join('|') + '/i';
  }
  return null;
}

function _forgeIoaLqlBuildWheres(model) {
  var andLines = [];
  var orClauses = [];

  IOA_LQL.fields.forEach(function(f) {
    var values = model.filters[f.id];
    if (!values || !values.length) return;
    var clause = _forgeIoaLqlBuildClause(f, values, model);
    if (!clause) return;
    if (model.joins[f.id] === 'or') {
      orClauses.push(clause);
    } else {
      andLines.push('| ' + clause);
    }
  });

  // Bloque OR (2+ campos → un solo | (a or b or c); 1 → trata como AND)
  if (orClauses.length === 1) {
    andLines.push('| ' + orClauses[0]);
  } else if (orClauses.length > 1) {
    var indent = '   ';  // alinea 'or' bajo '(' tras '| '
    var orBlock = '| (' + orClauses[0] + '\n' +
      orClauses.slice(1).map(function(c){ return indent + 'or ' + c; }).join('\n') + ')';
    andLines.push(orBlock);
  }
  return andLines;
}

function _forgeIoaLqlBuildHeader(model) {
  var hasAny = !!(model.meta.hypothesis || model.meta.mitre_tactic ||
                  model.meta.mitre_technique || model.meta.description ||
                  model.meta.fp || model.meta.noise);
  if (!hasAny) return '';

  var SEP = '// ═══════════════════════════════════════════════════════════════';
  var lines = [SEP];
  if (model.meta.hypothesis) lines.push('// NOMBRE: ' + model.meta.hypothesis);
  if (model.meta.mitre_tactic || model.meta.mitre_technique) {
    var parts = [];
    if (model.meta.mitre_tactic)    parts.push(model.meta.mitre_tactic);
    if (model.meta.mitre_technique) parts.push(model.meta.mitre_technique);
    lines.push('// MITRE ATT&CK: ' + parts.join(' - '));
  }
  lines.push('// EVENT TYPE: ' + model.eventType);
  if (model.meta.description) lines.push('// DESCRIPCIÓN: ' + model.meta.description);
  if (model.meta.fp)           lines.push('// FALSOS POSITIVOS: ' + model.meta.fp);
  if (model.meta.noise)        lines.push('// NIVEL DE RUIDO: ' + model.meta.noise);
  lines.push(SEP);
  return lines.join('\n');
}

function _forgeIoaLqlBuildSelect() {
  // Mismo formato que los ejemplos del IOC Hunter CS — split en 2 líneas balanceadas.
  var fields = IOA_LQL.selectFields;
  var half = Math.ceil(fields.length / 2);
  var line1 = fields.slice(0, half).join(', ');
  var line2 = fields.slice(half).join(', ');
  return '| select([' + line1 + ',\n          ' + line2 + '])';
}

function _forgeIoaLqlRender(model) {
  var header = _forgeIoaLqlBuildHeader(model);
  var wheres = _forgeIoaLqlBuildWheres(model);
  var sel    = _forgeIoaLqlBuildSelect();

  var lines = [];
  lines.push('setTimeInterval(start=' + model.lookback + ')');
  lines.push('#event_simpleName=' + model.eventType);
  if (model.platform && model.platform !== 'all') {
    lines.push('| event_platform=' + model.platform);
  }
  wheres.forEach(function(w){ lines.push(w); });
  lines.push(sel);

  var query = lines.join('\n');
  return header ? header + '\n\n' + query : query;
}


/* ── Controlador: generar / limpiar / copiar / display ────── */

function forgeIoaLqlGenerate() {
  var model = _forgeIoaLqlReadModel();
  if (!_forgeIoaLqlHasAnyFilter(model)) {
    var statsEl = document.getElementById('forge-ioa-lql-stats');
    var outEl   = document.getElementById('forge-ioa-lql-output');
    if (statsEl) statsEl.textContent = 'Rellena al menos un campo de comportamiento.';
    if (outEl)   outEl.innerHTML = '';
    if (typeof toast === 'function') toast('Rellena al menos un campo de comportamiento', 'err');
    return;
  }
  var query = _forgeIoaLqlRender(model);
  _forgeIoaLqlDisplay(query, model);
}

function _forgeIoaLqlDisplay(query, model) {
  var filterCount = 0;
  IOA_LQL.fields.forEach(function(f){
    if (model.filters[f.id] && model.filters[f.id].length) filterCount++;
  });
  var statsEl = document.getElementById('forge-ioa-lql-stats');
  var outEl   = document.getElementById('forge-ioa-lql-output');
  if (statsEl) {
    statsEl.innerHTML = '<span class="forge-count">' + filterCount + ' filtro' +
      (filterCount === 1 ? '' : 's') + '</span>' +
      ' <span class="forge-muted"> | event: ' + model.eventType + '</span>' +
      ' <span class="forge-muted"> | plataforma: ' + (model.platform === 'all' ? 'todas' : model.platform) + '</span>' +
      ' <span class="forge-muted"> | lookback: ' + model.lookback + '</span>';
  }
  if (outEl) {
    outEl.innerHTML =
      '<div class="forge-tab-viewer"><div class="forge-tab-pane active">' +
        '<div class="forge-tab-meta">' +
          '<span class="forge-tab-meta-text">Query · ' + model.eventType + '</span>' +
          '<button class="forge-copy-btn" onclick="forgeIoaLqlCopy(\'forge-ioa-lql-pre\',this)">Copiar</button>' +
        '</div>' +
        '<pre id="forge-ioa-lql-pre" class="forge-pre">' + esc(query) + '</pre>' +
      '</div></div>';
  }
}

function forgeIoaLqlCopy(id, btn) {
  var el = document.getElementById(id);
  if (!el) return;
  copyToClipboard(el.textContent).then(function(){
    var orig = btn.textContent;
    btn.textContent = 'Copiado';
    setTimeout(function(){ btn.textContent = orig; }, 1500);
  });
}

function forgeIoaLqlClear() {
  IOA_LQL.fields.forEach(function(f) {
    var el = document.getElementById(f.input);
    if (el) el.value = '';
    delete _forgeIoaModes[f.input];
    delete _forgeIoaJoins[f.input];
  });
  ['hypothesis','mitre-tactic','mitre-technique','description','fp'].forEach(function(k){
    var el = document.getElementById('ioa-lql-' + k);
    if (el) el.value = '';
  });
  var noise = document.getElementById('ioa-lql-noise');
  if (noise) noise.value = '';

  _forgeIoaSyncAllToggles();
  _forgeIoaSyncAllJoinToggles();

  var statsEl = document.getElementById('forge-ioa-lql-stats');
  var outEl   = document.getElementById('forge-ioa-lql-output');
  if (statsEl) statsEl.textContent = '';
  if (outEl)   outEl.innerHTML = '';
}


/* ── Help popover LQL ─────────────────────────────────────── */

function forgeIoaLqlToggleHelp(btn) {
  var pop = document.getElementById('forge-ioa-lql-help-popover');
  if (!pop) return;
  if (!pop.hidden) { pop.hidden = true; return; }
  var r = btn.getBoundingClientRect();
  pop.style.top  = (r.bottom + 8) + 'px';
  pop.style.left = (r.right - 320) + 'px';
  pop.hidden = false;
  setTimeout(function(){
    document.addEventListener('mousedown', forgeIoaLqlCloseHelp);
  }, 0);
}

function forgeIoaLqlCloseHelp(e) {
  var pop = document.getElementById('forge-ioa-lql-help-popover');
  if (!pop || pop.hidden) {
    document.removeEventListener('mousedown', forgeIoaLqlCloseHelp);
    return;
  }
  if (pop.contains(e.target) || (e.target.closest && e.target.closest('.forge-help-btn'))) return;
  pop.hidden = true;
  document.removeEventListener('mousedown', forgeIoaLqlCloseHelp);
}


function forgeCsSelectTool(tool) {
  _forgeCollapseKql();
  _forgeCollapseXql();

  if (_forgeCsActiveTool === tool) {
    _forgeCollapseCs();
    document.getElementById('forge-workspace-empty').style.display = 'flex';
    return;
  }
  if (_forgeCsActiveTool) _forgeCollapseCs();

  var body  = document.getElementById('forge-' + tool + '-body');
  var arrow = document.getElementById('forge-arrow-' + tool);
  var head  = document.getElementById('forge-' + tool + '-head');

  document.getElementById('forge-workspace-empty').style.display = 'none';
  var ws = document.getElementById('forge-workspace-' + tool);
  if (ws) ws.classList.add('is-active');

  if (body)  body.style.display = 'flex';
  if (arrow) arrow.style.transform = 'rotate(90deg)';
  if (head)  head.style.background = 'rgba(var(--teal-rgb),.05)';

  _forgeCsActiveTool = tool;
}
