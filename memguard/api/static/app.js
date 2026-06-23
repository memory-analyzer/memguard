(function () {
  var scanId = null;
  var errors = [];

  function log(msg) {
    var el = document.getElementById('log');
    el.textContent += msg + '\n';
    el.scrollTop = el.scrollHeight;
  }

  function progress(pct) {
    document.getElementById('pb').style.width = pct + '%';
  }

  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }
  window.esc = esc;

  function resetUI() {
    document.getElementById('stats-card').style.display = 'none';
    document.getElementById('results-card').style.display = 'none';
    document.getElementById('tbody').innerHTML = '';
    document.getElementById('log').textContent = '';
    errors = [];
  }

  // ── Live scan via WebSocket ──────────────────────────────────────────────
  document.getElementById('btn-live').onclick = function () {
    var target  = document.getElementById('inp-target').value.trim();
    var compile = document.getElementById('inp-compile').value.trim();
    var argsRaw = document.getElementById('inp-args').value.trim();
    var args    = argsRaw ? argsRaw.split(' ') : [];
    if (!target) { alert('Enter a target path'); return; }

    resetUI();
    progress(5);

    var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    var url   = proto + '//' + location.host + '/ws/scan';
    log('Connecting to ' + url);

    // MemHint settings
    var memhintEnabled = document.getElementById('chk-memhint').checked;
    var memhintSrc = document.getElementById('inp-memhint-src').value.trim() || null;
    if (memhintEnabled) {
      log('[MemHint] Neuro-symbolic analysis enabled — discovering custom allocators...');
    }

    var ws;
    try { ws = new WebSocket(url); }
    catch (e) { log('ERROR: ' + e.message); return; }

    ws.onopen = function () {
      var payload = JSON.stringify({
        target: target,
        compile_cmd: compile || null,
        args: args,
        max_errors: 30,
        no_ai: false,
        model: 'auto',
        memhint_enabled: memhintEnabled,
        memhint_source_dir: memhintSrc
      });
      log('Sending request for: ' + target);
      if (memhintEnabled) log('[MemHint] Source: ' + (memhintSrc || 'auto-detect from binary'));
      ws.send(payload);
      progress(10);
    };

    ws.onmessage = function (e) {
      try { handleEvent(JSON.parse(e.data)); }
      catch (err) { log('Parse error: ' + err.message); }
    };

    ws.onerror = function () {
      log('WebSocket error — try Quick Scan (REST) instead');
      progress(0);
    };

    ws.onclose = function (e) {
      log('WS closed (code=' + e.code + ')');
    };
  };



  // ── WebSocket event handler ──────────────────────────────────────────────
  function handleEvent(ev) {
    if (ev.kind === 'memhint_start') {
      log('[MemHint] Stage 1: Analyzing source at ' + ev.source_dir);
      progress(8);
    } else if (ev.kind === 'memhint_progress') {
      log('[MemHint] ' + ev.message);
    } else if (ev.kind === 'memhint_done') {
      log('[MemHint] Done: ' + ev.extracted + ' functions → ' + ev.candidates + ' candidates → ' + ev.summaries + ' summaries → ' + ev.validated + ' validated (' + ev.duration_ms + 'ms)');
      showMemhintResults(ev);
      progress(15);
    } else if (ev.kind === 'memhint_error') {
      log('[MemHint] Error: ' + ev.message);
    } else if (ev.kind === 'scan_start') {
      log('Tools: ' + (ev.tools || []).join(', '));
      progress(20);
    } else if (ev.kind === 'tool_done') {
      log('[OK] ' + ev.tool + ' — ' + (ev.error_count || 0) + ' issues (' + ev.duration_ms + 'ms)');
      progress(40);
    } else if (ev.kind === 'parse_done') {
      log('Parsed: ' + ev.unique + ' unique issues');
      progress(50);
    } else if (ev.kind === 'ai_start') {
      log('AI: ' + ev.count + ' issues with ' + ev.model);
      progress(60);
    } else if (ev.kind === 'ai_progress') {
      progress(60 + (ev.completed / ev.total) * 35);
      log('  [' + ev.completed + '/' + ev.total + '] ' + ev.bug_type + ' — ' + (ev.root_cause || '').slice(0, 80));
    } else if (ev.kind === 'complete') {
      scanId = ev.scan_id;
      log('DONE! ID: ' + ev.scan_id);
      progress(100);
      loadScan(ev.scan_id).then(loadHistory);
      setTimeout(function () { progress(0); }, 1500);
    } else if (ev.kind === 'error') {
      log('ERROR: ' + ev.message);
      progress(0);
    }
  }

  function showMemhintResults(data) {
    var card = document.getElementById('memhint-card');
    card.style.display = '';

    // Badges
    var badges = document.getElementById('mh-badges');
    badges.innerHTML =
      '<div class="badge"><div class="bv" style="color:var(--cyan)">' + data.extracted + '</div><div class="bl">Functions</div></div>' +
      '<div class="badge"><div class="bv" style="color:var(--purple)">' + data.candidates + '</div><div class="bl">Candidates</div></div>' +
      '<div class="badge"><div class="bv" style="color:var(--green)">' + data.validated + '</div><div class="bl">Validated</div></div>' +
      '<div class="badge"><div class="bv" style="color:var(--red)">' + (data.summaries - data.validated) + '</div><div class="bl">Z3 Rejected</div></div>';

    // Allocators
    var allocDiv = document.getElementById('mh-allocs');
    if (data.allocators && data.allocators.length) {
      var h = '<div style="font-size:.75rem;color:var(--dim);text-transform:uppercase;font-weight:600;margin-bottom:.4rem">Custom Allocators (' + data.allocators.length + ')</div>';
      h += '<div style="display:flex;flex-wrap:wrap;gap:.4rem">';
      data.allocators.forEach(function(a) {
        h += '<span style="background:#238636;color:#fff;padding:.25rem .6rem;border-radius:4px;font-size:.8rem;font-weight:600">' + esc(a.name) + '() → ' + esc(a.target) + '</span>';
      });
      h += '</div>';
      allocDiv.innerHTML = h;
    }

    // Deallocators
    var deallocDiv = document.getElementById('mh-deallocs');
    if (data.deallocators && data.deallocators.length) {
      var h2 = '<div style="font-size:.75rem;color:var(--dim);text-transform:uppercase;font-weight:600;margin-bottom:.4rem">Custom Deallocators (' + data.deallocators.length + ')</div>';
      h2 += '<div style="display:flex;flex-wrap:wrap;gap:.4rem">';
      data.deallocators.forEach(function(d) {
        h2 += '<span style="background:#da3633;color:#fff;padding:.25rem .6rem;border-radius:4px;font-size:.8rem;font-weight:600">' + esc(d.name) + '() → frees ' + esc(d.target) + '</span>';
      });
      h2 += '</div>';
      deallocDiv.innerHTML = h2;
    }
  }

  // ── Load scan results ────────────────────────────────────────────────────
  async function loadScan(id) {
    var r    = await fetch('/scans/' + id);
    var data = await r.json();
    scanId   = id;

    var sev    = data.error_count_by_severity || {};
    var colors = { critical: '#f85149', high: '#f0883e', medium: '#d29922', low: '#58a6ff', info: '#8b949e' };
    var badges = '';
    Object.keys(sev).forEach(function (k) {
      badges += '<div class="badge"><div class="n" style="color:' + (colors[k] || '#ccc') + '">'
        + sev[k] + '</div><div class="l">' + k + '</div></div>';
    });
    if (data.total_bytes_leaked) {
      badges += '<div class="badge"><div class="n" style="color:#f85149">'
        + (data.total_bytes_leaked / 1024).toFixed(1) + 'K</div><div class="l">bytes leaked</div></div>';
    }
    document.getElementById('badges').innerHTML = badges;
    document.getElementById('stats-card').style.display = '';

    errors = data.errors || [];
    var rows = '';
    errors.forEach(function (err, i) {
      var loc   = err.primary_location
        ? err.primary_location.file.split('/').pop() + ':' + err.primary_location.line : '-';
      var bytes = err.bytes_leaked ? err.bytes_leaked.toLocaleString() + ' B' : '-';
      rows += '<tr data-idx="' + i + '" style="cursor:pointer" title="Click to view AI analysis and fix">' 
        + '<td>' + (i + 1) + '</td>'
        + '<td><span class="sev ' + err.severity + '">' + err.severity + '</span></td>'
        + '<td>' + err.bug_type.replace(/_/g, ' ') + '</td>'
        + '<td style="color:var(--dim);font-size:.8rem">' + esc(loc) + '</td>'
        + '<td style="color:var(--dim)">' + err.tool + '</td>'
        + '<td style="color:var(--red)">' + bytes + '</td>'
        + '</tr>';
    });
    document.getElementById('tbody').innerHTML = rows;
    // Add hint if not already there
    var hint = document.getElementById('row-hint');
    if (!hint) {
      var th = document.querySelector('#results-card h2');
      if (th) th.insertAdjacentHTML('afterend', '<div style="display:flex;gap:.75rem;align-items:center;margin-bottom:.5rem"><p id="row-hint" style="color:var(--dim);font-size:.8rem;margin:0">Click any row to view AI analysis, fix diff, and interactive debugger</p><button style="background:#bc8cff;color:#fff;border:none;border-radius:4px;padding:.4rem 1rem;cursor:pointer;font-weight:600;font-size:.8rem" onclick="window.open(\'/scans/\'+scanId+\'/viz\',\'_blank\')">Memory Visualization</button></div>');
    }
    document.getElementById('results-card').style.display = '';

    // Load memory visualization inline
    if (scanId && errors.length > 0) {
      var vizCard = document.getElementById('viz-card');
      var vizIframe = document.getElementById('viz-iframe');
      vizIframe.src = '/scans/' + scanId + '/viz';
      vizCard.style.display = '';
    }

    // Row click → modal
    document.querySelectorAll('#tbody tr').forEach(function (row) {
      row.style.cursor = 'pointer';
      row.onclick = function () { showError(parseInt(this.dataset.idx)); };
    });
  }

  // ── Error detail modal ───────────────────────────────────────────────────
  async function showError(idx) {
    var err = errors[idx];
    if (!err || !scanId) return;

    var sevColors = {critical:'#f85149',high:'#f0883e',medium:'#d29922',low:'#58a6ff',info:'#8b949e'};
    var sevCol = sevColors[err.severity] || '#ccc';

    var html = '<div style="display:flex;align-items:center;gap:1rem;margin-bottom:.75rem">'
      + '<h2 style="color:var(--cyan);margin:0">' + esc(err.bug_type.replace(/_/g, ' ').toUpperCase()) + '</h2>'
      + '<span style="background:' + sevCol + ';color:#000;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:700">'
      + err.severity.toUpperCase() + '</span>'
      + '</div>';

    html += '<p style="color:var(--text);margin-bottom:.5rem">' + esc(err.message) + '</p>';

    // Info grid
    html += '<div style="display:flex;gap:1.5rem;flex-wrap:wrap;margin:.5rem 0">';
    if (err.primary_location) {
      html += '<div><span style="color:var(--dim);font-size:.75rem">LOCATION</span><br>'
        + '<span style="color:var(--yellow)">' + esc(err.primary_location.file) + ':' + err.primary_location.line + '</span></div>';
    }
    if (err.bytes_leaked) {
      html += '<div><span style="color:var(--dim);font-size:.75rem">LEAKED</span><br>'
        + '<span style="color:var(--red);font-weight:700">' + err.bytes_leaked.toLocaleString() + ' bytes</span></div>';
    }
    if (err.alloc_count) {
      html += '<div><span style="color:var(--dim);font-size:.75rem">BLOCKS</span><br>'
        + '<span style="color:var(--red)">' + err.alloc_count + '</span></div>';
    }
    html += '<div><span style="color:var(--dim);font-size:.75rem">TOOL</span><br>'
      + '<span style="color:var(--cyan)">' + err.tool + '</span></div>';
    html += '</div>';

    if (err.source_context) {
      var ctx  = err.source_context;
      var lines = [];
      (ctx.before_lines || []).slice(-4).forEach(function (l) { lines.push(esc(l)); });
      lines.push('<b style="color:var(--red)">' + esc(ctx.target_line) + '  &lt;-- error</b>');
      (ctx.after_lines || []).slice(0, 4).forEach(function (l) { lines.push(esc(l)); });
      html += '<hr class="divider"><pre>' + lines.join('\n') + '</pre>';
    }

    // Load AI analysis
    try {
      var ar = await fetch('/scans/' + scanId + '/errors/' + err.id + '/analysis');
      if (ar.ok) {
        var a = await ar.json();
        html += '<hr class="divider">';
        html += '<div style="background:#1c2128;border-radius:6px;padding:1rem;margin:.5rem 0">';
        html += '<h3 style="color:var(--purple);margin:0 0 .5rem">AI Analysis</h3>';
        html += '<div style="margin-bottom:.5rem"><span style="color:var(--dim);font-size:.75rem">ROOT CAUSE</span><br>'
          + '<p style="margin:.25rem 0">' + esc(a.root_cause || '-') + '</p></div>';
        html += '<div style="margin-bottom:.5rem"><span style="color:var(--dim);font-size:.75rem">EXPLANATION</span><br>'
          + '<p style="margin:.25rem 0">' + esc(a.explanation || '-') + '</p></div>';
        html += '<div><span style="color:var(--dim);font-size:.75rem">IMPACT</span><br>'
          + '<p style="margin:.25rem 0;color:var(--red)">' + esc(a.impact || '-') + '</p></div>';
        html += '</div>';

        if (a.fixes && a.fixes.length) {
          a.fixes.forEach(function(fix, fi) {
            var confColor = fix.confidence === 'high' ? 'var(--green)' : fix.confidence === 'low' ? 'var(--red)' : 'var(--yellow)';
            html += '<div style="background:#1c2128;border-left:3px solid var(--green);border-radius:0 6px 6px 0;padding:1rem;margin:.5rem 0">';
            html += '<div style="display:flex;justify-content:space-between;align-items:center;gap:.5rem;flex-wrap:wrap">';
            html += '<h3 style="color:var(--green);margin:0">Fix ' + (fi+1) + ': ' + esc(fix.description || '') + '</h3>';
            html += '<div style="display:flex;gap:.5rem;align-items:center">';
            if (fix.applicable === false) {
              html += '<span style="color:var(--yellow);font-size:.7rem">manual apply</span>';
            } else {
              html += '<span style="color:var(--green);font-size:.7rem">auto-applicable</span>';
            }
            html += '<span style="color:' + confColor + ';font-size:.75rem;font-weight:700">' + (fix.confidence || 'medium').toUpperCase() + '</span>';
            html += '</div></div>';
            if (fix.diff) {
              // Color-code the diff
              var diffLines = fix.diff.split('\n').map(function(l) {
                if (l.startsWith('+') && !l.startsWith('+++')) return '<span style="color:var(--green)">' + esc(l) + '</span>';
                if (l.startsWith('-') && !l.startsWith('---')) return '<span style="color:var(--red)">' + esc(l) + '</span>';
                if (l.startsWith('@@')) return '<span style="color:var(--cyan)">' + esc(l) + '</span>';
                return esc(l);
              }).join('\n');
              html += '<pre style="margin:.5rem 0">' + diffLines + '</pre>';
            }
            if (fix.test_suggestion) {
              html += '<p style="color:var(--dim);font-size:.82rem;margin-top:.5rem">Test: ' + esc(fix.test_suggestion) + '</p>';
            }
            html += '</div>';
          });
        }

        if (a.best_practices && a.best_practices.length) {
          html += '<div style="margin-top:.75rem">';
          html += '<h3 style="color:var(--cyan);margin-bottom:.5rem">Best Practices</h3>';
          a.best_practices.forEach(function(bp) {
            html += '<div style="margin-bottom:.5rem;padding-left:.75rem;border-left:2px solid var(--border)">';
            html += '<b>' + esc(bp.title || '') + '</b><br>';
            html += '<span style="color:var(--dim)">' + esc(bp.explanation || '') + '</span>';
            html += '</div>';
          });
          html += '</div>';
        }

        if (a.cwe_ids && a.cwe_ids.length) {
          html += '<p style="color:var(--dim);font-size:.8rem;margin-top:.5rem">References: '
            + a.cwe_ids.map(function(c){return '<a href="https://cwe.mitre.org/data/definitions/'+c.replace('CWE-','')+'.html" target="_blank" style="color:var(--cyan)">' + esc(c) + '</a>';}).join(' | ')
            + '</p>';
        }
      }
    } catch (e) { /* analysis not ready */ }

    // Stack trace
    if (err.stack && err.stack.length) {
      var frames = err.stack.slice(0, 10).map(function (f) {
        var loc = (f.file && f.line) ? f.file.split('/').pop() + ':' + f.line : (f.address || '??');
        var fn = f.function || '??';
        var color = (f.file && !f.file.startsWith('/usr/')) ? 'var(--cyan)' : 'var(--dim)';
        return '<span style="color:var(--dim)">#' + f.index + '</span> '
          + '<span style="color:' + color + ';font-weight:600">' + esc(fn) + '</span>'
          + '  <span style="color:var(--dim)">' + esc(loc) + '</span>';
      }).join('\n');
      html += '<hr class="divider"><h3 style="color:var(--dim);margin-bottom:.25rem">Error Stack Trace</h3>'
        + '<pre>' + frames + '</pre>';
    }

    // Allocation info
    if (err.allocation_info && err.allocation_info.stack && err.allocation_info.stack.length) {
      var aframes = err.allocation_info.stack.slice(0, 6).map(function (f) {
        var loc = (f.file && f.line) ? f.file.split('/').pop() + ':' + f.line : (f.address || '??');
        return '<span style="color:var(--dim)">#' + f.index + '</span> '
          + '<span style="color:var(--yellow)">' + esc(f.function || '??') + '</span>'
          + '  <span style="color:var(--dim)">' + esc(loc) + '</span>';
      }).join('\n');
      var akind = err.allocation_info.kind ? ' (' + esc(err.allocation_info.kind) + ')' : '';
      html += '<h3 style="color:var(--dim);margin:.5rem 0 .25rem">Allocation Site' + akind + '</h3>'
        + '<pre>' + aframes + '</pre>';
    }

    // Chat
    html += '<hr class="divider">';
    html += '<div style="display:flex;gap:.5rem;margin-bottom:.75rem;flex-wrap:wrap">'
      + '<button onclick="aiDeepDebug(\'' + err.id + '\')" style="background:var(--purple);color:#fff;border:none;border-radius:4px;padding:.5rem 1rem;cursor:pointer;font-weight:600;font-size:.85rem">AI Deep Debug</button>'
      + '<button onclick="showTimewarp()" style="background:#238636;color:#fff;border:none;border-radius:4px;padding:.5rem 1rem;cursor:pointer;font-weight:600;font-size:.85rem">Time Travel Debug</button>'
      + '<button onclick="showTaintFlow()" style="background:#da3633;color:#fff;border:none;border-radius:4px;padding:.5rem 1rem;cursor:pointer;font-weight:600;font-size:.85rem">Taint Flow</button>'
      + '</div>';

    // AI Debug results container
    html += '<div id="ai-debug-panel" style="display:none"></div>';

    // Time Travel panel
    html += '<div id="timewarp-panel" style="display:none"></div>';

    html += '<div class="chat-box">'
      + '<h3 style="color:var(--cyan);margin-bottom:.5rem">Chat with AI</h3>'
      + '<div class="chat-msgs" id="cm"></div>'
      + '<div class="chat-row">'
      + '<input id="ci" placeholder="Ask about this error..." />'
      + '<button class="btn" id="chat-send">Send</button>'
      + '</div></div>';

    document.getElementById('modal-body').innerHTML = html;
    document.getElementById('overlay').style.display = 'block';

    var ci  = document.getElementById('ci');
    var btn = document.getElementById('chat-send');
    var eid = err.id;

    ci.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') sendChat(eid);
    });
    btn.addEventListener('click', function () { sendChat(eid); });
  }

  function renderMarkdown(text) {
    var s = text;
    // fenced code blocks  ```lang\ncode\n```
    s = s.replace(/```[\w]*\n?([\s\S]*?)```/g, function(_, code) {
      return '<pre style="background:var(--bg);border:1px solid var(--border);border-radius:4px;'
           + 'padding:.75rem;margin:.5rem 0;overflow-x:auto;font-size:.8rem"><code>'
           + code.trim().replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
           + '</code></pre>';
    });
    // inline code
    s = s.replace(/`([^`\n]+)`/g, '<code style="background:var(--bg);border:1px solid var(--border);'
      + 'border-radius:3px;padding:1px 4px;font-size:.85em">$1</code>');
    // bold
    s = s.replace(/\*\*([^*\n]+)\*\*/g, '<b>$1</b>');
    // h3
    s = s.replace(/^### (.+)$/gm, '<h4 style="color:var(--cyan);margin:.6rem 0 .2rem">$1</h4>');
    // h2
    s = s.replace(/^## (.+)$/gm, '<h3 style="color:var(--cyan);margin:.6rem 0 .2rem">$1</h3>');
    // numbered list
    s = s.replace(/^\d+\. (.+)$/gm, '<div style="margin:.2rem 0 .2rem 1rem">$1</div>');
    // bullet list
    s = s.replace(/^[-*] (.+)$/gm,
      '<div style="margin:.2rem 0 .2rem 1rem;display:flex;gap:.4rem">'
      + '<span style="color:var(--cyan)">&#8226;</span><span>$1</span></div>');
    // blank lines
    s = s.replace(/\n\n/g, '<br><br>');
    // remaining newlines
    s = s.replace(/\n/g, '<br>');
    return s;
  }

  async function sendChat(errId) {
    var ci  = document.getElementById('ci');
    var cm  = document.getElementById('cm');
    var msg = ci.value.trim();
    if (!msg) return;
    ci.value = '';

    // User bubble
    cm.innerHTML += '<div style="margin:.5rem 0;padding:.5rem .75rem;background:#1c2128;border-radius:6px;border-left:2px solid var(--cyan)">'
      + '<span style="color:var(--cyan);font-size:.75rem;font-weight:700">YOU</span><br>'
      + '<span>' + esc(msg) + '</span></div>';

    // AI thinking bubble
    var aiBubbleId = 'ai-' + Date.now();
    cm.innerHTML += '<div id="' + aiBubbleId + '" style="margin:.5rem 0;padding:.5rem .75rem;background:#21262d;border-radius:6px;border-left:2px solid var(--purple)">'
      + '<span style="color:var(--purple);font-size:.75rem;font-weight:700">AI</span><br>'
      + '<span style="color:var(--dim)">thinking...</span></div>';
    cm.scrollTop = cm.scrollHeight;

    try {
      var r = await fetch('/scans/' + scanId + '/errors/' + errId + '/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: msg, model: 'auto' })
      });
      var d = await r.json();
      var rendered = renderMarkdown(d.response || 'No response');
      document.getElementById(aiBubbleId).querySelector('span:last-child').innerHTML = rendered;
    } catch (e) {
      document.getElementById(aiBubbleId).querySelector('span:last-child').textContent = 'Error: ' + e.message;
    }
    cm.scrollTop = cm.scrollHeight;
  }

  // ── History ──────────────────────────────────────────────────────────────
  async function loadHistory() {
    try {
      var scans = await fetch('/scans').then(function (r) { return r.json(); });
      var el    = document.getElementById('history');
      if (!scans.length) {
        el.innerHTML = '<p style="color:var(--dim)">No scans yet.</p>';
        return;
      }
      var rows = scans.slice(0, 10).map(function (s) {
        return '<tr style="cursor:pointer" data-id="' + s.scan_id + '">'
          + '<td style="font-size:.8rem;color:var(--dim)">' + s.scan_id.slice(0, 16) + '</td>'
          + '<td style="color:var(--dim)">' + (s.started_at || '').slice(0, 19) + '</td>'
          + '<td>' + s.total + '</td>'
          + '<td style="color:var(--red)">' + s.critical + '</td>'
          + '<td style="color:var(--yellow)">' + s.high + '</td>'
          + '</tr>';
      }).join('');
      el.innerHTML = '<table><thead><tr><th>ID</th><th>Date</th><th>Total</th>'
        + '<th>Critical</th><th>High</th></tr></thead><tbody>' + rows + '</tbody></table>';
      el.querySelectorAll('tbody tr').forEach(function (row) {
        row.onclick = function () { loadScan(this.dataset.id).then(loadHistory); };
      });
    } catch (e) { /* ignore */ }
  }

  // ── Modal close ──────────────────────────────────────────────────────────
  document.getElementById('close-modal').onclick = function () {
    document.getElementById('overlay').style.display = 'none';
  };
  document.getElementById('overlay').onclick = function (e) {
    if (e.target === this) this.style.display = 'none';
  };

  // ── Init ─────────────────────────────────────────────────────────────────
  loadHistory();

  // ── MemHint checkbox toggle ──
  document.getElementById('chk-memhint').addEventListener('change', function() {
    document.getElementById('inp-memhint-src').style.display = this.checked ? '' : 'none';
    document.getElementById('memhint-auto-note').style.display = this.checked ? '' : 'none';
  });

  // Expose scanId for onclick handlers in HTML
  window.__memguard_getScanId = function() { return scanId; };
})();

// Global: switch visualization tab by clicking into iframe
function switchVizTab(tabName) {
  var iframe = document.getElementById('viz-iframe');
  if (!iframe || !iframe.contentWindow) return;
  // Click the tab inside the iframe
  try {
    var tabs = iframe.contentDocument.querySelectorAll('.tab');
    tabs.forEach(function(t) { t.classList.remove('active'); });
    var panels = iframe.contentDocument.querySelectorAll('.panel');
    panels.forEach(function(p) { p.classList.remove('active'); });
    var target = iframe.contentDocument.getElementById(tabName);
    if (target) target.classList.add('active');
    // Activate the clicked tab button
    tabs.forEach(function(t) {
      if (t.textContent.toLowerCase().indexOf(tabName) >= 0) t.classList.add('active');
    });
  } catch(e) { /* cross-origin fallback */ }
  // Update parent buttons
  document.querySelectorAll('.viz-tab').forEach(function(b) { b.classList.remove('active'); });
  event.target.classList.add('active');
}

// Expose scanId for inline onclick
Object.defineProperty(window, 'scanId', {
  get: function() { return window.__memguard_getScanId ? window.__memguard_getScanId() : null; }
});

// Taint Flow Analysis
async function showTaintFlow() {
  var panel = document.getElementById('timewarp-panel');
  if (!panel) return;
  panel.style.display = '';
  panel.innerHTML = '<p style="color:var(--red)">Analyzing taint flow — tracing external input to memory bugs...</p>';

  try {
    var resp = await fetch('/scans/' + scanId + '/taint');
    if (!resp.ok) { panel.innerHTML = '<p style="color:var(--red)">Taint analysis failed: ' + resp.status + '</p>'; return; }
    var data = await resp.json();
    var html = '<div style="background:#1c2128;border-radius:6px;padding:1rem;margin:.5rem 0">';
    html += '<h3 style="color:var(--red);margin:0 0 .75rem">Taint Flow Analysis</h3>';

    // Risk summary
    var sumColor = data.risk_summary.startsWith('CRITICAL') ? 'var(--red)' : data.risk_summary.startsWith('HIGH') ? 'var(--orange)' : 'var(--yellow)';
    html += '<div style="background:#21262d;border-left:3px solid ' + sumColor + ';padding:.75rem;margin-bottom:.75rem;border-radius:0 4px 4px 0">';
    html += '<span style="color:' + sumColor + ';font-weight:700">' + esc(data.risk_summary) + '</span></div>';

    // Stats
    html += '<div style="display:flex;gap:.75rem;margin-bottom:.75rem;flex-wrap:wrap">';
    html += '<div style="background:#21262d;padding:.5rem .75rem;border-radius:4px;font-size:.8rem"><b style="color:var(--cyan)">' + data.taint_sources.length + '</b> input sources</div>';
    html += '<div style="background:#21262d;padding:.5rem .75rem;border-radius:4px;font-size:.8rem"><b style="color:var(--cyan)">' + (data.functions_analyzed || data.call_graph_size) + '</b> functions analyzed</div>';
    html += '<div style="background:#21262d;padding:.5rem .75rem;border-radius:4px;font-size:.8rem"><b style="color:var(--purple)">' + (data.data_flow_edges || 0) + '</b> data-flow edges</div>';
    html += '<div style="background:#21262d;padding:.5rem .75rem;border-radius:4px;font-size:.8rem"><b style="color:var(--purple)">' + (data.tainted_variables || 0) + '</b> tainted variables</div>';
    html += '<div style="background:#21262d;padding:.5rem .75rem;border-radius:4px;font-size:.8rem"><b style="color:var(--red)">' + data.reachable + '</b> bugs reachable</div>';
    html += '<div style="background:#21262d;padding:.5rem .75rem;border-radius:4px;font-size:.8rem"><b style="color:var(--green)">' + data.isolated + '</b> bugs isolated</div>';
    html += '</div>';

    // Taint paths
    if (data.taint_paths.length) {
      html += '<div style="font-size:.75rem;color:var(--dim);text-transform:uppercase;font-weight:600;margin-bottom:.5rem">Attack Paths (' + data.taint_paths.length + ')</div>';
      data.taint_paths.forEach(function(p) {
        var riskColor = p.risk.startsWith('CRITICAL') ? 'var(--red)' : p.risk.startsWith('HIGH') ? 'var(--orange)' : 'var(--yellow)';
        html += '<div style="border:1px solid ' + riskColor + ';border-radius:6px;padding:.75rem;margin-bottom:.5rem;background:#161b22">';

        // Flow visualization with variables and edge types
        html += '<div style="display:flex;align-items:center;gap:.3rem;flex-wrap:wrap;margin-bottom:.5rem">';
        html += '<span style="background:var(--red);color:#fff;padding:.2rem .5rem;border-radius:4px;font-size:.75rem;font-weight:700">' + esc(p.source_call) + '()</span>';
        html += '<span style="color:var(--dim);font-size:.7rem">' + esc(p.source_type) + '</span>';
        if (p.source_var) {
          html += '<span style="color:var(--purple);font-size:.7rem;font-weight:600"> → \'' + esc(p.source_var) + '\'</span>';
        }

        var edges = p.path_edges || [];
        var vars = p.path_variables || [];
        if (p.path.length > 1) {
          p.path.forEach(function(fn, i) {
            if (i > 0) {
              var edgeLabel = edges[i] || 'call';
              var edgeColor = edgeLabel === 'param' ? '#bc8cff' : edgeLabel === 'return' ? '#3fb950' : edgeLabel === 'global' ? '#d29922' : '#58a6ff';
              html += '<span style="color:' + edgeColor + ';font-weight:700;font-size:.7rem"> →<sup style=\\"font-size:.6rem\\">' + edgeLabel + '</sup> </span>';
              html += '<span style="background:#21262d;padding:.2rem .5rem;border-radius:4px;font-size:.75rem;border:1px solid var(--border)">' + esc(fn) + '()';
              if (vars[i] && vars[i] !== '??') {
                html += '<span style="color:var(--purple);font-size:.65rem"> \'' + esc(vars[i]) + '\'</span>';
              }
              html += '</span>';
            }
          });
        }
        html += '<span style="color:var(--cyan);font-weight:700"> → </span>';
        html += '<span style="background:' + riskColor + ';color:#fff;padding:.2rem .5rem;border-radius:4px;font-size:.75rem;font-weight:700">' + esc(p.bug_type.toUpperCase()) + '</span>';
        html += '<span style="color:var(--dim);font-size:.75rem">at ' + esc(p.bug_location) + '</span>';
        html += '</div>';

        // Data flow detail
        if (p.data_flow) {
          html += '<div style="font-size:.75rem;color:var(--purple);background:#1c1030;padding:.4rem .6rem;border-radius:4px;margin-bottom:.4rem;border-left:2px solid var(--purple)">' + esc(p.data_flow) + '</div>';
        }

        // Risk assessment
        html += '<div style="font-size:.82rem;color:var(--text)">' + esc(p.risk) + '</div>';
        html += '<div style="font-size:.75rem;color:var(--dim);margin-top:.25rem">Confidence: ' + Math.round(p.confidence * 100) + '%</div>';
        html += '</div>';
      });
    }

    // Input sources
    if (data.taint_sources.length) {
      html += '<details style="margin-top:.75rem"><summary style="cursor:pointer;color:var(--dim);font-size:.8rem;font-weight:600">Input Sources (' + data.taint_sources.length + ')</summary>';
      html += '<div style="margin-top:.5rem;display:flex;flex-wrap:wrap;gap:.3rem">';
      data.taint_sources.forEach(function(s) {
        var c = s.risk === 'critical' ? 'var(--red)' : s.risk === 'high' ? 'var(--orange)' : s.risk === 'medium' ? 'var(--yellow)' : 'var(--green)';
        html += '<span style="background:#21262d;padding:.25rem .5rem;border-radius:4px;font-size:.75rem;border-left:2px solid ' + c + '">'
          + esc(s.call) + '() → <b style="color:var(--purple)">\'' + esc(s.tainted_var || '??') + '\'</b> in ' + esc(s.function) + '() <span style="color:var(--dim)">' + esc(s.file) + ':' + s.line + '</span></span>';
      });
      html += '</div></details>';
    }

    html += '</div>';
    panel.innerHTML = html;
  } catch (e) {
    panel.innerHTML = '<p style="color:var(--red)">Error: ' + e.message + '</p>';
  }
}

// Heaptrack — heap memory profiling
async function runHeaptrack() {
  var target = document.getElementById('inp-target').value.trim();
  if (!target) { alert('Enter a binary path first'); return; }

  var log = document.getElementById('log');
  log.textContent = '[HeapProfile] Running heaptrack on ' + target + '...\nThis records every malloc/free call with full call stacks.\n';

  // Show loading state
  var vizCard = document.getElementById('viz-card');
  var vizIframe = document.getElementById('viz-iframe');

  try {
    var resp = await fetch('/heaptrack/' + encodeURIComponent(target), {method: 'POST'});
    if (!resp.ok) {
      var err = await resp.text();
      log.textContent += '\n[HeapProfile] Error: ' + err;
      if (err.indexOf('not found') >= 0 || err.indexOf('not installed') >= 0) {
        log.textContent += '\n\nInstall heaptrack: sudo apt install heaptrack';
      }
      return;
    }

    var html = await resp.text();
    log.textContent += '[HeapProfile] Done! Rendering visualization...\n';

    // Show in viz iframe
    vizCard.style.display = '';
    vizIframe.srcdoc = html;

    // Update tab buttons for heap mode
    document.querySelectorAll('.viz-tab').forEach(function(t) { t.style.display = 'none'; });
    var openBtn = vizCard.querySelector('button:last-child');
    if (openBtn) openBtn.style.display = 'none';

    // Add heap profile label
    var h2 = vizCard.querySelector('h2');
    if (h2) h2.textContent = 'Heap Memory Profile (heaptrack)';

  } catch (e) {
    log.textContent += '\n[HeapProfile] Error: ' + e.message;
  }
}

// AI Deep Debug — reasoning chain + backtracking
async function aiDeepDebug(errorId) {
  var panel = document.getElementById('ai-debug-panel');
  if (!panel) return;
  panel.style.display = '';
  panel.innerHTML = '<p style="color:var(--cyan)">Running AI deep analysis (reasoning chain + backtracking)...</p>'
    + '<p style="color:var(--dim);font-size:.8rem">This takes 30-120 seconds on a local 14B model</p>';

  try {
    var resp = await fetch('/scans/' + scanId + '/errors/' + errorId + '/ai-debug', {method: 'POST'});
    if (!resp.ok) { panel.innerHTML = '<p style="color:var(--red)">AI debug failed: ' + resp.status + '</p>'; return; }
    var data = await resp.json();
    var html = '';

    // Reasoning Chain
    if (data.reasoning && data.reasoning.steps) {
      html += '<div style="background:#1c2128;border-radius:6px;padding:1rem;margin:.5rem 0">';
      html += '<h3 style="color:var(--purple);margin:0 0 .75rem">AI Reasoning Chain</h3>';
      data.reasoning.steps.forEach(function(s) {
        var confColor = s.confidence >= 0.8 ? 'var(--green)' : s.confidence >= 0.5 ? 'var(--yellow)' : 'var(--red)';
        html += '<div style="border-left:3px solid var(--cyan);padding:.5rem .75rem;margin-bottom:.75rem;background:#161b22;border-radius:0 4px 4px 0">';
        html += '<div style="display:flex;justify-content:space-between;align-items:center">';
        html += '<b style="color:var(--cyan)">Step ' + s.step + ': ' + esc(s.title) + '</b>';
        html += '<span style="color:' + confColor + ';font-size:.75rem;font-weight:700">' + Math.round(s.confidence * 100) + '% confident</span>';
        html += '</div>';
        html += '<p style="margin:.25rem 0;font-size:.85rem"><b>Observe:</b> ' + esc(s.observation) + '</p>';
        html += '<p style="margin:.25rem 0;font-size:.85rem"><b>Evidence:</b> <code style="color:var(--yellow)">' + esc(s.evidence) + '</code></p>';
        html += '<p style="margin:.25rem 0;font-size:.85rem"><b>Infer:</b> ' + esc(s.inference) + '</p>';
        if (s.alternatives && s.alternatives.length) {
          html += '<p style="margin:.25rem 0;font-size:.8rem;color:var(--dim)">Ruled out: ' + s.alternatives.map(esc).join('; ') + '</p>';
        }
        html += '</div>';
      });
      // Verdict
      if (data.reasoning.verdict) {
        var vc = data.reasoning.confidence >= 0.8 ? 'var(--green)' : 'var(--yellow)';
        html += '<div style="background:#238636;color:#fff;padding:.75rem;border-radius:4px;margin-top:.5rem">';
        html += '<b>Verdict:</b> ' + esc(data.reasoning.verdict);
        html += '<br><span style="font-size:.8rem">Confidence: ' + Math.round(data.reasoning.confidence * 100) + '%</span>';
        if (data.reasoning.counterfactual) {
          html += '<br><span style="font-size:.8rem;opacity:.8">If this bug did NOT exist: ' + esc(data.reasoning.counterfactual) + '</span>';
        }
        html += '</div>';
      }
      html += '</div>';
    }

    // Backtracking
    if (data.backtrack && !data.backtrack.error) {
      html += '<div style="background:#1c2128;border-radius:6px;padding:1rem;margin:.5rem 0">';
      html += '<h3 style="color:var(--green);margin:0 0 .75rem">Allocation Backtracker</h3>';

      // Birth
      html += '<div style="border-left:3px solid var(--green);padding:.5rem .75rem;margin-bottom:.5rem">';
      html += '<b style="color:var(--green)">BORN</b> via <code>' + esc(data.backtrack.allocated_via) + '</code>';
      html += '<br><span style="color:var(--dim)">' + esc(data.backtrack.allocated_at) + '</span></div>';

      // Ownership chain
      if (data.backtrack.ownership_chain && data.backtrack.ownership_chain.length) {
        html += '<div style="display:flex;align-items:center;gap:.25rem;flex-wrap:wrap;margin:.5rem 0">';
        data.backtrack.ownership_chain.forEach(function(step, i) {
          if (i > 0) html += '<span style="color:var(--cyan);font-weight:700"> → </span>';
          var cls = i === 0 ? 'var(--green)' : 'var(--cyan)';
          html += '<span style="background:#21262d;padding:.25rem .5rem;border-radius:4px;border:1px solid ' + cls + ';font-size:.8rem">' + esc(step) + '</span>';
        });
        // End
        var freed = data.backtrack.actually_freed;
        html += '<span style="color:var(--cyan);font-weight:700"> → </span>';
        html += '<span style="background:#21262d;padding:.25rem .5rem;border-radius:4px;border:1px solid var(--red);font-size:.8rem;color:var(--red)">'
          + (freed === 'NEVER' ? 'LEAKED' : 'freed') + '</span>';
        html += '</div>';
      }

      // Death
      html += '<div style="border-left:3px solid var(--red);padding:.5rem .75rem;margin-top:.5rem">';
      html += '<b style="color:var(--red)">Should free at:</b> ' + esc(data.backtrack.should_free_at);
      html += '<br><b style="color:var(--red)">Actually freed:</b> ' + esc(data.backtrack.actually_freed);
      html += '<br><b style="color:var(--red)">Lost at:</b> ' + esc(data.backtrack.lost_at);
      html += '</div>';
      html += '</div>';
    }

    panel.innerHTML = html || '<p style="color:var(--dim)">No additional analysis available</p>';
  } catch (e) {
    panel.innerHTML = '<p style="color:var(--red)">Error: ' + e.message + '</p>';
  }
}

// Time Travel Debug panel
async function showTimewarp() {
  var panel = document.getElementById('timewarp-panel');
  if (!panel) return;
  panel.style.display = '';
  panel.innerHTML = '<p style="color:var(--cyan)">Loading time-travel debug info...</p>';

  try {
    var resp = await fetch('/scans/' + scanId + '/timewarp');
    if (!resp.ok) { panel.innerHTML = '<p style="color:var(--red)">Failed: ' + resp.status + '</p>'; return; }
    var data = await resp.json();
    var html = '<div style="background:#1c2128;border-radius:6px;padding:1rem;margin:.5rem 0">';
    html += '<h3 style="color:var(--green);margin:0 0 .75rem">Time Travel Debugger</h3>';

    // Breakpoints
    html += '<div style="margin-bottom:.75rem">';
    html += '<b style="color:var(--dim);font-size:.75rem">' + data.breakpoints.length + ' BREAKPOINTS SET</b>';
    data.breakpoints.forEach(function(bp) {
      var col = {use_after_free:'var(--red)',race_condition:'var(--yellow)',memory_leak:'var(--cyan)',null_deref:'var(--yellow)',buffer_overflow:'var(--red)'}[bp.bug_type] || 'var(--dim)';
      html += '<div style="margin:.25rem 0;padding:.25rem .5rem;border-left:2px solid ' + col + ';font-size:.82rem">';
      html += '<span style="color:' + col + ';font-weight:600">' + bp.bug_type.toUpperCase() + '</span> ';
      html += '<span style="color:var(--cyan)">' + esc(bp.function) + '()</span> at ' + esc(bp.location);
      html += '</div>';
    });
    html += '</div>';

    // Recordings
    if (data.recordings && data.recordings.length) {
      html += '<b style="color:var(--dim);font-size:.75rem">RECORDINGS</b>';
      data.recordings.forEach(function(r) {
        html += '<div style="font-size:.82rem;color:var(--dim);margin:.25rem 0">'
          + r.id + ' (' + r.tool + ', ' + r.duration_ms + 'ms, ' + r.size_mb + 'MB)</div>';
      });
    }

    // Instructions
    html += '<div style="margin-top:.75rem;padding:.75rem;background:#0d1117;border-radius:4px;border:1px solid var(--border)">';
    html += '<b style="color:var(--green);font-size:.8rem">Launch Commands:</b><br>';
    html += '<code style="color:var(--cyan);font-size:.8rem">memguard record ' + esc(data.binary) + '</code><br>';
    html += '<code style="color:var(--cyan);font-size:.8rem">memguard timewarp ' + esc(data.scan_id) + ' --launch</code><br><br>';
    html += '<b style="color:var(--green);font-size:.8rem">Inside Debugger:</b><br>';
    html += '<code style="color:var(--dim);font-size:.78rem">continue</code> → run to first bug<br>';
    html += '<code style="color:var(--dim);font-size:.78rem">reverse-continue</code> → travel backwards<br>';
    html += '<code style="color:var(--dim);font-size:.78rem">mg-ai</code> → AI explains current state<br>';
    html += '<code style="color:var(--dim);font-size:.78rem">mg-why</code> → AI explains root cause<br>';
    html += '<code style="color:var(--dim);font-size:.78rem">mg-fix</code> → AI generates fix<br>';
    html += '</div>';

    html += '</div>';
    panel.innerHTML = html;
  } catch (e) {
    panel.innerHTML = '<p style="color:var(--red)">Error: ' + e.message + '</p>';
  }
}
