'use strict';
// This view has no shell bridge, fetch, persistence, provider calls or agent executor.
(() => {
  const $ = (selector) => document.querySelector(selector);
  const MAX_SESSIONS = 8, MAX_RECORDS = 200;
  const sessions = [];
  let active, view = 'terminal', historyIndex = 0, draft = '';
  const pad = (n) => String(n).padStart(2, '0');
  const time = () => new Date().toLocaleTimeString([], {hour12: false});
  const node = (tag, className, text) => {
    const element = document.createElement(tag);
    element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  };
  function appendBounded(list, item) { list.push(item); if (list.length > MAX_RECORDS) list.shift(); }
  function log(message) { appendBounded(active.logs, {time: time(), message}); }
  function announce(message) { $('#announcement').textContent = message; }
  function createSession() {
    if (sessions.length >= MAX_SESSIONS) return;
    active = {id: sessions.length + 1, history: [], entries: [], logs: [], draft: ''};
    sessions.push(active);
    log('Local preview session opened. Agent transport is not connected.');
    historyIndex = 0; draft = ''; view = 'terminal';
    $('#command').value = '';
    render();
    announce(`Command deck ${pad(active.id)} opened. Local preview only.`);
  }
  function selectSession(session) {
    active.draft = $('#command').value;
    active = session; historyIndex = active.history.length; draft = active.draft;
    $('#command').value = draft;
    render();
  }
  function render() {
    const list = $('#sessions'); list.replaceChildren();
    sessions.forEach((session) => {
      const button = node('button', 'session-button');
      button.type = 'button'; button.setAttribute('aria-current', String(session === active));
      button.append(node('span', 'session-symbol', '›_'));
      const label = node('span', '', `Command deck ${pad(session.id)}`);
      label.append(node('small', '', 'Local preview'));
      button.append(label); button.addEventListener('click', () => selectSession(session)); list.append(button);
    });
    $('#session-count').textContent = pad(sessions.length);
    $('#session-title').textContent = `Command deck ${pad(active.id)}`;
    $('#history-count').textContent = active.history.length;
    $('#new-session').disabled = sessions.length >= MAX_SESSIONS;
    document.querySelectorAll('[data-view]').forEach((button) => button.setAttribute('aria-pressed', String(button.dataset.view === view)));
    const output = $('#transcript'); output.replaceChildren();
    output.setAttribute('aria-label', view === 'terminal' ? 'Terminal output' : `Session ${view}`);
    if (view === 'terminal') {
      if (active.entries.length === 0) {
        output.append(node('p', 'welcome-kicker', 'MOTHERSHIP / LOCAL COMMAND DECK'));
        output.append(node('h2', 'welcome-title', 'A quiet space for what comes next.'));
        output.append(node('p', 'welcome-copy', 'Explore the OMNI launcher interface. These commands control this preview only. Your existing CLI remains in your terminal; no agent or shell is connected here.'));
        const actions = node('div', 'quick-commands');
        ['help', 'status', 'sessions'].forEach((command) => {
          const button = node('button', '', command); button.type = 'button';
          button.addEventListener('click', () => execute(command)); actions.append(button);
        }); output.append(actions);
      }
      active.entries.forEach((entry) => {
        const line = node('div', `entry entry-${entry.kind}`);
        line.append(node('span', 'entry-time', entry.time), document.createTextNode(entry.text)); output.append(line);
      });
    } else if (view === 'history') {
      output.append(node('h2', 'welcome-kicker', 'COMMAND HISTORY / THIS SESSION'));
      output.append(node('p', 'welcome-copy', 'Up to 200 local commands. Use ↑ and ↓ in the input to recall them.'));
      active.history.forEach((command, index) => output.append(node('div', 'entry', `${pad(index + 1)}  ${command}`)));
      if (!active.history.length) output.append(node('p', 'empty-view', 'No commands entered yet.'));
    } else {
      output.append(node('h2', 'welcome-kicker', 'LOCAL INTERFACE LOG / THIS SESSION'));
      output.append(node('p', 'welcome-copy', 'Interface events only. These are not CLI output or agent execution records.'));
      active.logs.forEach((entry) => output.append(node('div', 'entry', `${entry.time}  ${entry.message}`)));
    }
    output.scrollTop = output.scrollHeight;
  }
  function execute(raw) {
    const command = raw.trim(); if (!command) return;
    // Avoid retaining commonly pasted credentials, including in history and UI logs.
    if (/sk-[a-z0-9_-]{12,}|-----BEGIN .*PRIVATE KEY|\b(?:password|api[_ -]?key|secret|token)\s*[:=]\s*\S+/i.test(command)) {
      $('#command').value = ''; active.draft = ''; draft = '';
      announce('Possible credential omitted. Do not enter credentials in this preview.');
      appendBounded(active.entries, {kind: 'response', time: time(), text: 'Possible credential omitted. Do not enter credentials in this preview.'});
      view = 'terminal'; render(); return;
    }
    appendBounded(active.history, command);
    historyIndex = active.history.length; draft = ''; active.draft = ''; $('#command').value = '';
    appendBounded(active.entries, {kind: 'command', time: time(), text: `OMNI › ${command}`});
    let response;
    switch (command.toLowerCase()) {
      case 'help': response = 'LOCAL PREVIEW COMMANDS\nhelp       Show this reference\nstatus     Show connection state\nagents     Show agent availability\nsessions   List local preview sessions\nhistory    Open this session’s command history\nlogs       Open this session’s interface log\nclear      Clear visible output (history and logs remain)\n\nUse “New local session” to create a separate command deck.\nCLI commands run in your existing terminal, not in this browser.'; break;
      case 'status': response = 'Interface: local design preview\nAgent transport: not connected\nAgent execution: unavailable\nShell bridge: not connected\nStorage: this tab’s memory only'; break;
      case 'agents': response = 'No agents connected to this interface.\nNo agent runtime is queried; running status is unknown.\nConnecting or launching agents is not available in this preview.'; break;
      case 'sessions': response = sessions.map(s => `${pad(s.id)}  Command deck ${pad(s.id)}  · local preview${s === active ? ' · selected' : ''}`).join('\n'); break;
      case 'history': view = 'history'; break;
      case 'logs': view = 'logs'; break;
      case 'clear': active.entries = []; view = 'terminal'; break;
      default: response = 'Command not available in this preview. Nothing was executed.\nUse help for local UI commands. Run existing evolution commands in your terminal.';
    }
    if (response) { appendBounded(active.entries, {kind: 'response', time: time(), text: response}); view = 'terminal'; }
    log(`Local UI command handled: ${['help','status','agents','sessions','history','logs','clear'].includes(command.toLowerCase()) ? command.toLowerCase() : 'unsupported command (not executed)'}`);
    render(); announce(response || `${view} view updated.`); $('#command').focus();
  }
  $('#command-form').addEventListener('submit', (event) => { event.preventDefault(); execute($('#command').value); });
  $('#command').addEventListener('keydown', (event) => {
    if (!['ArrowUp', 'ArrowDown'].includes(event.key)) return;
    event.preventDefault();
    if (historyIndex === active.history.length) draft = event.target.value;
    historyIndex = Math.max(0, Math.min(active.history.length, historyIndex + (event.key === 'ArrowUp' ? -1 : 1)));
    event.target.value = historyIndex === active.history.length ? draft : active.history[historyIndex];
  });
  $('#command').addEventListener('input', () => { historyIndex = active.history.length; active.draft = $('#command').value; });
  $('#new-session').addEventListener('click', () => { active.draft = $('#command').value; createSession(); $('#command').focus(); });
  $('#clear').addEventListener('click', () => { active.entries = []; view = 'terminal'; log('Visible output cleared; history retained.'); render(); announce('Visible output cleared.'); });
  document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => { view = button.dataset.view; render(); }));
  createSession();
})();
