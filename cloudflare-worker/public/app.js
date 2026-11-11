// League Hub — reads the league's read-only API and renders each page. No build step.
(() => {
  const view = document.getElementById('view');
  const seasonSelect = document.getElementById('season-select');
  const followSelect = document.getElementById('follow-select');
  const state = { meta: null, season: null, follow: '' };

  // ---------- helpers
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const store = {
    get(k) { try { return localStorage.getItem(k) ?? ''; } catch { return ''; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } }
  };
  const one = (n) => (n == null ? '–' : (Math.round(n * 10) / 10).toFixed(1));
  const pg = (total, gp) => (gp ? one(total / gp) : '–');
  const pct = (v) => (v == null ? '–' : `${(v * 100).toFixed(1)}%`);
  const signed = (n) => (n > 0 ? `+${n}` : String(n));
  const when = (iso) => (iso ? new Intl.DateTimeFormat(undefined, { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }).format(new Date(iso)) : '');
  const teamLink = (id, name) => `<a href="#/team/${encodeURIComponent(id)}">${esc(name)}</a>`;
  const playerLink = (id, name) => `<a href="#/player/${encodeURIComponent(id)}">${esc(name)}</a>`;
  const followed = (id) => state.follow && id === state.follow;

  async function api(path) {
    const sep = path.includes('?') ? '&' : '?';
    const res = await fetch(`/api/${path}${state.season ? `${sep}season=${state.season}` : ''}`, { headers: { accept: 'application/json' } });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `The league server returned ${res.status}.`);
    return data;
  }

  function render(html, title) {
    view.innerHTML = html;
    document.title = title ? `${title} – ${state.meta?.league_name ?? 'League Hub'}` : (state.meta?.league_name ?? 'League Hub');
  }

  function fail(error) {
    render(`<p class="error">Couldn't load this page: ${esc(error.message)}</p><p class="note">Check your connection and refresh. If it keeps happening, tell the Commissioner.</p>`);
  }

  // ---------- shared pieces
  function ladder(rows) {
    if (!rows.length) return '<p class="empty">No teams yet. Standings appear once franchises are added.</p>';
    const seeded = rows.filter((r) => r.seed);
    const lastSeed = seeded.length ? Math.max(...seeded.map((r) => r.seed)) : 0;
    let html = '<ol class="ladder">';
    rows.forEach((r, i) => {
      const courtPct = Math.min(100, Math.round((r.on_court / r.on_court_needed) * 100));
      html += `<li class="ladder-row${followed(r.franchise_id) ? ' is-followed' : ''}${r.can_qualify ? '' : ' is-out'}" style="--i:${i}">
        <span class="ladder-rank">${r.rank}</span>
        <div class="ladder-team">
          <a class="ladder-name" href="#/team/${encodeURIComponent(r.franchise_id)}">${esc(r.name)}</a>
          <div class="ladder-meta">
            <span class="court" title="Games actually played (not forfeits or no-report wins) toward the ${r.on_court_needed} needed for playoffs">
              <span class="court-bar${r.on_court >= r.on_court_needed ? ' met' : ''}"><span style="width:${courtPct}%"></span></span>
              ${r.on_court}/${r.on_court_needed} played
            </span>
            <span class="${r.diff > 0 ? 'diff-pos' : r.diff < 0 ? 'diff-neg' : ''}">${signed(r.diff)} diff</span>
            ${r.tie ? '<span class="tag tie">Tie: Commissioner draw</span>' : ''}
            ${r.can_qualify ? '' : '<span>Can\'t reach 32 played</span>'}
          </div>
        </div>
        <span class="ladder-record">${r.w}–${r.l}<small>${r.gp} games</small></span>
      </li>`;
      if (r.seed === 2 && lastSeed > 2) html += '<li class="cutline bye" aria-hidden="true"><span>Bye line: top 2 skip round one</span></li>';
      if (r.seed && r.seed === lastSeed && i < rows.length - 1) html += '<li class="cutline" aria-hidden="true"><span>Playoff line</span></li>';
    });
    return `${html}</ol>`;
  }

  function gameRow(g, { showWeek = false } = {}) {
    const final = g.counted;
    const homeWon = final && g.winner_id === g.home_id;
    const awayWon = final && g.winner_id === g.away_id;
    let right = '';
    let meta = '';
    if (g.result_type === 'Played' && g.home_score != null) right = `<div>${g.home_score}</div><div>${g.away_score}</div>`;
    else if (g.result_type === 'Unreported') { right = '<div>W</div><div>L</div>'; meta = 'No report: home team gets the win'; }
    else if (g.result_type === 'Forfeit') { right = `<div>${homeWon ? 'W' : 'F'}</div><div>${awayWon ? 'W' : 'F'}</div>`; meta = 'Forfeit'; }
    else if (g.result_type === 'Double forfeit') { right = '<div>F</div><div>F</div>'; meta = 'Double forfeit'; }
    else if (g.status === 'Reported') meta = 'Reported, waiting on the other team';
    else if (g.start) meta = when(g.start);
    else meta = g.status === 'Time proposed' ? 'Time proposed, not yet confirmed' : 'Time not set';
    const metaText = [showWeek ? `Week ${g.week}` : '', meta].filter(Boolean).join(', ');
    return `<li class="fixture${followed(g.home_id) || followed(g.away_id) ? ' is-followed' : ''}">
      <div class="teams">
        <div class="${homeWon ? 'won' : ''}">${teamLink(g.home_id, g.home)} <span class="note">home</span></div>
        <div class="${awayWon ? 'won' : ''}">${teamLink(g.away_id, g.away)}</div>
      </div>
      <div class="right score">${right}</div>
      <div class="meta">${esc(metaText)}</div>
    </li>`;
  }

  function sortableTable(columns, rows, { key, dir = 'desc', rowClass = () => '' } = {}) {
    const id = `t${Math.random().toString(36).slice(2, 8)}`;
    let sortKey = key;
    let sortDir = dir;
    const draw = () => {
      const col = columns.find((c) => c.key === sortKey);
      const sorted = rows.slice();
      if (col) {
        sorted.sort((a, b) => {
          const av = col.sort ? col.sort(a) : a[col.key];
          const bv = col.sort ? col.sort(b) : b[col.key];
          const x = typeof av === 'string' ? av.localeCompare(bv) : (av ?? -Infinity) - (bv ?? -Infinity);
          return sortDir === 'asc' ? x : -x;
        });
      }
      const head = columns.map((c) => `<th scope="col"${c.text ? ' class="txt"' : ''}${c.key === sortKey ? ` aria-sort="${sortDir === 'asc' ? 'ascending' : 'descending'}"` : ''}>${c.noSort ? esc(c.label) : `<button type="button" data-key="${c.key}">${esc(c.label)}</button>`}</th>`).join('');
      const body = sorted.map((r) => `<tr class="${rowClass(r)}">${columns.map((c) => `<td class="${[c.cls, c.text ? 'txt' : ''].filter(Boolean).join(' ')}">${c.cell ? c.cell(r) : esc(r[c.key])}</td>`).join('')}</tr>`).join('');
      const el = document.getElementById(id);
      if (el) el.innerHTML = `<table><thead><tr>${head}</tr></thead><tbody>${body || `<tr><td colspan="${columns.length}" class="dim">Nothing here yet.</td></tr>`}</tbody></table>`;
    };
    setTimeout(() => {
      const el = document.getElementById(id);
      if (!el) return;
      el.addEventListener('click', (e) => {
        const btn = e.target.closest('button[data-key]');
        if (!btn) return;
        if (btn.dataset.key === sortKey) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
        else { sortKey = btn.dataset.key; sortDir = columns.find((c) => c.key === sortKey)?.text ? 'asc' : 'desc'; }
        draw();
        el.querySelector(`button[data-key="${sortKey}"]`)?.focus();
      });
      draw();
    });
    return `<div class="table-wrap" id="${id}"></div>`;
  }

  const perGameCols = [
    { key: 'gp', label: 'GP' },
    { key: 'ppg', label: 'PTS', sort: (r) => r.pts / (r.gp || 1), cell: (r) => pg(r.pts, r.gp) },
    { key: 'rpg', label: 'REB', sort: (r) => r.reb / (r.gp || 1), cell: (r) => pg(r.reb, r.gp) },
    { key: 'apg', label: 'AST', sort: (r) => r.ast / (r.gp || 1), cell: (r) => pg(r.ast, r.gp) },
    { key: 'spg', label: 'STL', sort: (r) => r.stl / (r.gp || 1), cell: (r) => pg(r.stl, r.gp) },
    { key: 'bpg', label: 'BLK', sort: (r) => r.blk / (r.gp || 1), cell: (r) => pg(r.blk, r.gp) },
    { key: 'tpg', label: 'TOV', sort: (r) => r.tov / (r.gp || 1), cell: (r) => pg(r.tov, r.gp) },
    { key: 'fg', label: 'FG', sort: (r) => (r.fga ? r.fgm / r.fga : -1), cell: (r) => `${r.fgm}/${r.fga}` },
    { key: 'tp', label: '3P', sort: (r) => r.tpm / (r.gp || 1), cell: (r) => `${r.tpm}/${r.tpa}` },
    { key: 'efg', label: 'eFG%', cell: (r) => pct(r.efg) }
  ];

  // ---------- pages
  async function pageHome() {
    const d = await api('home');
    const leaders = ['pts', 'reb', 'ast'].map((k) => {
      const label = { pts: 'Points per game', reb: 'Rebounds per game', ast: 'Assists per game' }[k];
      const list = d.leaders[k];
      return `<div class="leader-group"><h4>${label}</h4>${list.length ? list.map((p) => `<div class="leader-line">${playerLink(p.player_id, p.name)}<b>${esc(p.value)}</b></div>`).join('') : `<p class="note">Nobody has ${d.leader_min_gp} games yet.</p>`}</div>`;
    }).join('');
    render(`
      <h1 class="page-title">Season ${d.season} standings</h1>
      <p class="page-sub">${d.phase === 'in-season' ? 'Season in progress.' : 'Offseason.'} The top 6 teams that play at least 32 games (forfeits don\'t count) make the playoffs; the top 2 skip the first round.</p>
      <div class="layout">
        <section aria-label="Standings">${ladder(d.standings)}</section>
        <aside>
          <div class="side-block"><h2 class="side-title">Coming up</h2>${d.upcoming.length ? `<ul class="game-list">${d.upcoming.map((g) => gameRow(g)).join('')}</ul>` : '<p class="note">No confirmed game times yet.</p>'}</div>
          <div class="side-block"><h2 class="side-title">Latest results</h2>${d.recent.length ? `<ul class="game-list">${d.recent.map((g) => gameRow(g)).join('')}</ul>` : '<p class="note">No final results yet.</p>'}</div>
          <div class="side-block"><h2 class="side-title">Leaders</h2>${leaders}<p class="note"><a href="#/leaders">All leaders</a></p></div>
        </aside>
      </div>`, 'Standings');
  }

  async function pageSchedule() {
    const d = await api('schedule');
    if (!d.fixtures.length) return render('<h1 class="page-title">Schedule</h1><p class="empty">No games scheduled for this season yet.</p>', 'Schedule');
    const weeks = new Map();
    for (const g of d.fixtures) { if (!weeks.has(g.week)) weeks.set(g.week, []); weeks.get(g.week).push(g); }
    render(`<h1 class="page-title">Season ${d.season} schedule</h1>
      <p class="page-sub">${d.fixtures.filter((g) => g.counted).length} of ${d.fixtures.length} games final.</p>
      ${[...weeks.entries()].map(([w, list]) => `<section class="week"><h2>Week ${w}</h2><ul class="game-list">${list.map((g) => gameRow(g)).join('')}</ul></section>`).join('')}`, 'Schedule');
  }

  async function pageTeams() {
    const d = await api('teams');
    render(`<h1 class="page-title">Teams</h1><p class="page-sub">Rosters, cap sheets, and results for every franchise.</p>
      ${d.teams.length ? `<ul class="team-list">${d.teams.map((t) => `<li>${teamLink(t.franchise_id, t.name)}<span>${t.record ? `${t.record.w}–${t.record.l}` : '0–0'}</span></li>`).join('')}</ul>` : '<p class="empty">No teams yet.</p>'}`, 'Teams');
  }

  async function pageTeam(id) {
    const d = await api(`team/${encodeURIComponent(id)}`);
    const r = d.record;
    const c = d.cap;
    const seasons = Object.entries(c.fp_by_season);
    const meter = (value, max, floor) => `<div class="meter${value > max ? ' over' : ''}"><span style="width:${Math.min(100, (value / max) * 100)}%"></span>${floor ? `<i class="floor" style="left:${Math.min(100, (floor / max) * 100)}%" title="Floor ${floor}"></i>` : ''}</div>`;
    const rosterCols = [
      { key: 'name', label: 'Player', text: true, cls: 'name', cell: (p) => playerLink(p.player_id, p.name) },
      { key: 'tier', label: 'Tier', text: true, sort: (p) => p.pcv },
      { key: 'pcv', label: 'PCV' },
      { key: 'fp_cost', label: 'FP' },
      { key: 'end_season', label: 'Through', cell: (p) => `Season ${p.end_season}${p.option === 'undecided' ? ' + option' : ''}${p.start_season > d.cap_season ? ' (starts next)' : ''}` }
    ];
    render(`
      <div class="hero">
        <h1 class="hero-name">${esc(d.team.name)}</h1>
        <div class="hero-line"><span>Season ${d.season}</span>${r?.seed ? `<span>Seed ${r.seed} if the season ended today</span>` : ''}</div>
      </div>
      <div class="bigstats">
        <div class="bigstat"><b>${r ? `${r.w}–${r.l}` : '0–0'}</b><span>Record</span></div>
        <div class="bigstat"><b>${r ? r.on_court : 0}/${r ? r.on_court_needed : 32}</b><span>Games played (32 needed)</span></div>
        <div class="bigstat"><b>${one(d.scoring.ppg)}</b><span>Points per game</span></div>
        <div class="bigstat"><b>${one(d.scoring.opp_ppg)}</b><span>Allowed per game</span></div>
      </div>

      <h2 class="section-title">Cap sheet, season ${d.cap_season}</h2>
      <div class="capgrid">
        <div>
          <div class="meter-label"><span>Talent (PCV)</span><b>${c.pcv} / ${c.pcv_cap}</b></div>
          ${meter(c.pcv, c.pcv_cap, c.size >= c.roster_min ? c.floor : 0)}
          <p class="note">${c.size} of ${c.roster_max} roster spots used${c.size >= c.roster_min ? `, floor ${c.floor}` : ''}. ${c.franchise_tier} of ${c.franchise_tier_max} Franchise-tier players.</p>
        </div>
        <div>
          ${seasons.map(([y, v]) => `<div class="meter-label"><span>FP committed, season ${y}</span><b>${v} / ${c.fp_cap}</b></div>${meter(v, c.fp_cap)}`).join('<div style="height:10px"></div>')}
          <p class="note">FP bank: ${c.bank} of ${c.bank_max}.</p>
        </div>
      </div>
      <div class="status ${c.legal ? 'ok' : 'bad'}">${c.legal ? 'Roster is legal.' : `Roster needs fixing:<ul>${c.problems.map((p) => `<li>${esc(p)}</li>`).join('')}</ul>`}${c.warnings.length ? `<ul class="warn">${c.warnings.map((w) => `<li>${esc(w)}</li>`).join('')}</ul>` : ''}</div>

      <h2 class="section-title">Contracts</h2>
      ${sortableTable(rosterCols, d.roster, { key: 'pcv' })}
      ${d.dead_cap.length ? `<p class="note">Dead cap: ${d.dead_cap.map((x) => `${esc(x.name)} ${x.fp_cost} FP per season through season ${x.end_season}`).join('; ')}.</p>` : ''}

      <h2 class="section-title">Player stats</h2>
      ${sortableTable([{ key: 'name', label: 'Player', text: true, cls: 'name', cell: (p) => playerLink(p.player_id, p.name) }, ...perGameCols], d.players, { key: 'ppg' })}
      <p class="note">Per game. Forfeits and no-report wins don\'t count toward stats.</p>

      <h2 class="section-title">Games</h2>
      ${d.games.length ? `<ul class="game-list">${d.games.map((g) => gameRow(g, { showWeek: true })).join('')}</ul>` : '<p class="note">No games scheduled.</p>'}
    `, d.team.name);
  }

  async function pagePlayers() {
    const d = await api('players');
    render(`<h1 class="page-title">Players</h1>
      <p class="page-sub">Season ${d.season} averages. Select a column to sort.</p>
      <div class="toolbar"><input class="search" id="player-search" type="search" placeholder="Find a player or team" aria-label="Find a player or team"></div>
      <div id="players-table"></div>`, 'Players');
    const cols = [
      { key: 'name', label: 'Player', text: true, cls: 'name', cell: (p) => playerLink(p.player_id, p.name) },
      { key: 'team', label: 'Team', text: true, cell: (p) => (p.franchise_id ? teamLink(p.franchise_id, p.team) : '<span class="dim">Free agent</span>') },
      ...perGameCols
    ];
    const box = document.getElementById('players-table');
    const draw = (q) => {
      const term = q.trim().toLowerCase();
      const rows = term ? d.players.filter((p) => `${p.name} ${p.team ?? ''}`.toLowerCase().includes(term)) : d.players;
      box.innerHTML = sortableTable(cols, rows, { key: 'ppg', rowClass: (p) => (followed(p.franchise_id) ? 'is-followed' : '') });
    };
    document.getElementById('player-search').addEventListener('input', (e) => draw(e.target.value));
    draw('');
  }

  async function pagePlayer(id) {
    const d = await api(`player/${encodeURIComponent(id)}`);
    const s = d.stats;
    const e = d.eligibility;
    const total = e.appearances + e.credits;
    const k = d.contract;
    const logCols = [
      { key: 'week', label: 'Week' },
      { key: 'opponent', label: 'Opponent', text: true, cell: (g) => `${g.home ? 'vs' : '@'} ${teamLink(g.opponent_id, g.opponent)}` },
      { key: 'score', label: 'Result', text: true, cell: (g) => `<span class="${g.won ? 'w' : 'l'}">${g.won ? 'W' : 'L'}</span> ${esc(g.score)}` },
      { key: 'pts', label: 'PTS' }, { key: 'reb', label: 'REB' }, { key: 'ast', label: 'AST' }, { key: 'stl', label: 'STL' },
      { key: 'blk', label: 'BLK' }, { key: 'tov', label: 'TOV' },
      { key: 'fg', label: 'FG', sort: (g) => g.fgm, cell: (g) => `${g.fgm}/${g.fga}` },
      { key: 'tp', label: '3P', sort: (g) => g.tpm, cell: (g) => `${g.tpm}/${g.tpa}` }
    ];
    render(`
      <div class="hero">
        <h1 class="hero-name">${esc(d.player.name)}</h1>
        <div class="hero-line">${d.player.franchise_id ? teamLink(d.player.franchise_id, d.player.team) : '<span>Free agent</span>'}${d.player.position ? `<span>${esc(d.player.position)}</span>` : ''}<span>Season ${d.season}</span></div>
      </div>
      ${s ? `<div class="bigstats">
        <div class="bigstat"><b>${pg(s.pts, s.gp)}</b><span>Points</span></div>
        <div class="bigstat"><b>${pg(s.reb, s.gp)}</b><span>Rebounds</span></div>
        <div class="bigstat"><b>${pg(s.ast, s.gp)}</b><span>Assists</span></div>
        <div class="bigstat"><b>${pct(s.efg)}</b><span>eFG%</span></div>
        <div class="bigstat"><b>${s.gp}</b><span>Games</span></div>
      </div>` : '<p class="empty">No games played this season yet.</p>'}

      <h2 class="section-title">Playoff eligibility</h2>
      <div class="meter-label"><span>${total >= e.needed ? 'Eligible for the playoffs' : `${e.needed - total} more appearance${e.needed - total === 1 ? '' : 's'} needed`}</span><b>${total} / ${e.needed}</b></div>
      <div class="meter"><span style="width:${Math.min(100, (total / e.needed) * 100)}%"></span></div>
      ${e.credits ? `<p class="note">Includes ${e.credits} forfeit credit${e.credits === 1 ? '' : 's'}.</p>` : ''}

      <h2 class="section-title">Contract</h2>
      ${k ? `<p>${esc(k.tier)} tier, ${k.pcv} PCV, ${k.fp_cost} FP per season, seasons ${k.start_season}–${k.end_season}${k.option === 'undecided' ? ', player option still to decide' : ''}.</p><p class="note">PCV and FP cost stay the same for the whole contract.</p>` : '<p class="note">No active contract.</p>'}

      <h2 class="section-title">Game log</h2>
      ${sortableTable(logCols, d.games, { key: 'week', dir: 'asc' })}
    `, d.player.name);
  }

  async function pageLeaders(category = 'pts') {
    const cats = [['pts', 'Points'], ['reb', 'Rebounds'], ['ast', 'Assists'], ['stl', 'Steals'], ['blk', 'Blocks'], ['tpm', '3-pointers'], ['efg', 'eFG%']];
    const d = await api(`leaders?category=${category}`);
    const meta = await api('players');
    const rule = category === 'efg' ? `At least ${meta.efg_min_gp} games and ${meta.efg_min_fga} shot attempts.` : `Per game, at least ${meta.leader_min_gp} games.`;
    render(`<h1 class="page-title">Leaders</h1>
      <div class="toolbar pills" role="group" aria-label="Category">${cats.map(([k, label]) => `<button type="button" data-cat="${k}" aria-pressed="${k === category}">${label}</button>`).join('')}</div>
      <p class="page-sub">${esc(d.label)}, season ${d.season}. ${rule}</p>
      ${d.leaders.length ? `<div class="table-wrap"><table><thead><tr><th scope="col">Player</th><th scope="col">Team</th><th scope="col">GP</th><th scope="col">${esc(d.label)}</th></tr></thead><tbody>
        ${d.leaders.map((p, i) => `<tr class="${followed(p.franchise_id) ? 'is-followed' : ''}"><td class="name">${i + 1}. ${playerLink(p.player_id, p.name)}</td><td>${p.franchise_id ? teamLink(p.franchise_id, p.team) : ''}</td><td>${p.gp}</td><td><b>${esc(p.value)}</b></td></tr>`).join('')}
      </tbody></table></div>` : '<p class="empty">Nobody qualifies yet.</p>'}`, 'Leaders');
    view.querySelectorAll('button[data-cat]').forEach((b) => b.addEventListener('click', () => { location.hash = `#/leaders/${b.dataset.cat}`; }));
  }

  // ---------- routing
  async function route() {
    const parts = location.hash.replace(/^#\/?/, '').split('/').map(decodeURIComponent);
    const page = parts[0] || 'home';
    document.querySelectorAll('[data-nav]').forEach((a) => {
      const active = a.dataset.nav === page || (page === 'team' && a.dataset.nav === 'teams') || (page === 'player' && a.dataset.nav === 'players') || (page === 'standings' && a.dataset.nav === 'home');
      if (active) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    });
    view.innerHTML = '<p class="loading">Loading…</p>';
    try {
      if (page === 'home' || page === 'standings') await pageHome();
      else if (page === 'schedule') await pageSchedule();
      else if (page === 'teams') await pageTeams();
      else if (page === 'team' && parts[1]) await pageTeam(parts[1]);
      else if (page === 'players') await pagePlayers();
      else if (page === 'player' && parts[1]) await pagePlayer(parts[1]);
      else if (page === 'leaders') await pageLeaders(parts[1] || 'pts');
      else render('<h1 class="page-title">Page not found</h1><p class="note"><a href="#/">Go to the standings</a></p>');
    } catch (error) {
      fail(error);
    }
    view.focus({ preventScroll: true });
  }

  async function start() {
    try {
      state.meta = await (await fetch('/api/meta')).json();
    } catch {
      state.meta = null;
    }
    if (!state.meta || state.meta.error) {
      fail(new Error(state.meta?.error || 'The league server could not be reached.'));
      return;
    }
    document.getElementById('league-name').textContent = state.meta.league_name;
    state.season = state.meta.season;
    seasonSelect.innerHTML = state.meta.seasons.slice().reverse().map((s) => `<option value="${s}"${s === state.season ? ' selected' : ''}>Season ${s}</option>`).join('');
    followSelect.innerHTML = '<option value="">No team</option>' + state.meta.teams.map((t) => `<option value="${esc(t.franchise_id)}">${esc(t.name)}</option>`).join('');
    state.follow = store.get('follow');
    if (!state.meta.teams.some((t) => t.franchise_id === state.follow)) state.follow = '';
    followSelect.value = state.follow;
    seasonSelect.addEventListener('change', () => { state.season = Number(seasonSelect.value); route(); });
    followSelect.addEventListener('change', () => { state.follow = followSelect.value; store.set('follow', state.follow); route(); });
    window.addEventListener('hashchange', route);
    route();
  }

  start();
})();
