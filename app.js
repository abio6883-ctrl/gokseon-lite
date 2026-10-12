// 곡선중 교사 간편판 — 학교 PC가 꺼져 있어도 폰에서 보는 읽기 전용 화면
// 자료는 학교 비밀번호로 암호화되어 있고, 이 폰 안에서만 풀립니다.
(() => {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const store = { get: k => { try { return localStorage.getItem('gl.' + k); } catch { return null; } }, set: (k, v) => { try { v == null ? localStorage.removeItem('gl.' + k) : localStorage.setItem('gl.' + k, v); } catch { /* */ } } };
  const DOW = ['일', '월', '화', '수', '목', '금', '토'];
  const pad = n => String(n).padStart(2, '0');
  const ymd = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  const parse = s => { const [y, m, d] = s.split('-').map(Number); return new Date(y, m - 1, d); };
  const fmt = s => { const d = parse(s); return `${d.getMonth() + 1}/${d.getDate()}(${DOW[d.getDay()]})`; };
  const CAT = { 학사: '#2563eb', 행사: '#16a34a', 시험: '#dc2626', '방학·휴업': '#9333ea', 연수: '#ea580c', 회의: '#0891b2', 기타: '#64748b' };
  const catColor = c => CAT[c] || '#64748b';
  // D: 화면에 보이는 자료, KEY: 공용(양식) 열쇠, P: 내 개인 자료(로그인한 경우), PKEY: 내 상자 열쇠, UH: 내 상자 파일 이름
  let D = null, KEY = null, META = null, P = null, PKEY = null, UH = '', tab = store.get('tab') || 'today';

  // ── 암호 풀기 (PBKDF2-SHA256 → AES-GCM)
  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  async function deriveKey(pass) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64(META.salt), iterations: META.iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  }
  async function decrypt(buf) {
    const u = new Uint8Array(buf);
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, KEY, u.slice(12));
  }
  async function gunzip(buf) {
    const s = new Blob([buf]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Response(s).text();
  }

  // ── 시작
  async function boot() {
    // 주소 뒤에 시각·버전을 붙여 인터넷 캐시에 남은 옛 파일 대신 최신 파일을 받는다
    try { META = await fetch('meta.json?t=' + Date.now(), { cache: 'no-store' }).then(r => r.json()); }
    catch { return lock('인터넷 연결을 확인해 주세요. (한 번 열어 본 폰은 연결이 없어도 열립니다)'); }
    // 이 기기에 로그인 유지가 되어 있으면 바로 열기
    const su = store.get('user'), sk = store.get('ukey');
    if (su && sk && META.ns) { try { await openUser(su, null, b64(sk)); shell(); return; } catch { store.set('ukey', null); } }
    const saved = store.get('pass');
    if (saved) { try { await unlock(saved, true); return; } catch { store.set('pass', null); } }
    lock();
  }
  // ── 아이디·비밀번호 로그인: 내 상자(u/○○.bin)를 내 비밀번호로 열고, 그 안의 열쇠로 교직원판(staff.bin)을 연다
  async function sha256hex(t) { const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t)); return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join(''); }
  async function openUser(username, password, rawKey) {
    UH = (await sha256hex(META.ns + ':' + username)).slice(0, 32);
    const r = await fetch(`u/${UH}.bin?v=${META.at}`, { cache: 'no-store' });
    if (r.status === 404) throw new Error('nouser');
    if (!r.ok) throw new Error('상자를 받지 못했어요');
    const u = new Uint8Array(await r.arrayBuffer());
    if (rawKey) PKEY = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
    else {
      const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
      const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: u.slice(0, 16), iterations: META.piter || META.iter, hash: 'SHA-256' }, base, 256);
      rawKey = new Uint8Array(bits);
      PKEY = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
    }
    let plain;
    try { plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(16, 28) }, PKEY, u.slice(28)); } catch { throw new Error('pass'); }
    P = JSON.parse(await gunzip(plain));
    KEY = await crypto.subtle.importKey('raw', b64(P.staffKey), 'AES-GCM', false, ['decrypt']);
    const sb = await fetch('staff.bin?v=' + META.at, { cache: 'no-store' }).then(x => { if (!x.ok) throw new Error('교직원판 없음'); return x.arrayBuffer(); });
    D = JSON.parse(await gunzip(await decrypt(sb)));
    if (!store.get('me') && P.me?.name) store.set('me', P.me.name);
    return rawKey;
  }
  function lock(msg = '') {
    $('#app').innerHTML = `<div class="lock">
      <div class="lk-top"><img class="lk-ava" src="mascot.png" alt=""><div class="lk-bub">안녕하세요! <b>꿈송이</b>예요 💛<br><span>선생님 전용 간편판이에요</span></div></div>
      <h1>${esc(META?.school || '곡선중학교')}<small>교사 간편판</small></h1>
      <p class="lk-desc">학교 PC가 꺼져 있어도 일정·공지·급식·업무 자료·내선번호를 볼 수 있어요. 학생 개인정보는 들어 있지 않습니다.</p>
      ${META?.ns ? `<form id="uf"><h3 class="lk-h">🙋 내 계정으로 로그인 <small>웹 포털과 같은 아이디·비밀번호</small></h3>
        <input id="un" autocomplete="username" placeholder="아이디" required autocapitalize="off" spellcheck="false">
        <input id="up" type="password" autocomplete="current-password" placeholder="비밀번호" required>
        <label class="lk-keep"><input type="checkbox" id="ukeep" checked> 이 기기에서 로그인 유지 <small>(로그아웃하거나 비밀번호를 바꿀 때까지)</small></label>
        <button class="btn primary big">로그인</button>
        <p class="lk-note">내 할 일·메모·우리 반 학생·교직원 연락처까지 볼 수 있어요.</p></form>
      <details class="lk-alt"><summary>공용 비밀번호로 보기 (개인 정보 없이)</summary>` : ''}
      <form id="lf"><input id="pw" type="password" inputmode="text" autocomplete="off" placeholder="학교에서 받은 간편판 공용 비밀번호" required>
        <label class="lk-keep"><input type="checkbox" id="keep" checked> 이 기기에서 기억하기</label>
        <button class="btn big">공용 비밀번호로 열기</button></form>
      ${META?.ns ? '</details>' : ''}
      <p class="lk-err">${esc(msg)}</p>
      <p class="made">Made by Lee Jae Kwang</p></div>`;
    $('#lf').onsubmit = async e => {
      e.preventDefault();
      const btn = $('#lf button'); btn.disabled = true; btn.textContent = '여는 중…';
      try { await unlock($('#pw').value, false); if ($('#keep').checked) store.set('pass', $('#pw').value); }
      catch (err) { $('.lk-err').textContent = err.message === 'pass' ? '비밀번호가 맞지 않아요. 학교 관리자(JK Lee)에게 확인해 주세요.' : '자료를 열지 못했어요: ' + err.message; btn.disabled = false; btn.textContent = '공용 비밀번호로 열기'; }
    };
    $('#uf')?.addEventListener('submit', async e => {
      e.preventDefault();
      const btn = $('#uf button'); btn.disabled = true; btn.textContent = '로그인 중…';
      const name = $('#un').value.trim();
      try {
        const raw = await openUser(name, $('#up').value, null);
        if ($('#ukeep').checked) { store.set('user', name); store.set('ukey', btoa(String.fromCharCode(...raw))); try { navigator.storage?.persist?.(); } catch { /* */ } }
        shell();
      } catch (err) {
        $('.lk-err').textContent = err.message === 'nouser' ? '이 아이디의 간편판이 아직 없어요. 학교에서 웹 포털에 한 번 로그인하면 다음 갱신(10분 안팎) 때 생겨요.'
          : err.message === 'pass' ? '비밀번호가 맞지 않아요. (웹 포털에서 비밀번호를 바꿨다면 갱신 뒤 새 비밀번호로)' : '열지 못했어요: ' + err.message;
        btn.disabled = false; btn.textContent = '로그인';
      }
    });
  }
  async function unlock(pass, quiet) {
    KEY = await deriveKey(pass);
    const buf = await fetch('data.bin?v=' + META.at, { cache: 'no-store' }).then(r => { if (!r.ok) throw new Error('자료 파일 없음'); return r.arrayBuffer(); });
    let plain;
    try { plain = await decrypt(buf); } catch { throw new Error('pass'); }
    D = JSON.parse(await gunzip(plain));
    shell();
  }

  // ── 화면 틀
  const TABS = [['today', '🏠', '오늘'], ['cal', '📅', '일정'], ['notice', '📢', '공지'], ['me', '🙋', '나'], ['find', '🔎', '찾기'], ['contact', '☎️', '연락처']];
  function shell() {
    // 로그인한 경우에만 '나' 탭이 보인다
    const tabs = TABS.filter(t => t[0] !== 'me' || P);
    if (!tabs.some(t => t[0] === tab)) tab = 'today';
    document.body.classList.add('in');
    $('#app').innerHTML = `<header class="top"><div class="brand"><img src="mascot.png" alt=""><div><b>${esc(D.school)}</b><small>교사 간편판 · ${new Date(D.at).toLocaleString('ko-KR', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' })} 기준</small></div></div>
      <button class="ic" id="out" title="잠그기">🔒</button></header>
      <main id="view"></main>
      <nav class="tabs t${tabs.length}">${tabs.map(([k, i, l]) => `<button data-tab="${k}"><span>${i}</span>${l}</button>`).join('')}</nav>`;
    if (P) $('.brand small').textContent = `${P.me.name} 선생님 · ` + $('.brand small').textContent;
    $$('[data-tab]').forEach(b => b.onclick = () => go(b.dataset.tab));
    $('#out').onclick = () => { if (confirm(P ? '로그아웃할까요? 다음에 열 때 아이디·비밀번호를 다시 넣어야 해요.' : '잠글까요? 다음에 열 때 비밀번호를 다시 넣어야 해요.')) { store.set('pass', null); store.set('ukey', null); KEY = null; D = null; P = null; PKEY = null; lock(); } };
    go(tab);
  }
  function go(t, arg) {
    tab = t; store.set('tab', t);
    $$('[data-tab]').forEach(b => b.classList.toggle('on', b.dataset.tab === t));
    const v = $('#view'); v.scrollTop = 0; window.scrollTo(0, 0);
    v.className = 'v-' + t + (arg ? ' v-detail' : ''); // 노트북 화면에서 탭마다 배치를 다르게
    ({ today, cal, notice, find, contact, me: meTab }[t] || today)(v, arg);
  }

  // ── 간단한 글 표시 (굵게·빨간 강조·형광펜·큰 글씨·목록·표)
  function md(t, q) {
    let h = esc(t);
    h = h.replace(/!!(.+?)!!/g, '<b class="red">$1</b>').replace(/==(.+?)==/g, '<mark>$1</mark>').replace(/\+\+(.+?)\+\+/g, '<span class="big">$1</span>').replace(/\*\*(.+?)\*\*/g, '<b>$1</b>');
    if (q) for (const w of q.split(/\s+/).filter(x => x.length >= 2)) h = h.replace(new RegExp(w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), m => `<mark class="hit">${m}</mark>`);
    return h.split('\n').map(l => /\|/.test(l) ? `<div class="tr">${l.split('|').map(c => `<span>${c.trim()}</span>`).join('')}</div>` : /^\s*[-•]\s+/.test(l) ? `<div class="li">• ${l.replace(/^\s*[-•]\s+/, '')}</div>` : l.trim() ? `<p>${l}</p>` : '').join('');
  }

  // ── 시간표 도우미
  const teachers = () => [...new Set(Object.values(D.timetable.days).flatMap(day => Object.values(day).flat().filter(Boolean).map(c => c[1]).filter(n => n && n.length >= 2)))].sort((a, b) => a.localeCompare(b, 'ko'));
  const myDay = (who, ds) => { const day = D.timetable.days[ds]; if (!day) return null; const out = []; for (const [cls, ps] of Object.entries(day)) ps.forEach((c, i) => { if (c && c[1] === who) out[i] = { p: i + 1, cls, s: c[0], ch: c[2] }; }); return out; };
  const ptime = p => D.timetable.periods.find(x => x.n === p)?.time || '';
  function nowPeriod() {
    const d = new Date(), m = d.getHours() * 60 + d.getMinutes();
    for (const p of D.timetable.periods) { const [h, mm] = p.time.split(':').map(Number); if (m >= h * 60 + mm && m < h * 60 + mm + 45) return p.n; }
    return 0;
  }

  // ── 🏠 오늘
  function today(v) {
    const t = ymd(new Date()), d = new Date();
    const meal = D.meals.filter(m => m.d === t);
    const nextMeal = !meal.length ? D.meals.find(m => m.d > t) : null;
    const todays = D.events.filter(e => e.s <= t && (e.e || e.s) >= t);
    const week = D.events.filter(e => e.s > t && e.s <= ymd(new Date(Date.now() + 7 * 864e5)));
    const me = store.get('me');
    const mine = me ? myDay(me, t) : null;
    const cur = nowPeriod();
    const L = D.links;
    v.innerHTML = `<section class="hello"><div><small>${d.getFullYear()}년 ${d.getMonth() + 1}월 ${d.getDate()}일 ${DOW[d.getDay()]}요일</small><h2>${me ? esc(me) + ' 선생님,' : '선생님,'} 좋은 하루 되세요 🌼</h2></div></section>
      <section class="card"><h3>🕘 내 시간표 <button class="lnk" id="pickMe">${me ? '바꾸기' : '내 이름 고르기'}</button></h3>
        ${!me ? '<p class="faint">내 이름을 고르면 오늘 수업이 여기에 나와요.</p>' : !mine ? '<p class="faint">오늘은 수업 정보가 없어요 (주말·휴일).</p>' : `<div class="pds">${D.timetable.periods.map(p => { const c = mine[p.n - 1]; return `<div class="pd ${c ? '' : 'free'} ${cur === p.n ? 'now' : ''}"><small>${p.n}교시 ${p.time}</small>${c ? `<b>${esc(c.cls)}</b><span>${esc(c.s)}${c.ch ? ' ↺' : ''}</span>` : '<span>공강</span>'}</div>`; }).join('')}</div>
        <button class="lnk" id="weekTT">이번 주 전체 보기 →</button>`}</section>
      <section class="card"><h3>🍚 ${meal.length ? '오늘의 급식' : nextMeal ? fmt(nextMeal.d) + ' 급식' : '급식'}</h3>${(meal.length ? meal : nextMeal ? [nextMeal] : []).map(m => `<div class="meal"><b>${esc(m.type)}</b> <small>${esc(m.kcal)}</small><div>${m.dishes.map(esc).join(' · ')}</div></div>`).join('') || '<p class="faint">급식 정보가 없어요.</p>'}</section>
      <section class="card"><h3>📅 오늘 일정</h3>${todays.length ? todays.map(evRow).join('') : '<p class="faint">오늘은 등록된 일정이 없어요.</p>'}
        ${week.length ? `<h4>다가오는 7일</h4>${week.slice(0, 8).map(evRow).join('')}` : ''}<button class="lnk" data-go="cal">학사일정 전체 →</button></section>
      ${D.notices.length ? `<section class="card"><h3>📢 공지사항</h3>${D.notices.slice().sort((a, b) => b.pin - a.pin || b.at - a.at).slice(0, 3).map(n => `<button class="row" data-notice="${n.id}">${n.imp ? '<span class="tag red">중요</span>' : ''}<span class="grow">${esc(n.t)}</span><small>${new Date(n.at).toLocaleDateString('ko-KR', { month: 'numeric', day: 'numeric' })}</small></button>`).join('')}</section>` : ''}
      <section class="card links"><h3>🔗 바로가기</h3><div class="lk">
        ${L.portal ? `<a href="${esc(L.portal)}" target="_blank" rel="noopener">🏫 전체 포털 <small>학교 PC 켜져 있을 때</small></a>` : ''}
        <a href="${L.goe}" target="_blank" rel="noopener">🏛️ 경기도교육청</a><a href="${L.gone}" target="_blank" rel="noopener">🌐 교육공동체포털(지원이)</a><a href="${L.home}" target="_blank" rel="noopener">🏫 곡선중 홈페이지</a></div></section>
      <p class="made">학생 개인정보는 들어 있지 않은 간편판입니다 · Made by Lee Jae Kwang</p>`;
    $('#pickMe').onclick = pickMe;
    $('#weekTT')?.addEventListener('click', () => weekTT(me));
    bindCommon(v);
  }
  const evRow = e => `<div class="ev"><i style="background:${catColor(e.c)}"></i><div class="grow"><b>${esc(e.t)}</b><small>${fmt(e.s)}${e.e ? ' ~ ' + fmt(e.e) : ''}${e.time ? ' · ' + esc(e.time) : ''}${e.p ? ' · ' + esc(e.p) : ''}</small></div><span class="tag" style="color:${catColor(e.c)}">${esc(e.c)}</span></div>`;
  function pickMe() {
    const list = teachers();
    sheet(`<h3>내 이름 고르기</h3><input id="tq" placeholder="이름 검색" autocomplete="off"><div class="pick" id="tl"></div>`, el => {
      const draw = q => { $('#tl', el).innerHTML = list.filter(n => !q || n.includes(q)).map(n => `<button data-n="${esc(n)}">${esc(n)}</button>`).join('') || '<p class="faint">없어요</p>'; };
      draw(''); $('#tq', el).oninput = e => draw(e.target.value.trim());
      $('#tl', el).onclick = e => { const b = e.target.closest('[data-n]'); if (!b) return; store.set('me', b.dataset.n); close(); go('today'); };
    });
  }
  function weekTT(who, cls) {
    const days = Object.keys(D.timetable.days).sort();
    const t = ymd(new Date());
    const classes = Object.keys(D.timetable.days[days[0]] || {}).sort();
    const render = (mode, val) => {
      const head = days.map(ds => `<th class="${ds === t ? 'tod' : ''}">${fmt(ds)}</th>`).join('');
      const rows = D.timetable.periods.map(p => `<tr><th>${p.n}<small>${p.time}</small></th>${days.map(ds => {
        const day = D.timetable.days[ds];
        if (mode === 'me') { const c = (myDay(val, ds) || [])[p.n - 1]; return `<td class="${ds === t ? 'tod' : ''}">${c ? `<b>${esc(c.cls)}</b><br><small>${esc(c.s)}</small>` : ''}</td>`; }
        const c = day?.[val]?.[p.n - 1]; return `<td class="${ds === t ? 'tod' : ''}">${c ? `<b>${esc(c[0])}</b><br><small>${esc(c[1])}</small>` : ''}</td>`;
      }).join('')}</tr>`).join('');
      return `<div class="ttw"><table class="tt"><thead><tr><th></th>${head}</tr></thead><tbody>${rows}</tbody></table></div>`;
    };
    sheet(`<h3>🕘 시간표 (이번 주·다음 주)</h3><div class="seg" id="ttm"><button data-m="me" class="${who ? 'on' : ''}">내 시간표</button>${classes.map(c => `<button data-m="${c}" class="${!who && c === (cls || classes[0]) ? 'on' : ''}">${c}</button>`).join('')}</div><div id="ttb"></div>`, el => {
      const show = m => { $$('#ttm button', el).forEach(b => b.classList.toggle('on', b.dataset.m === m)); $('#ttb', el).innerHTML = m === 'me' ? (who ? render('me', who) : '<p class="faint">오늘 화면에서 내 이름을 먼저 골라 주세요.</p>') : render('cls', m); };
      show(who ? 'me' : cls || classes[0]);
      $('#ttm', el).onclick = e => { const b = e.target.closest('[data-m]'); if (b) show(b.dataset.m); };
    }, true);
  }

  // ── 📅 일정 (달별)
  function cal(v, ym) {
    const t = new Date(); let cur = ym || store.get('ym') || `${t.getFullYear()}-${pad(t.getMonth() + 1)}`;
    const draw = () => {
      store.set('ym', cur);
      const [y, m] = cur.split('-').map(Number);
      const start = `${cur}-01`, end = ymd(new Date(y, m, 0));
      const list = D.events.filter(e => e.s <= end && (e.e || e.s) >= start);
      const byDay = {};
      for (const e of list) { const k = e.s < start ? start : e.s; (byDay[k] ||= []).push(e); }
      const todayS = ymd(t);
      v.innerHTML = `<div class="mhead"><button class="ic" id="pm">◀</button><h2>${y}년 ${m}월</h2><button class="ic" id="nm">▶</button></div>
        <div class="legend">${Object.entries(CAT).map(([k, c]) => `<span><i style="background:${c}"></i>${k}</span>`).join('')}</div>
        ${Object.keys(byDay).sort().map(ds => `<section class="day ${ds === todayS ? 'tod' : ''} ${ds < todayS ? 'past' : ''}"><div class="dd"><b>${parse(ds).getDate()}</b><small>${DOW[parse(ds).getDay()]}</small></div><div class="grow">${byDay[ds].map(e => `<div class="ce"><i style="background:${catColor(e.c)}"></i><span><b>${esc(e.t)}</b>${e.e ? `<small> ~ ${fmt(e.e)}</small>` : ''}${e.time ? `<small> · ${esc(e.time)}</small>` : ''}</span></div>`).join('')}</div></section>`).join('') || '<p class="faint center">이 달에는 일정이 없어요.</p>'}
        <button class="btn" id="ttAll" style="width:100%;margin-top:12px">🕘 반별·내 시간표 보기</button>`;
      $('#pm').onclick = () => { const d = new Date(y, m - 2, 1); cur = `${d.getFullYear()}-${pad(d.getMonth() + 1)}`; draw(); };
      $('#nm').onclick = () => { const d = new Date(y, m, 1); cur = `${d.getFullYear()}-${pad(d.getMonth() + 1)}`; draw(); };
      $('#ttAll').onclick = () => weekTT(store.get('me'));
      setTimeout(() => $('.day.tod')?.scrollIntoView({ block: 'center' }), 50);
    };
    draw();
  }

  // ── 📢 공지
  function notice(v, id) {
    const list = D.notices.slice().sort((a, b) => b.pin - a.pin || b.at - a.at);
    if (id) {
      const n = list.find(x => x.id === id);
      if (n) {
        v.innerHTML = `<button class="back" data-go="notice">← 공지 목록</button><article class="card doc"><div class="tags">${n.pin ? '<span class="tag">📌 고정</span>' : ''}${n.imp ? '<span class="tag red">중요</span>' : ''}<span class="tag">${esc(n.d)}</span></div>
          <h2 class="${n.imp ? 'redt' : ''}">${esc(n.t)}</h2><small class="faint">${new Date(n.at).toLocaleDateString('ko-KR')}${n.end ? ` · ${fmt(n.end)}까지 게시` : ''}</small><div class="body">${md(n.b)}</div></article>`;
        return bindCommon(v);
      }
    }
    v.innerHTML = `<h2 class="pt">📢 공지사항</h2>${list.length ? list.map(n => `<button class="row card-row" data-notice="${n.id}">${n.imp ? '<span class="tag red">중요</span>' : ''}<span class="grow"><b>${esc(n.t)}</b><small>${esc(n.d)} · ${new Date(n.at).toLocaleDateString('ko-KR', { month: 'numeric', day: 'numeric' })}${n.end ? ` · ~${fmt(n.end)}` : ''}</small></span><span>›</span></button>`).join('') : '<p class="faint center">지금 게시 중인 공지가 없어요.</p>'}`;
    bindCommon(v);
  }

  // ── 🔎 찾기 (업무 자료·규정·업무절차·양식·공지·일정·업체)
  const KINDS = ['전체', '자료', '업무절차', '규정', '양식', '파일'];
  function find(v, arg) {
    let q = store.get('q') || '', kind = '전체';
    if (arg?.doc != null) return docView(v, arg.doc, arg.q);
    v.innerHTML = `<h2 class="pt">🔎 업무 자료 찾기</h2><input id="fq" type="search" placeholder="예: 체험학습, 출결, 외부강의, 정기시험" value="${esc(q)}" autocomplete="off">
      <div class="chips" id="kd">${KINDS.map(k => `<button data-k="${k}" class="${k === kind ? 'on' : ''}">${k}</button>`).join('')}</div>
      <div id="fr"></div>
      <p class="faint small center">학교 PC가 꺼져 있어도 찾을 수 있어요. 양식은 내려받기도 됩니다.</p>`;
    const draw = () => {
      store.set('q', q);
      const words = q.toLowerCase().split(/\s+/).filter(Boolean);
      if (!words.length) {
        const forms = D.forms;
        $('#fr').innerHTML = `<h4>📥 양식함 (${forms.length})</h4>${forms.map(f => `<button class="row card-row" data-dl="${f.id}"><span class="fi">📝</span><span class="grow"><b>${esc(f.name.replace(/_/g, ' '))}</b><small>${esc(f.g)} · ${Math.max(1, Math.round(f.size / 1024))}KB</small></span><span class="dlb">⬇</span></button>`).join('')}
          <h4>🧭 업무절차·자료</h4>${D.docs.map((d, i) => [d, i]).filter(([d]) => d.k === '업무절차' || d.k === '자료').map(([d, i]) => docRow(d, i)).join('')}`;
        return;
      }
      const hits = D.docs.map((d, i) => {
        const tl = d.t.toLowerCase(), xl = d.x.toLowerCase();
        if (kind !== '전체' && d.k !== kind) return null;
        if (!words.every(w => tl.includes(w) || xl.includes(w))) return null;
        const score = words.reduce((a, w) => a + (tl.includes(w) ? 10 : 0) + Math.min(5, xl.split(w).length - 1), 0) + (d.k === '업무절차' || d.k === '자료' ? 3 : 0);
        return { d, i, score };
      }).filter(Boolean).sort((a, b) => b.score - a.score).slice(0, 40);
      const evs = kind === '전체' ? D.events.filter(e => words.every(w => e.t.toLowerCase().includes(w))).slice(0, 6) : [];
      const vds = kind === '전체' ? D.vendors.filter(x => words.every(w => [x.n, x.c, x.items, x.memo].join(' ').toLowerCase().includes(w))).slice(0, 6) : [];
      $('#fr').innerHTML = `${evs.length ? `<h4>📅 일정</h4>${evs.map(evRow).join('')}` : ''}
        ${vds.length ? `<h4>🏢 업체·기관</h4>${vds.map(vRow).join('')}` : ''}
        <h4>📚 자료 ${hits.length}건</h4>${hits.map(h => docRow(h.d, h.i, words)).join('') || '<p class="faint">찾는 자료가 없어요. 낱말을 줄여 보세요.</p>'}`;
    };
    $('#fq').oninput = e => { q = e.target.value.trim(); draw(); };
    $('#kd').onclick = e => { const b = e.target.closest('[data-k]'); if (!b) return; kind = b.dataset.k; $$('#kd button').forEach(x => x.classList.toggle('on', x === b)); draw(); };
    $('#fr').onclick = e => { const b = e.target.closest('[data-doc]'); if (b) go('find', { doc: Number(b.dataset.doc), q }); };
    draw(); bindCommon(v);
  }
  function snip(x, words) {
    const t = x.replace(/\s+/g, ' ');
    let p = words?.length ? t.toLowerCase().indexOf(words[0]) : 0; if (p < 0) p = 0;
    return esc(t.slice(Math.max(0, p - 30), p + 90)).replace(/(\s*\|\s*)+/g, ' · ');
  }
  const docRow = (d, i, words) => `<button class="row card-row" data-doc="${i}"><span class="fi">${{ 자료: '📘', 업무절차: '🧭', 규정: '📜', 양식: '📝', 파일: '📄' }[d.k] || '📄'}</span><span class="grow"><b>${esc(d.t)}</b><small>${esc(d.k)}${d.g ? ' · ' + esc(d.g) : ''}</small>${words ? `<em>${snip(d.x, words)}</em>` : ''}</span><span>›</span></button>`;
  function docView(v, i, q) {
    const d = D.docs[i];
    v.innerHTML = `<button class="back" data-go="find">← 찾기로</button><article class="card doc"><div class="tags"><span class="tag">${esc(d.k)}</span>${d.g ? `<span class="tag">${esc(d.g)}</span>` : ''}</div><h2>${esc(d.t)}</h2>
      ${d.f ? `<button class="btn primary" data-dl="${d.f}" style="width:100%;margin:10px 0">⬇ 양식 파일 내려받기</button>` : ''}
      <div class="body">${md(d.x, q)}</div></article>`;
    bindCommon(v);
    setTimeout(() => $('.hit', v)?.scrollIntoView({ block: 'center' }), 60);
  }

  // ── 🙋 나: 내 할 일·메모·서명할 문서·우리 반 학생·내 자료 (로그인한 경우)
  const tel = p => String(p || '').replace(/[^\d]/g, '');
  const SPN = { 시간제: '특수', 복합: '복합', 순회: '순회' };
  const subList = () => Array.isArray(P?.subCls) ? P.subCls : P?.subCls ? [P.subCls] : [];
  function meTab(v, sub) {
    if (!P) return today(v);
    const m = P.me, todo = P.todos || [], left = todo.filter(t => !t.done);
    const clsCard = (c, label) => !c ? '' : `<section class="card"><h3>👨‍👩‍👧 ${label} ${esc(c.key)}반 <small class="faint">${c.students.length}명</small></h3>
      <input class="cls-q" data-cls="${esc(c.key)}" type="search" placeholder="이름·번호 검색" autocomplete="off">
      <div class="stu-list" data-list="${esc(c.key)}">${c.students.map(stuRow).join('')}</div></section>`;
    v.innerHTML = `<section class="hello"><small>${esc(m.dept || '')}${m.position ? ' · ' + esc(m.position) : ''}${m.ext ? ' · 내선 ' + esc(m.ext) : ''}</small><h2>${esc(m.name)} 선생님</h2>
        ${m.homeroom ? `<span class="tag">${esc(m.homeroom)} 담임</span>` : ''}${m.sub ? ` <span class="tag">${esc(m.sub)} 부담임</span>` : ''}${m.subject ? ` <span class="tag">${esc(m.subject)}</span>` : ''}</section>
      ${P.sign?.length ? `<section class="card warn-card"><h3>✍️ 서명할 문서 <span class="tag red">${P.sign.length}</span></h3>${P.sign.map(s => `<div class="ev"><div class="grow"><b>${esc(s.t)}</b><small>${esc(s.kind)}${s.due ? ' · 기한 ' + fmt(s.due) : ''}</small></div></div>`).join('')}<p class="faint small">서명은 학교 포털에서 할 수 있어요.</p></section>` : ''}
      <section class="card"><h3>✅ 나의 할 일 <small class="faint">남은 일 ${left.length}</small></h3>${todo.length ? todo.map(t => `<div class="todo ${t.done ? 'done' : ''}"><span>${t.done ? '☑' : '☐'}</span><span class="grow">${esc(t.t)}</span>${t.due ? `<small class="${!t.done && t.due < ymd(new Date()) ? 'red' : ''}">${fmt(t.due)}</small>` : ''}</div>`).join('') : '<p class="faint">할 일이 없어요.</p>'}</section>
      ${P.memos?.length ? `<section class="card"><h3>📝 내 메모</h3><div class="memos">${P.memos.map(mm => `<div class="memo c-${esc(mm.color)}"><b>${esc(mm.title || '메모')}</b>${mm.mode === 'note' ? `<p>${esc(mm.text).replace(/\n/g, '<br>')}</p>` : mm.rows.map(r => `<div class="${r.done ? 'done' : ''}">${r.done ? '☑' : '☐'} ${esc(r.t)}</div>`).join('')}</div>`).join('')}</div></section>` : ''}
      ${clsCard(P.cls, '우리 반')}${subList().map(c => clsCard(c, '부담임')).join('')}
      ${P.files?.length ? `<section class="card"><h3>📁 내가 올린 자료 <small class="faint">${P.files.length}개</small></h3>${P.files.slice(0, 40).map(f => `<button class="row" ${f.has ? `data-myf="${f.id}"` : ''}><span class="fi">📄</span><span class="grow"><b>${esc(f.name.replace(/_/g, ' '))}</b><small>${esc(f.g)} · ${Math.max(1, Math.round(f.size / 1024))}KB${f.has ? '' : ' · 학교 포털에서만'}</small></span>${f.has ? '<span class="dlb">⬇</span>' : ''}</button>`).join('')}</section>` : ''}
      <p class="faint small center">간편판은 보기 전용이에요. 고치려면 학교 포털에서 — 바꾼 내용은 학교 PC가 켜져 있을 때 10분 안에 여기에 반영돼요.</p>`;
    $$('.cls-q', v).forEach(i => i.oninput = () => {
      const c = [P.cls, ...subList()].find(x => x && x.key === i.dataset.cls), q = i.value.trim();
      $(`[data-list="${i.dataset.cls}"]`, v).innerHTML = c.students.filter(s => !q || s.name.includes(q) || String(s.num) === q).map(stuRow).join('');
    });
    bindCommon(v);
  }
  const stuRow = s => `<div class="stu ${s.st === '전출' ? 'gone' : ''}"><div class="stu-h"><span class="num">${s.num}</span><b>${esc(s.name)}</b>${s.g ? `<small>${esc(s.g)}</small>` : ''}${s.sp ? `<span class="tag">${SPN[s.sp] || esc(s.sp)}</span>` : ''}${s.st ? `<span class="tag">${esc(s.st)}</span>` : ''}</div>
    <div class="tels">${s.ph ? `<a class="tel m" href="tel:${tel(s.ph)}">📱 학생 ${esc(s.ph)}</a>` : ''}${s.pp ? `<a class="tel" href="tel:${tel(s.pp)}">👪 ${esc(s.pn || '보호자')} ${esc(s.pp)}</a><a class="tel sms" href="sms:${tel(s.pp)}">💬</a>` : ''}${s.pp2 ? `<a class="tel" href="tel:${tel(s.pp2)}">👪 ${esc(s.pp2)}</a>` : ''}${!s.ph && !s.pp ? '<small class="faint">등록된 연락처 없음</small>' : ''}</div>
    ${s.notes ? `<small class="stu-n">📌 ${esc(s.notes)}</small>` : ''}</div>`;

  // ── ☎️ 연락처 (내선번호 · 업체·기관)
  const vRow = x => `<div class="vd"><div class="grow"><b>${esc(x.n)}</b><small>${esc(x.c)}${x.memo ? ' · ' + esc(x.memo) : ''}</small></div><div class="tels">${x.p ? `<a class="tel" href="tel:${x.p.replace(/[^\d]/g, '')}">📞 ${esc(x.p)}</a>` : ''}${x.m ? `<a class="tel m" href="tel:${x.m.replace(/[^\d]/g, '')}">📱 ${esc(x.m)}</a>` : ''}</div></div>`;
  function contact(v) {
    let mode = store.get('cmode') || 'ext', q = '';
    v.innerHTML = `<h2 class="pt">☎️ 연락처</h2><div class="seg" id="cm"><button data-m="ext">내선번호</button><button data-m="vd">업체·기관</button></div>
      <input id="cq" type="search" placeholder="이름·부서·과목·업체 검색" autocomplete="off"><div id="cl"></div>
      <p class="faint small center">교무실 031-231-8330 · 행정실 031-231-8430 · 팩스 031-231-8418<br>내선번호를 누르면 031-231-8 + 내선으로 전화합니다.</p>`;
    const draw = () => {
      store.set('cmode', mode);
      $$('#cm button').forEach(b => b.classList.toggle('on', b.dataset.m === mode));
      const s = q.toLowerCase();
      if (mode === 'ext') {
        const list = D.contacts.filter(c => !s || [c.n, c.r, c.dept, c.sub, c.hr, c.ext].join(' ').toLowerCase().includes(s));
        // 로그인한 교직원에게는 휴대폰 번호(전화·문자)도 보인다
        $('#cl').innerHTML = `<div class="exts">${list.map(c => { const e = String(c.ext).split(/[^\d]/)[0]; return `<div class="ext-wrap"><a class="ext" ${e ? `href="tel:0312318${e.slice(0, 3)}"` : ''}><b>${esc(c.n)}</b><small>${esc(c.r)}${c.sub ? ' · ' + esc(c.sub) : ''}${c.hr ? ' · ' + esc(c.hr) + ' 담임' : ''}</small><span>${esc(c.ext || '-')}</span></a>${c.ph ? `<div class="ph"><a href="tel:${tel(c.ph)}">📱 ${esc(c.ph)}</a><a href="sms:${tel(c.ph)}">💬</a></div>` : ''}</div>`; }).join('')}</div>`;
      } else {
        const list = D.vendors.filter(x => !s || [x.n, x.c, x.items, x.memo, x.p, x.m].join(' ').toLowerCase().includes(s));
        const cats = [...new Set(list.map(x => x.c))];
        $('#cl').innerHTML = cats.map(c => `<h4>${esc(c)}</h4>${list.filter(x => x.c === c).map(vRow).join('')}`).join('') || '<p class="faint">없어요</p>';
      }
    };
    $('#cm').onclick = e => { const b = e.target.closest('[data-m]'); if (b) { mode = b.dataset.m; draw(); } };
    $('#cq').oninput = e => { q = e.target.value.trim(); draw(); };
    draw();
  }

  // ── 공통: 링크·내려받기
  function bindCommon(v) {
    v.onclick = async e => {
      const g = e.target.closest('[data-go]'); if (g) return go(g.dataset.go);
      const n = e.target.closest('[data-notice]'); if (n) return go('notice', n.dataset.notice);
      const dl = e.target.closest('[data-dl]'); if (dl) return download(dl.dataset.dl, dl);
      const my = e.target.closest('[data-myf]'); if (my) return download(my.dataset.myf, my, true);
    };
  }
  // 양식: 로그인했으면 교직원판(fs/), 아니면 공용판(f/) · 내 자료: 내 상자(u/○○/)를 내 열쇠로
  async function download(id, btn, mine) {
    const f = mine ? P?.files?.find(x => x.id === id) : D.forms.find(x => x.id === id); if (!f) return;
    const old = btn.innerHTML; btn.disabled = true;
    try {
      const url = mine ? `u/${UH}/${id}.bin` : P ? `fs/${id}.bin` : `f/${id}.bin`;
      const buf = await fetch(`${url}?v=${META.at}`).then(r => { if (!r.ok) throw new Error('파일이 없어요'); return r.arrayBuffer(); });
      const u = new Uint8Array(buf);
      const plain = mine ? await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, PKEY, u.slice(12)) : await decrypt(buf);
      const blob = new Blob([plain]);
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = f.name; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 4000);
    } catch (err) { alert('내려받지 못했어요: ' + err.message); }
    btn.disabled = false; btn.innerHTML = old;
  }
  // 아래에서 올라오는 창
  let sheetEl = null;
  function sheet(html, init, wide) {
    close();
    sheetEl = document.createElement('div'); sheetEl.className = 'sheet-back';
    sheetEl.innerHTML = `<div class="sheet ${wide ? 'wide' : ''}"><button class="ic x" title="닫기">✕</button>${html}</div>`;
    document.body.appendChild(sheetEl);
    sheetEl.onclick = e => { if (e.target === sheetEl || e.target.closest('.x')) close(); };
    init?.(sheetEl);
  }
  function close() { sheetEl?.remove(); sheetEl = null; }

  if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('sw.js').catch(() => {});
  boot();
})();
