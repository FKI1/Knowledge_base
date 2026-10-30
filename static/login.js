const $ = (id) => document.getElementById(id);
const stage = $('stage'), pull = $('pull'), line = $('line'), hintText = $('hintText'),
      card = $('card'), statusEl = $('status'), titleEl = $('title'), subEl = $('sub'),
      COARSE = matchMedia('(pointer: coarse)').matches;

/* ---------- Лампа ---------- */
const LEN = 90, MAX = 110, THRESHOLD = 45;   // длина шнурка, предел вытяжки, порог срабатывания (px)
let startY = 0, extra = 0, moved = false, dragging = false, focusTimer;

const setLen = (px) => line.style.setProperty('--len', (LEN + px) + 'px');
function focusFirst() {
  if (COARSE) return;                         // на телефоне не вызываем клавиатуру сами
  const el = card.querySelector('form:not([hidden]) input');
  if (el) el.focus({preventScroll: true});
}
function setOn(on) {
  stage.classList.toggle('on', on);
  pull.setAttribute('aria-pressed', on);
  pull.setAttribute('aria-label', on ? 'Потянуть за шнурок, чтобы выключить лампу' : 'Потянуть за шнурок, чтобы включить лампу');
  hintText.textContent = on ? 'Потяните ещё раз, чтобы выключить свет' : 'Потяните за шнурок, чтобы увидеть больше';
  card.toggleAttribute('inert', !on);         // лампа выключена = форма недоступна
  clearTimeout(focusTimer);
  if (on) focusTimer = setTimeout(() => stage.classList.contains('on') && focusFirst(), 700);
}
const toggle = () => setOn(!stage.classList.contains('on'));

function tap() {                               // короткий клик/клавиатура: шнурок дёргается сам
  pull.classList.add('snap');
  setLen(55);
  toggle();
  setTimeout(() => { pull.classList.remove('snap'); setLen(0); }, 140);
}
pull.addEventListener('pointerdown', (e) => {
  if (e.button !== 0) return;
  e.preventDefault();
  dragging = true; moved = false; extra = 0; startY = e.clientY;
  pull.setPointerCapture(e.pointerId);
  pull.classList.add('drag');
});
pull.addEventListener('pointermove', (e) => {
  if (!dragging) return;
  const dy = e.clientY - startY;
  if (Math.abs(dy) > 4) moved = true;
  extra = Math.min(MAX, dy <= 0 ? 0 : dy <= 60 ? dy : 60 + (dy - 60) * 0.3);  // дальше 60px тянется «упруго»
  setLen(extra);
});
function release(e, cancelled) {
  if (!dragging) return;
  dragging = false;
  pull.classList.remove('drag');
  if (pull.hasPointerCapture(e.pointerId)) pull.releasePointerCapture(e.pointerId);
  if (!cancelled && !moved) { tap(); return; }
  if (!cancelled && extra >= THRESHOLD) toggle();
  setLen(0);
  extra = 0;
}
pull.addEventListener('pointerup', (e) => release(e, false));
pull.addEventListener('pointercancel', (e) => release(e, true));
pull.addEventListener('click', (e) => e.preventDefault());
const isActivate = (e) => e.key === 'Enter' || e.key === ' ' || e.code === 'Space';
pull.addEventListener('keydown', (e) => { if (!isActivate(e)) return; e.preventDefault(); if (!e.repeat) tap(); });
pull.addEventListener('keyup', (e) => { if (isActivate(e)) e.preventDefault(); });
document.addEventListener('keydown', (e) => {   // Enter/Space, когда фокус нигде
  if (!isActivate(e) || e.repeat || e.target !== document.body) return;
  e.preventDefault(); tap();
});

/* ---------- Показ пароля ---------- */
function resetEye(btn) {
  const input = $(btn.dataset.for);
  input.type = 'password'; input.value = '';
  btn.setAttribute('aria-pressed', 'false'); btn.setAttribute('aria-label', 'Показать пароль'); btn.title = 'Показать пароль';
}
card.querySelectorAll('.eye').forEach((btn) => {
  const input = $(btn.dataset.for);
  btn.addEventListener('mousedown', (e) => e.preventDefault());   // фокус остаётся в поле
  btn.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    const t = show ? 'Скрыть пароль' : 'Показать пароль';
    btn.setAttribute('aria-pressed', show); btn.setAttribute('aria-label', t); btn.title = t;
  });
});

/* ---------- Экраны: вход / регистрация / восстановление / новый пароль ---------- */
const VIEWS = {
  login:    {form: 'form',       title: 'Добро пожаловать!', sub: 'Войдите в аккаунт, чтобы получить доступ к материалам.'},
  register: {form: 'formReg',    title: 'Создание аккаунта', sub: 'Укажите email и придумайте пароль. Мы отправим письмо, чтобы подтвердить адрес.'},
  forgot:   {form: 'formForgot', title: 'Забыли пароль?',    sub: 'Укажите email — мы отправим ссылку для создания нового пароля.'},
  reset:    {form: 'formReset',  title: 'Новый пароль',      sub: 'Придумайте новый пароль для входа в аккаунт.'}
};
let resetToken = '';
function setStatus(msg, bad) { statusEl.textContent = msg || ''; statusEl.classList.toggle('bad', !!bad); }
function showView(name, msg, bad) {
  for (const k in VIEWS) $(VIEWS[k].form).hidden = k !== name;
  titleEl.textContent = VIEWS[name].title; subEl.textContent = VIEWS[name].sub;
  card.querySelectorAll('.err, .field-err').forEach((el) => { el.textContent = ''; });
  card.querySelectorAll('input').forEach((i) => i.setAttribute('aria-invalid', 'false'));
  card.querySelectorAll('.eye').forEach(resetEye);
  $('note').hidden = name === 'register';      // на регистрации блок «Нет доступа…» не нужен
  setStatus(msg, bad);
  if (stage.classList.contains('on')) focusFirst();
}
function go(name, msg, bad) { history.replaceState(null, '', '#' + name); showView(name, msg, bad); }
function route() {
  let h = location.hash.slice(1), msg = '', bad = false, wake = false;
  if (h.startsWith('reset=')) {                // токен из письма: берём и убираем из адресной строки
    resetToken = h.slice(6); h = 'reset'; wake = true; history.replaceState(null, '', '#reset');
  } else if (h === 'verified') {
    h = 'login'; msg = 'Email подтверждён. Теперь можно войти.'; wake = true; history.replaceState(null, '', '#login');
  } else if (h === 'badlink') {
    h = 'login'; msg = 'Ссылка недействительна или устарела.'; bad = true; wake = true; history.replaceState(null, '', '#login');
  }
  if (h === 'reset' && !resetToken) { h = 'forgot'; msg = 'Ссылка для сброса недействительна. Запросите новую.'; bad = true; }
  if (!VIEWS[h]) h = 'login';
  if (wake) setOn(true);                       // пришли по ссылке из письма: сразу включаем свет
  showView(h, msg, bad);
}

/* ---------- Формы ---------- */
const setErr = (input, msg) => {
  $(input.id + '-err').textContent = msg || '';
  input.setAttribute('aria-invalid', msg ? 'true' : 'false');
};
const checkEmail = (i) => { const v = i.value.trim(); if (!v) setErr(i, 'Введите email'); else if (!i.checkValidity()) setErr(i, 'Проверьте формат email'); };
const checkNewPw = (i) => { if (i.value.length < 10) setErr(i, 'Минимум 10 символов'); };

async function post(url, data) {
  const r = await fetch(url, {method: 'POST', credentials: 'same-origin',
    headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)});
  let d = {}; try { d = await r.json(); } catch { /* пустой ответ */ }
  return {r, d};
}
function commonErr(r, d) {
  if (r.status === 429) return 'Слишком много попыток. Попробуйте позже.';
  if (r.status === 403) {
    if (d.detail === 'email_not_verified') return 'Сначала подтвердите email: проверьте почту.';
    if (d.detail === 'Registration closed') return 'Регистрация закрыта. Обратитесь в поддержку.';
    return 'Запрос отклонён. Обновите страницу и повторите.';
  }
  if (r.status >= 500) return 'Сервис временно недоступен. Попробуйте позже.';
  return 'Не удалось выполнить запрос. Попробуйте ещё раз.';
}
function wire(form, check, send) {
  const btn = form.querySelector('.go'), label = btn.textContent, err = form.querySelector('.err');
  let busy = false;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (busy) return;                          // защита от двойной отправки
    err.textContent = ''; setStatus('');
    form.querySelectorAll('input').forEach((i) => setErr(i));
    check();
    const bad = form.querySelector('[aria-invalid="true"]');
    if (bad) { bad.focus(); return; }
    busy = true; btn.disabled = true; btn.textContent = 'Подождите…'; form.setAttribute('aria-busy', 'true');
    let keep = false;
    try { keep = await send(err); } catch { err.textContent = 'Нет связи с сервером.'; }
    finally { busy = false; if (!keep) { btn.disabled = false; btn.textContent = label; form.removeAttribute('aria-busy'); } }
  });
}

const em = $('email'), pw = $('password');
wire($('form'), () => { checkEmail(em); if (!pw.value) setErr(pw, 'Введите пароль'); }, async (err) => {
  const {r, d} = await post('/api/login', {email: em.value.trim(), password: pw.value});
  if (r.ok) { $('form').querySelector('.go').textContent = 'Готово'; location.replace('/'); return true; }
  if (r.status === 401) {
    err.textContent = 'Неверный email или пароль.';
    em.setAttribute('aria-invalid', 'true'); pw.setAttribute('aria-invalid', 'true');
    pw.value = ''; pw.focus();
  } else if (r.status === 422) setErr(em, 'Проверьте формат email');
  else err.textContent = commonErr(r, d);
  return false;
});

const rNick = $('reg-nick'), rEm = $('reg-email'), rPw = $('reg-password'), rPw2 = $('reg-password2');
const NICK_RE = /^[\p{L}\p{N}_.-]{3,24}$/u;
wire($('formReg'), () => {
  if (!rNick.value.trim()) setErr(rNick, 'Придумайте никнейм');
  else if (!NICK_RE.test(rNick.value.trim())) setErr(rNick, '3–24 символа: буквы, цифры, точка, _ и -');
  checkEmail(rEm); checkNewPw(rPw);
  if (!rPw2.value) setErr(rPw2, 'Повторите пароль');
  else if (rPw2.value !== rPw.value) setErr(rPw2, 'Пароли не совпадают');
}, async (err) => {
  const {r, d} = await post('/api/register', {nickname: rNick.value.trim(), email: rEm.value.trim(), password: rPw.value});
  if (r.ok) { go('login', 'Проверьте почту: мы отправили письмо со ссылкой для подтверждения адреса.'); return false; }
  if (r.status === 409) { setErr(rNick, 'Этот никнейм уже занят'); rNick.focus(); }
  else err.textContent = r.status === 422 ? 'Проверьте никнейм, email и пароль (минимум 10 символов).' : commonErr(r, d);
  return false;
});

const fEm = $('fg-email');
wire($('formForgot'), () => checkEmail(fEm), async (err) => {
  const {r, d} = await post('/api/forgot', {email: fEm.value.trim()});
  if (r.ok) { go('login', 'Если такой аккаунт есть, мы отправили ссылку для сброса пароля. Проверьте почту.'); return false; }
  if (r.status === 422) setErr(fEm, 'Проверьте формат email'); else err.textContent = commonErr(r, d);
  return false;
});

const sPw = $('rs-password');
wire($('formReset'), () => checkNewPw(sPw), async (err) => {
  const {r, d} = await post('/api/reset', {token: resetToken, password: sPw.value});
  if (r.ok) { resetToken = ''; go('login', 'Пароль изменён. Теперь войдите с новым паролем.'); return false; }
  if (r.status === 400) { resetToken = ''; go('forgot', 'Ссылка недействительна или устарела. Запросите новую.', true); return false; }
  err.textContent = r.status === 422 ? 'Пароль должен быть не короче 10 символов.' : commonErr(r, d);
  return false;
});

setOn(false);
route();
addEventListener('hashchange', route);