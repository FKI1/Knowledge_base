// Страница после входа. Узнаём, кто вошёл; если сессии нет — отправляем на вход.
fetch('/api/me', {credentials: 'same-origin'}).then(async r => {
  if (!r.ok) return location.replace('/login');
  document.getElementById('hi').textContent = 'Вы вошли как ' + (await r.json()).email;
});
// Кнопка «Выйти»: закрываем сессию на сервере и возвращаемся на страницу входа.
document.getElementById('out').addEventListener('click', async () => {
  await fetch('/api/logout', {method: 'POST', credentials: 'same-origin'});
  location.replace('/login');
});
