const root = document.documentElement;
const themeButton = document.querySelector('#themeButton');
const menuButton = document.querySelector('#menuButton');
const sidebar = document.querySelector('#sidebar');
const searchInput = document.querySelector('#searchInput');
const searchEmpty = document.querySelector('#searchEmpty');
const sections = [...document.querySelectorAll('.searchable')];
const navLinks = [...document.querySelectorAll('#navigation a')];

const savedTheme = localStorage.getItem('go-auth-docs-theme');
if (savedTheme) root.dataset.theme = savedTheme;

themeButton.addEventListener('click', () => {
  root.dataset.theme = root.dataset.theme === 'light' ? 'dark' : 'light';
  localStorage.setItem('go-auth-docs-theme', root.dataset.theme);
});

menuButton.addEventListener('click', () => {
  const open = sidebar.classList.toggle('open');
  menuButton.setAttribute('aria-expanded', String(open));
});

navLinks.forEach(link => link.addEventListener('click', () => sidebar.classList.remove('open')));

document.addEventListener('keydown', event => {
  if (event.key === '/' && document.activeElement !== searchInput) {
    event.preventDefault();
    searchInput.focus();
  }
  if (event.key === 'Escape') {
    searchInput.value = '';
    searchInput.dispatchEvent(new Event('input'));
    searchInput.blur();
    sidebar.classList.remove('open');
  }
});

searchInput.addEventListener('input', () => {
  const query = searchInput.value.trim().toLowerCase();
  let visible = 0;
  sections.forEach(section => {
    const match = !query || `${section.dataset.title} ${section.textContent}`.toLowerCase().includes(query);
    section.classList.toggle('search-hidden', !match);
    if (match) visible += 1;
  });
  searchEmpty.hidden = visible > 0;
});

document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', async () => {
    await navigator.clipboard.writeText(button.dataset.copy);
    const previous = button.textContent;
    button.textContent = 'Copied';
    setTimeout(() => { button.textContent = previous; }, 1300);
  });
});

const observer = new IntersectionObserver(entries => {
  const current = entries.filter(entry => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
  if (!current) return;
  navLinks.forEach(link => link.classList.toggle('active', link.getAttribute('href') === `#${current.target.id}`));
}, { rootMargin: '-20% 0px -65%', threshold: [0, .25, .75] });

sections.forEach(section => observer.observe(section));
