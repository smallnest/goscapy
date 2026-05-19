/**
 * sidebar.js — Auto-generate sidebar from h2/h3 headings + scroll spy
 * Looks for <div id="sidebar"></div> and <main id="mainContent">
 */
(function () {
  'use strict';

  const sidebar = document.getElementById('sidebar');
  const main = document.getElementById('mainContent');
  if (!sidebar || !main) return;

  sidebar.classList.add('sidebar');

  // Collect headings
  const headings = main.querySelectorAll('h2, h3');
  if (headings.length === 0) return;

  const title = document.createElement('div');
  title.className = 'sidebar-title';
  title.textContent = document.documentElement.lang === 'zh' ? '目录' : 'On This Page';
  sidebar.appendChild(title);

  const nav = document.createElement('ul');
  nav.className = 'sidebar-nav';

  const items = [];
  headings.forEach(function (h, i) {
    // Ensure id
    if (!h.id) {
      h.id = 'section-' + i;
    }
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = '#' + h.id;
    a.textContent = h.textContent;
    if (h.tagName === 'H3') {
      a.classList.add('indent-3');
    }
    li.appendChild(a);
    nav.appendChild(li);
    items.push({ el: h, link: a });
  });

  sidebar.appendChild(nav);

  // Scroll spy via IntersectionObserver
  var activeLink = null;
  var observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        if (activeLink) activeLink.classList.remove('active');
        var found = items.find(function (it) { return it.el === entry.target; });
        if (found) {
          found.link.classList.add('active');
          activeLink = found.link;
        }
      }
    });
  }, {
    rootMargin: '-80px 0px -60% 0px',
    threshold: 0
  });

  items.forEach(function (it) {
    observer.observe(it.el);
  });

  // Mobile sidebar toggle
  var hamburger = document.getElementById('hamburger');
  if (hamburger) {
    hamburger.addEventListener('click', function () {
      sidebar.classList.toggle('open');
    });
  }
})();
