/**
 * nav.js — Fixed top navigation bar + language switch
 * Injects a navbar into any page that includes <div id="navbar"></div>
 */
(function () {
  'use strict';

  const currentLang = (document.documentElement.lang || 'en').startsWith('zh') ? 'zh' : 'en';
  const altLang = currentLang === 'en' ? 'zh' : 'en';
  const altLabel = currentLang === 'en' ? '中文' : 'English';

  const navItems = currentLang === 'en'
    ? [
        { label: 'Home', href: 'index.html' },
        { label: 'Docs', href: '#' },
        { label: 'GitHub', href: 'https://github.com/smallnest/goscapy', external: true },
      ]
    : [
        { label: '首页', href: 'index.html' },
        { label: '文档', href: '#' },
        { label: 'GitHub', href: 'https://github.com/smallnest/goscapy', external: true },
      ];

  const navbar = document.getElementById('navbar');
  if (!navbar) return;

  const linksHTML = navItems.map(item => {
    const target = item.external ? ' target="_blank" rel="noopener"' : '';
    return `<a href="${item.href}"${target}>${item.label}</a>`;
  }).join('');

  navbar.classList.add('navbar');
  navbar.innerHTML = `
    <a class="navbar-brand" href="index.html">
      <span class="brand-icon">G</span>
      <span>goscapy</span>
    </a>
    <nav class="navbar-links" id="navLinks">
      ${linksHTML}
      <button class="lang-switch" id="langSwitch" title="Switch language">
        🌐 ${altLabel}
      </button>
    </nav>
    <button class="hamburger" id="hamburger" aria-label="Menu">
      <span></span><span></span><span></span>
    </button>
  `;

  // Language switch
  document.getElementById('langSwitch').addEventListener('click', function () {
    const target = currentLang === 'en' ? '../zh/index.html' : '../en/index.html';
    window.location.href = target;
  });

  // Mobile hamburger
  const hamburger = document.getElementById('hamburger');
  const navLinks = document.getElementById('navLinks');
  hamburger.addEventListener('click', function () {
    navLinks.classList.toggle('open');
  });

  // Scroll effect
  window.addEventListener('scroll', function () {
    if (window.scrollY > 50) {
      navbar.classList.add('scrolled');
    } else {
      navbar.classList.remove('scrolled');
    }
  });
})();
