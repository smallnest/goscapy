/**
 * sidebar.js — Inline TOC generator with scroll spy
 * Scans page h2 headings and generates an inline TOC card
 * Looks for <div id="toc"></div>
 */
(function () {
  'use strict';

  var tocEl = document.getElementById('toc');
  if (!tocEl) return;

  var main = document.getElementById('mainContent');
  if (!main) main = document.body;

  var headings = main.querySelectorAll('h2');
  if (headings.length === 0) return;

  var currentLang = (document.documentElement.lang || 'en').startsWith('zh') ? 'zh' : 'en';
  var tocTitle = currentLang === 'zh' ? '目录' : 'On This Page';

  tocEl.className = 'toc';

  var html = '<h3>' + tocTitle + '</h3><ul>';
  var items = [];

  headings.forEach(function (h, i) {
    if (!h.id) {
      h.id = 'section-' + i;
    }
    html += '<li><a href="#' + h.id + '" data-section="' + h.id + '">' + h.textContent + '</a></li>';
    items.push({ el: h, id: h.id });
  });

  html += '</ul>';
  tocEl.innerHTML = html;

  // Scroll spy via IntersectionObserver
  var activeLink = null;
  var links = tocEl.querySelectorAll('a');

  if ('IntersectionObserver' in window) {
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          if (activeLink) activeLink.classList.remove('active');
          var link = tocEl.querySelector('a[data-section="' + entry.target.id + '"]');
          if (link) {
            link.classList.add('active');
            activeLink = link;
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
  }
})();
