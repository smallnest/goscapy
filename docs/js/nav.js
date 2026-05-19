/**
 * nav.js — Header with brand + page nav links + language switch
 * Injects into any page that includes <div id="navbar"></div>
 */
(function () {
  'use strict';

  var currentLang = (document.documentElement.lang || 'en').startsWith('zh') ? 'zh' : 'en';
  var altLang = currentLang === 'en' ? 'zh' : 'en';
  var altLabel = currentLang === 'en' ? '中文' : 'English';

  var navbar = document.getElementById('navbar');
  if (!navbar) return;

  var title = 'goscapy';
  var subtitle = currentLang === 'en'
    ? 'Go Network Packet Crafting Library'
    : 'Go 网络数据包构建库';

  // Detect if we're in a subdirectory (e.g. en/examples/)
  var path = window.location.pathname;
  var inSubdir = /\/(en|zh)\/examples\//.test(path);
  var prefix = inSubdir ? '../' : '';

  // Nav items
  var navItems;
  if (currentLang === 'en') {
    navItems = [
      { label: 'Home', href: prefix + 'index.html' },
      { label: 'Quick Start', href: prefix + 'quickstart.html' },
      { label: 'Guide', href: prefix + 'guide.html' },
      { label: 'Examples', href: prefix + 'examples/basic.html' },
      { label: 'GitHub', href: 'https://github.com/smallnest/goscapy', external: true }
    ];
  } else {
    navItems = [
      { label: '首页', href: prefix + 'index.html' },
      { label: '快速开始', href: prefix + 'quickstart.html' },
      { label: '完整指南', href: prefix + 'guide.html' },
      { label: '示例', href: prefix + 'examples/basic.html' },
      { label: 'GitHub', href: 'https://github.com/smallnest/goscapy', external: true }
    ];
  }

  var navLinksHTML = navItems.map(function (item) {
    var target = item.external ? ' target="_blank" rel="noopener"' : '';
    return '<a href="' + item.href + '"' + target + '>' + item.label + '</a>';
  }).join('');

  navbar.className = 'header';
  navbar.innerHTML =
    '<div class="header-row">' +
      '<div class="header-left">' +
        '<div class="pulse-dot" id="pulseDot"></div>' +
        '<h1>' + title + '</h1>' +
      '</div>' +
      '<nav class="header-nav">' +
        navLinksHTML +
        '<button class="lang-switch" id="langSwitch" title="Switch language">' +
          '\u{1F310} ' + altLabel +
        '</button>' +
      '</nav>' +
    '</div>' +
    '<p class="subtitle">' + subtitle + '</p>' +
    '<p class="subtitle" style="margin-top:0.25rem;">' +
      '<a href="https://github.com/smallnest/goscapy" style="color:#D97757;text-decoration:none;">github.com/smallnest/goscapy</a>' +
    '</p>';

  // Language switch
  document.getElementById('langSwitch').addEventListener('click', function () {
    // Determine current page name
    var pageName = path.split('/').pop() || 'index.html';
    // If we're in examples subdir, keep the same sub-path
    var currentExamples = /\/(en|zh)\/examples\//.test(path) ? 'examples/' : '';
    var up = inSubdir ? '../../' : '../';
    var target = up + altLang + '/' + currentExamples + pageName;
    window.location.href = target;
  });
})();
