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

  // Nav items
  var navItems;
  if (currentLang === 'en') {
    navItems = [
      { label: 'Home', href: 'index.html' },
      { label: 'Quick Start', href: 'quickstart.html' },
      { label: 'Guide', href: 'guide.html' },
      { label: 'GitHub', href: 'https://github.com/smallnest/goscapy', external: true }
    ];
  } else {
    navItems = [
      { label: '首页', href: 'index.html' },
      { label: '快速开始', href: 'quickstart.html' },
      { label: '完整指南', href: 'guide.html' },
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
    var target = currentLang === 'en' ? '../zh/index.html' : '../en/index.html';
    window.location.href = target;
  });
})();
