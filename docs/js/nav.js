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

  // Nav items — dropdown items use { label, dropdown: [...] }
  var navItems;
  if (currentLang === 'en') {
    navItems = [
      { label: 'Home', href: prefix + 'index.html' },
      { label: 'Quick Start', href: prefix + 'quickstart.html' },
      { label: 'Guide', href: prefix + 'guide.html' },
      { label: 'Examples', dropdown: [
        { label: 'Basic', href: prefix + 'examples/basic.html' },
        { label: 'Send / Recv', href: prefix + 'examples/send-recv.html' },
        { label: 'Sniffing', href: prefix + 'examples/sniff.html' },
        { label: 'Tunnel', href: prefix + 'examples/tunnel.html' },
        { label: 'DNS / DHCP', href: prefix + 'examples/app.html' },
        { label: 'IPv6 / ICMPv6', href: prefix + 'examples/ipv6.html' },
      ]},
      { label: 'GitHub', href: 'https://github.com/smallnest/goscapy', external: true }
    ];
  } else {
    navItems = [
      { label: '首页', href: prefix + 'index.html' },
      { label: '快速开始', href: prefix + 'quickstart.html' },
      { label: '完整指南', href: prefix + 'guide.html' },
      { label: '示例', dropdown: [
        { label: '基础组包', href: prefix + 'examples/basic.html' },
        { label: '发送/接收', href: prefix + 'examples/send-recv.html' },
        { label: '嗅探', href: prefix + 'examples/sniff.html' },
        { label: '隧道封装', href: prefix + 'examples/tunnel.html' },
        { label: 'DNS / DHCP', href: prefix + 'examples/app.html' },
        { label: 'IPv6 / ICMPv6', href: prefix + 'examples/ipv6.html' },
      ]},
      { label: 'GitHub', href: 'https://github.com/smallnest/goscapy', external: true }
    ];
  }

  // Current page filename for active highlighting
  var currentPage = path.split('/').pop() || 'index.html';

  var navLinksHTML = navItems.map(function (item) {
    if (item.dropdown) {
      var menuItems = item.dropdown.map(function (child) {
        var active = currentPage && child.href.indexOf(currentPage) !== -1 ? ' active' : '';
        return '<a href="' + child.href + '"' + active + '>' + child.label + '</a>';
      }).join('');
      return '<div class="nav-dropdown">' +
        '<button class="nav-dropdown-trigger">' + item.label + '</button>' +
        '<div class="nav-dropdown-menu">' + menuItems + '</div>' +
      '</div>';
    }
    var target = item.external ? ' target="_blank" rel="noopener"' : '';
    return '<a href="' + item.href + '"' + target + '>' + item.label + '</a>';
  }).join('');

  navbar.className = 'header';
  navbar.innerHTML =
    '<div class="header-row">' +
      '<div class="header-left">' +
        '<div class="pulse-dot" id="pulseDot" style="background: none; border-radius: 0; width: auto; height: auto; font-size: 1.5rem; animation: none; display: flex; align-items: center; justify-content: center; user-select: none;">🦎</div>' +
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
    var pageName = path.split('/').pop() || 'index.html';
    var currentExamples = /\/(en|zh)\/examples\//.test(path) ? 'examples/' : '';
    var up = inSubdir ? '../../' : '../';
    var target = up + altLang + '/' + currentExamples + pageName;
    window.location.href = target;
  });
})();
