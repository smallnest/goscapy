/**
 * nav.js — Simple header injection with brand + pulse dot + language switch
 * Injects a header into any page that includes <div id="navbar"></div>
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

  navbar.className = 'header';
  navbar.innerHTML =
    '<div class="header-row">' +
      '<div class="pulse-dot" id="pulseDot"></div>' +
      '<h1>' + title + '</h1>' +
      '<button class="lang-switch" id="langSwitch" title="Switch language">' +
        '\u{1F310} ' + altLabel +
      '</button>' +
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
