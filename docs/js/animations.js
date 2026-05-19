/**
 * animations.js — Anime.js powered scroll animations + hover effects
 * Loads anime.js from CDN and sets up IntersectionObserver for reveal animations
 */
(function () {
  'use strict';

  // Load anime.js from CDN
  var script = document.createElement('script');
  script.src = 'https://cdn.jsdelivr.net/npm/animejs@3.2.2/lib/anime.min.js';
  script.onload = init;
  document.head.appendChild(script);

  function init() {
    pageLoadAnimations();
    scrollObserver();
    hoverEffects();
    initCodeCopy();
  }

  // ---------- Page Load Animations ----------
  function pageLoadAnimations() {
    // Header fade in
    var header = document.querySelector('.header');
    if (header) {
      anime({
        targets: header,
        opacity: [0, 1],
        translateY: [-20, 0],
        duration: 800,
        easing: 'easeOutCubic'
      });
    }

    // Pulse dot elastic scale
    var pulseDot = document.querySelector('.pulse-dot');
    if (pulseDot) {
      anime({
        targets: pulseDot,
        scale: [0, 1],
        duration: 800,
        easing: 'easeOutElastic(1, .6)',
        delay: 300
      });
    }

    // Title slide from left
    var h1 = document.querySelector('.header h1');
    if (h1) {
      anime({
        targets: h1,
        opacity: [0, 1],
        translateX: [-30, 0],
        duration: 700,
        easing: 'easeOutCubic',
        delay: 200
      });
    }

    // Subtitle stagger
    var subtitles = document.querySelectorAll('.subtitle');
    if (subtitles.length) {
      anime({
        targets: subtitles,
        opacity: [0, 1],
        translateY: [10, 0],
        duration: 600,
        delay: anime.stagger(100, { start: 400 }),
        easing: 'easeOutCubic'
      });
    }

    // TOC slide in
    var toc = document.querySelector('.toc');
    if (toc) {
      anime({
        targets: toc,
        opacity: [0, 1],
        translateX: [-20, 0],
        duration: 700,
        easing: 'easeOutCubic',
        delay: 600
      });
    }
  }

  // ---------- Scroll Observer ----------
  function scrollObserver() {
    if (!('IntersectionObserver' in window)) return;

    // Sections fade up
    observe('.section', function (el) {
      anime({
        targets: el,
        opacity: [0, 1],
        translateY: [30, 0],
        duration: 700,
        easing: 'easeOutCubic'
      });
    });

    // Cards flip in with stagger
    var cardContainers = document.querySelectorAll('.cards');
    cardContainers.forEach(function (container) {
      observeDirect(container, function () {
        var cards = container.querySelectorAll('.card');
        anime({
          targets: cards,
          opacity: [0, 1],
          rotateY: [15, 0],
          translateX: [30, 0],
          duration: 600,
          delay: anime.stagger(80),
          easing: 'easeOutCubic'
        });
      });
    });

    // Tables row-by-row
    document.querySelectorAll('table').forEach(function (table) {
      var rows = table.querySelectorAll('tbody tr');
      if (rows.length === 0) return;
      rows.forEach(function (row) {
        row.style.opacity = '0';
        row.style.transform = 'translateY(10px)';
      });
      observe(table, function () {
        anime({
          targets: rows,
          opacity: [0, 1],
          translateY: [10, 0],
          duration: 400,
          delay: anime.stagger(60),
          easing: 'easeOutCubic'
        });
      });
    });

    // Code blocks slide from left
    observe('.code-block', function (el) {
      anime({
        targets: el,
        opacity: [0, 1],
        translateX: [-20, 0],
        duration: 600,
        easing: 'easeOutCubic'
      });
    });

    // Notes/tips slide from left with border growing
    observe('.note, .tip', function (el) {
      anime({
        targets: el,
        opacity: [0, 1],
        translateX: [-15, 0],
        duration: 600,
        easing: 'easeOutCubic'
      });
    });

    // Section dots elastic scale
    observe('.section-dot', function (el) {
      anime({
        targets: el,
        scale: [0, 1],
        duration: 600,
        easing: 'easeOutElastic(1, .6)'
      });
    });

    // Diagram boxes scale in
    observe('.diagram-box', function (el) {
      anime({
        targets: el,
        opacity: [0, 1],
        scale: [0.95, 1],
        duration: 600,
        easing: 'easeOutCubic'
      });
    });

    // Flow steps
    var flowArrows = document.querySelectorAll('.flow-arrow');
    flowArrows.forEach(function (flow) {
      observeDirect(flow, function () {
        anime({
          targets: flow.querySelectorAll('.flow-step'),
          opacity: [0, 1],
          scale: [0.8, 1],
          duration: 500,
          delay: anime.stagger(100),
          easing: 'easeOutBack'
        });
      });
    });
  }

  function observe(selector, callback) {
    var els = document.querySelectorAll(selector);
    if (els.length === 0) return;
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          callback(entry.target);
          observer.unobserve(entry.target);
        }
      });
    }, { rootMargin: '0px 0px -60px 0px', threshold: 0.1 });
    els.forEach(function (el) {
      el.style.opacity = '0';
      observer.observe(el);
    });
  }

  function observeDirect(el, callback) {
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          callback();
          observer.unobserve(entry.target);
        }
      });
    }, { rootMargin: '0px 0px -60px 0px', threshold: 0.1 });
    el.style.opacity = '0';
    observer.observe(el);
  }

  // ---------- Hover Effects ----------
  function hoverEffects() {
    // Card hover — scale + shadow (CSS handles this, but add anime.js flair)
    document.querySelectorAll('.card').forEach(function (card) {
      card.addEventListener('mouseenter', function () {
        anime({
          targets: card,
          scale: 1.03,
          duration: 300,
          easing: 'easeOutCubic'
        });
      });
      card.addEventListener('mouseleave', function () {
        anime({
          targets: card,
          scale: 1,
          duration: 300,
          easing: 'easeOutCubic'
        });
      });
    });

    // Inline code pop
    document.querySelectorAll('.inline-code, p > code, li > code').forEach(function (code) {
      code.addEventListener('mouseenter', function () {
        anime({
          targets: code,
          scale: 1.08,
          duration: 200,
          easing: 'easeOutCubic'
        });
      });
      code.addEventListener('mouseleave', function () {
        anime({
          targets: code,
          scale: 1,
          duration: 200,
          easing: 'easeOutCubic'
        });
      });
    });
  }

  // ---------- Code Copy ----------
  function initCodeCopy() {
    document.addEventListener('click', function (e) {
      if (e.target.classList.contains('code-copy')) {
        var codeBlock = e.target.closest('.code-block');
        if (!codeBlock) return;
        var pre = codeBlock.querySelector('pre');
        if (!pre) return;
        var text = pre.textContent;
        navigator.clipboard.writeText(text).then(function () {
          e.target.textContent = '✓ Copied';
          setTimeout(function () {
            e.target.textContent = 'Copy';
          }, 2000);
        });
      }
    });
  }
})();
