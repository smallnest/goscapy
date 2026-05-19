/**
 * animations.js — Intersection Observer scroll-triggered animations
 * Adds 'is-visible' class when elements enter the viewport
 *
 * Supports: anim-fade-in, anim-slide-in-left, anim-slide-in-right,
 *           anim-flip-in, anim-scale-in
 * Plus stagger-N delay classes
 */
(function () {
  'use strict';

  var ANIM_CLASSES = [
    'anim-fade-in',
    'anim-slide-in-left',
    'anim-slide-in-right',
    'anim-flip-in',
    'anim-scale-in'
  ];

  function initAnimations() {
    var elements = [];
    ANIM_CLASSES.forEach(function (cls) {
      var els = document.querySelectorAll('.' + cls);
      els.forEach(function (el) { elements.push(el); });
    });

    if (elements.length === 0) return;

    if (!('IntersectionObserver' in window)) {
      // Fallback: just make everything visible
      elements.forEach(function (el) { el.classList.add('is-visible'); });
      return;
    }

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      });
    }, {
      rootMargin: '0px 0px -60px 0px',
      threshold: 0.1
    });

    elements.forEach(function (el) {
      observer.observe(el);
    });
  }

  // Table row staggered animation
  function initTableAnimations() {
    var tables = document.querySelectorAll('.table-anim tbody tr');
    if (tables.length === 0) return;

    if (!('IntersectionObserver' in window)) {
      tables.forEach(function (tr) { tr.classList.add('is-visible'); });
      return;
    }

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      });
    }, {
      rootMargin: '0px 0px -40px 0px',
      threshold: 0.1
    });

    tables.forEach(function (tr, i) {
      tr.style.opacity = '0';
      tr.style.transform = 'translateY(10px)';
      tr.style.transition = 'opacity .4s ease ' + (i * 0.06) + 's, transform .4s ease ' + (i * 0.06) + 's';
      observer.observe(tr);
    });

    // Add is-visible styles
    var style = document.createElement('style');
    style.textContent = '.table-anim tbody tr.is-visible { opacity: 1 !important; transform: translateY(0) !important; }';
    document.head.appendChild(style);
  }

  // Admonition slide-in
  function initAdmonitionAnimations() {
    var admonitions = document.querySelectorAll('.admonition.anim-fade-in');
    if (admonitions.length === 0) return;

    if (!('IntersectionObserver' in window)) {
      admonitions.forEach(function (el) { el.classList.add('is-visible'); });
      return;
    }

    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      });
    }, {
      rootMargin: '0px 0px -40px 0px',
      threshold: 0.2
    });

    admonitions.forEach(function (el) { observer.observe(el); });
  }

  // Copy code button
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

  // Init on DOMContentLoaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      initAnimations();
      initTableAnimations();
      initAdmonitionAnimations();
      initCodeCopy();
    });
  } else {
    initAnimations();
    initTableAnimations();
    initAdmonitionAnimations();
    initCodeCopy();
  }
})();
