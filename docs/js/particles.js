/**
 * particles.js — Canvas particle background animation
 * Renders ~60 colorful particles with connecting lines on hero canvas
 */
(function () {
  'use strict';

  var canvas = document.getElementById('particleCanvas');
  if (!canvas) return;

  var ctx = canvas.getContext('2d');
  var particles = [];
  var animId;
  var PARTICLE_COUNT = 60;
  var CONNECTION_DIST = 140;

  function resize() {
    var parent = canvas.parentElement;
    canvas.width = parent.offsetWidth;
    canvas.height = parent.offsetHeight;
  }

  function createParticle() {
    var colors = [
      'rgba(0, 173, 216, ',   // primary
      'rgba(0, 230, 118, ',    // accent
      'rgba(88, 166, 255, ',   // link blue
      'rgba(210, 168, 255, ',  // purple
      'rgba(255, 167, 38, '    // orange
    ];
    var colorBase = colors[Math.floor(Math.random() * colors.length)];
    return {
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.6,
      vy: (Math.random() - 0.5) * 0.6,
      radius: Math.random() * 2 + 1,
      colorBase: colorBase,
      alpha: Math.random() * 0.5 + 0.3
    };
  }

  function init() {
    resize();
    particles = [];
    for (var i = 0; i < PARTICLE_COUNT; i++) {
      particles.push(createParticle());
    }
  }

  function drawParticle(p) {
    ctx.beginPath();
    ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
    ctx.fillStyle = p.colorBase + p.alpha + ')';
    ctx.fill();
  }

  function drawConnections() {
    for (var i = 0; i < particles.length; i++) {
      for (var j = i + 1; j < particles.length; j++) {
        var dx = particles[i].x - particles[j].x;
        var dy = particles[i].y - particles[j].y;
        var dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < CONNECTION_DIST) {
          var alpha = (1 - dist / CONNECTION_DIST) * 0.15;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = 'rgba(0, 173, 216, ' + alpha + ')';
          ctx.lineWidth = 0.5;
          ctx.stroke();
        }
      }
    }
  }

  function update() {
    for (var i = 0; i < particles.length; i++) {
      var p = particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.vy *= -1;
    }
  }

  function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    update();
    drawConnections();
    for (var i = 0; i < particles.length; i++) {
      drawParticle(particles[i]);
    }
    animId = requestAnimationFrame(animate);
  }

  window.addEventListener('resize', function () {
    resize();
  });

  // Pause when not visible
  var heroEl = canvas.closest('.hero');
  if (heroEl && 'IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      if (entries[0].isIntersecting) {
        if (!animId) animate();
      } else {
        cancelAnimationFrame(animId);
        animId = null;
      }
    });
    io.observe(heroEl);
  }

  init();
  animate();
})();
