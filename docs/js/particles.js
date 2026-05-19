/**
 * particles.js — Canvas particle background with warm palette colors
 * Renders ~60 particles with connecting lines on fixed background canvas
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

  var COLORS = [
    'rgba(217, 119, 87, ',   // Terracotta
    'rgba(91, 138, 114, ',   // Sage
    'rgba(139, 111, 138, ',  // Plum
    'rgba(74, 111, 165, ',   // Blue
    'rgba(201, 100, 100, ',  // Rose
    'rgba(45, 156, 219, ',   // Teal
    'rgba(124, 92, 191, '    // Violet
  ];

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  function createParticle() {
    var colorBase = COLORS[Math.floor(Math.random() * COLORS.length)];
    return {
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.6,
      vy: (Math.random() - 0.5) * 0.6,
      radius: Math.random() * 2 + 1,
      colorBase: colorBase,
      alpha: Math.random() * 0.4 + 0.2
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
          var alpha = (1 - dist / CONNECTION_DIST) * 0.12;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = 'rgba(139, 134, 128, ' + alpha + ')';
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
  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      if (entries[0].isIntersecting) {
        if (!animId) animate();
      } else {
        cancelAnimationFrame(animId);
        animId = null;
      }
    });
    io.observe(document.body);
  }

  init();
  animate();
})();
