// Homepage behaviour: scroll reveal, demo video, hero demo. Loaded with defer; kept in a file so the site CSP can forbid inline scripts.
(function() {
  // Scroll reveal
  if ('IntersectionObserver' in window) {
    var fades = document.querySelectorAll('.fade-up');
    document.documentElement.classList.add('reveal');
    var obs = new IntersectionObserver(function(entries) {
      entries.forEach(function(e) {
        if (e.isIntersecting) { e.target.classList.add('vis'); obs.unobserve(e.target); }
      });
    }, { threshold: 0.1 });
    fades.forEach(function(f) { obs.observe(f); });
  }

  // ======= Demo video: swap the poster for the player on click =======
  var player = document.getElementById('video-player');
  if (player) {
    player.addEventListener('click', function(e) {
      // YouTube refuses embeds that arrive without a referrer (error 153), which is what a file:// page sends.
      // There the link just opens YouTube in a new tab.
      if (location.protocol === 'file:') return;
      e.preventDefault();
      var wrap = document.createElement('div');
      wrap.className = 'video';
      var frame = document.createElement('iframe');
      frame.src = 'https://www.youtube-nocookie.com/embed/QP6XshUrCm4?autoplay=1&rel=0';
      frame.title = 'Paste Safely with Secret Sanitizer';
      frame.allow = 'autoplay; encrypted-media; picture-in-picture; fullscreen';
      frame.allowFullscreen = true;
      frame.referrerPolicy = 'strict-origin-when-cross-origin';
      wrap.appendChild(frame);
      player.parentNode.replaceChild(wrap, player);
    });
  }

  // ======= Hero demo: a paste lands in the chat box and its secrets become placeholders =======
  // Each line is [key, operator, value, placeholder]. Lines without a placeholder are ordinary text and stay as pasted.
  var scenarios = [
    {
      title: 'chatgpt.com', site: 'ChatGPT',
      lines: [
        ['NODE_ENV', '=', 'production'],
        ['OPENAI_API_KEY', '=', 'sk-proj-abc123xyz789def456ghi012jkl345mn', '[OPENAI_KEY_k3f9_0]'],
        ['DATABASE_URL', '=', 'postgres://admin:s3cret@db.prod:5432/app', '[DB_CONN_k3f9_1]'],
      ]
    },
    {
      title: 'claude.ai', site: 'Claude',
      lines: [
        ['CURRENCY', '=', 'usd'],
        // Split so secret scanners (e.g. GitHub push protection) don't flag this fake demo key
        ['STRIPE_SECRET_KEY', '=', 'sk_' + 'live_51HG7dKLMn0pQrStUvWxYz012', '[STRIPE_KEY_p7x2_0]'],
        ['AWS_ACCESS_KEY_ID', '=', 'AKIAIOSFODNN7EXAMPLE', '[AWS_KEY_p7x2_1]'],
      ]
    },
    {
      title: 'gemini.google.com', site: 'Gemini',
      lines: [
        ['region', ': ', 'us-east-1'],
        ['GITHUB_TOKEN', '=', 'ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8', '[GITHUB_TOKEN_m4q8_0]'],
        ['Authorization', ': Bearer ', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0', '[JWT_m4q8_1]'],
      ]
    },
    {
      title: 'chatgpt.com', site: 'ChatGPT',
      lines: [
        ['Order', ': ', '#48213'],
        ['Card', ': ', '4532 0151 1283 0366', '[CREDIT_CARD_c2w5_0]'],
        ['UPI', ': ', 'yourname@oksbi', '[UPI_ID_c2w5_1]'],
      ]
    }
  ];

  var linesEl = document.getElementById('demo-lines');
  var toastEl = document.getElementById('demo-toast');
  var toastText = document.getElementById('toast-text');
  var titleEl = document.getElementById('demo-title');
  var caret = document.createElement('span');
  caret.className = 'caret end';
  var idx = -1;

  function span(cls, text) {
    var s = document.createElement('span');
    s.className = cls;
    s.textContent = text || '';
    return s;
  }

  function addLine() {
    var row = document.createElement('div');
    row.className = 'demo-line';
    return linesEl.appendChild(row);
  }

  // Streams `text` into `target` a few characters per frame, with the caret riding the end
  function stream(target, text, done) {
    var i = 0;
    target.parentNode.appendChild(caret);
    (function tick() {
      if (i >= text.length) return done();
      i += 2;
      target.textContent = text.slice(0, i);
      setTimeout(tick, 22);
    })();
  }

  function streamLines(lines, n, secrets, done) {
    if (n === lines.length) return done();
    var l = lines[n], row = addLine();
    stream(row.appendChild(span('demo-key')), l[0], function() {
      stream(row.appendChild(span('demo-op')), l[1], function() {
        var val = row.appendChild(span('demo-val'));
        if (l[3]) { val.dataset.label = l[3]; secrets.push(val); }
        stream(val, l[2], function() {
          setTimeout(function() { streamLines(lines, n + 1, secrets, done); }, 90);
        });
      });
    });
  }

  function play() {
    idx = (idx + 1) % scenarios.length;
    var s = scenarios[idx];

    // 1. Empty chat box, waiting for input
    titleEl.textContent = s.title;
    toastEl.classList.remove('show');
    linesEl.textContent = '';
    var hint = addLine();
    hint.className = 'demo-line demo-placeholder';
    hint.appendChild(span('caret'));
    hint.appendChild(document.createTextNode('Message ' + s.site));

    // 2. The paste flows in line by line
    setTimeout(function() {
      linesEl.textContent = '';
      var secrets = [];
      streamLines(s.lines, 0, secrets, function() {
        // 3. The secrets light up for a moment, as if selected...
        setTimeout(function() {
          if (caret.parentNode) caret.parentNode.removeChild(caret);
          secrets.forEach(function(v) { v.classList.add('found'); });
          // 4. ...then each becomes its placeholder at the same instant
          setTimeout(function() {
            secrets.forEach(function(v) {
              v.parentNode.replaceChild(span('chip', v.dataset.label), v);
            });
            toastText.textContent = secrets.length + (secrets.length === 1 ? ' secret masked' : ' secrets masked');
            toastEl.classList.add('show');
            setTimeout(play, 4000);
          }, 420);
        }, 300);
      });
    }, 700);
  }

  // Without motion the static markup (scenario 0, already masked) is the whole demo
  if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) setTimeout(play, 500);
})();
