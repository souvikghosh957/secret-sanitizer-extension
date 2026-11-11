// Homepage behaviour: scroll reveal, demo video, hero demo. Loaded with defer; kept in a file so the site CSP can forbid inline scripts.
(function() {
  // Scroll reveal
  var fades = document.querySelectorAll('.fade-up');
  if ('IntersectionObserver' in window) {
    var obs = new IntersectionObserver(function(entries) {
      entries.forEach(function(e) {
        if (e.isIntersecting) { e.target.classList.add('vis'); obs.unobserve(e.target); }
      });
    }, { threshold: 0.1 });
    fades.forEach(function(f) { obs.observe(f); });
  } else {
    fades.forEach(function(f) { f.classList.add('vis'); });
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
  var idx = 0;

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

    // 2. Paste: every line lands at once, as a real paste does
    setTimeout(function() {
      linesEl.textContent = '';
      var secrets = [];
      s.lines.forEach(function(l) {
        var row = addLine();
        row.appendChild(span('demo-key', l[0]));
        row.appendChild(span('demo-op', l[1]));
        var val = row.appendChild(span('demo-val', l[2]));
        if (l[3]) { val.dataset.label = l[3]; secrets.push(val); }
      });

      // 3. The secrets are spotted...
      setTimeout(function() {
        secrets.forEach(function(v) { v.classList.add('hit'); });

        // 4. ...and swapped for placeholders, one after another
        setTimeout(function() {
          secrets.forEach(function(v, n) {
            var chip = span('chip chip-in', v.dataset.label);
            chip.style.animationDelay = (n * 0.22) + 's';
            v.parentNode.replaceChild(chip, v);
          });
          setTimeout(function() {
            toastText.textContent = secrets.length + (secrets.length === 1 ? ' secret masked' : ' secrets masked');
            toastEl.classList.add('show');
            setTimeout(play, 4200);
          }, 500);
        }, 700);
      }, 450);
    }, 1400);
  }

  // The static markup already shows scenario 0 masked, so the loop starts on the next one
  if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) setTimeout(play, 3600);
})();
