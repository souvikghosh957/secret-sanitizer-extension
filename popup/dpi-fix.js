// Secret Sanitizer - Windows High DPI Popup Fix (Recommended)
(function() {
  const isWindows = /win/i.test(navigator.userAgentData?.platform || navigator.userAgent);
  const dpr = window.devicePixelRatio || 1;

  if (isWindows && dpr > 1.15) {
    // Gentle increase (feels perfect on 125–175% scaling)
    document.documentElement.style.fontSize = '107.5%';
    
    // Make popup comfortably larger on Windows
    const container = document.querySelector('.container');
    if (container) container.style.width = '398px';
  }
})();
