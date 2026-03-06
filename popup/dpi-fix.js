// Windows DPI scaling fix.
// Chrome applies OS display scaling to extension popups on Windows.
// Instead of fighting it with zoom (which shrinks text and layout),
// we scale down CSS dimensions so Chrome's native DPI rendering
// produces the intended physical size while keeping text crisp.
(function() {
  var platform = '';
  if (navigator.userAgentData && navigator.userAgentData.platform) {
    platform = navigator.userAgentData.platform;
  } else {
    platform = navigator.userAgent || '';
  }
  var isWindows = /win/i.test(platform);
  var dpr = window.devicePixelRatio;
  if (isWindows && dpr && dpr > 1) {
    // Scale CSS dimensions down; Chrome's DPI multiplier restores physical size.
    // Text renders at native DPI — sharp and readable, no zoom needed.
    var scale = 1 / dpr;
    document.documentElement.style.setProperty('--dpi-scale', scale);
  }
})();
