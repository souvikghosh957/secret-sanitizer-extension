// Windows DPI scaling fix.
// On Windows, Chrome applies OS display scaling to extension popups,
// making them appear larger than intended. macOS handles this correctly.
(function() {
  var platform = '';
  if (navigator.userAgentData && navigator.userAgentData.platform) {
    platform = navigator.userAgentData.platform;
  } else {
    platform = navigator.userAgent || '';
  }
  var isMac = /mac/i.test(platform);
  var dpr = window.devicePixelRatio;
  if (!isMac && dpr && dpr !== 1) {
    var s = document.documentElement.style;
    s.zoom = (1 / dpr);
    s.setProperty('--dpr-scale', dpr);
  }
})();
