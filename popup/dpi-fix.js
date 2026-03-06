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
  var isWindows = /win/i.test(platform);
  var dpr = window.devicePixelRatio;
  if (isWindows && dpr && dpr !== 1) {
    document.documentElement.style.zoom = (1 / dpr);
  }
})();
