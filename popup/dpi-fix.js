// Windows DPI scaling fix.
// On Windows, Chrome applies OS display scaling to extension popups,
// making them appear larger than intended. macOS handles this correctly.
// We apply inverse zoom to fix dimensions, then restore font-size so text
// stays readable instead of shrinking with the zoom.
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
    // Counteract zoom's text shrinkage: bump root font-size so em-based
    // sizes render at their intended visual size despite the zoom.
    document.documentElement.style.fontSize = (dpr * 100) + '%';
  }
})();
