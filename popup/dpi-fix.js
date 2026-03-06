// Windows DPI scaling fix.
// On Windows, Chrome applies OS display scaling to extension popups,
// making them appear larger than intended. macOS handles this correctly.
// We apply a clamped inverse zoom — enough to prevent the popup from
// being oversized, but never below 75% so text stays readable.
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
    // Clamp zoom: compensate DPI but never shrink below 85%.
    // This keeps text readable while preventing an oversized popup.
    // At 125% DPI: zoom=0.85, at 150%: zoom=0.85, at 200%: zoom=0.85
    var zoom = Math.max(1 / dpr, 0.85);
    document.documentElement.style.zoom = zoom;
  }
})();
