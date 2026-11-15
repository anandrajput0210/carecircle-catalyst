/**
 * CareCircle - Client Accessibility & State Helpers
 */
(function () {
  "use strict";

  // Elements
  const body = document.body;
  const toggleContrastBtn = document.getElementById("toggle-contrast");
  const increaseFontBtn = document.getElementById("increase-font");
  const decreaseFontBtn = document.getElementById("decrease-font");
  const liveAnnouncer = document.getElementById("live-announcer");

  // State
  const fontSizes = ["standard", "font-large", "font-xlarge"];
  let currentFontIdx = 0;

  // Screen Reader Live Announcer
  function announce(message) {
    if (liveAnnouncer) {
      liveAnnouncer.textContent = "";
      setTimeout(function () {
        liveAnnouncer.textContent = message;
      }, 50);
    }
  }

  // High Contrast Mode
  function initContrast() {
    const isHighContrast = localStorage.getItem("carecircle_contrast") === "high";
    if (isHighContrast) {
      body.classList.add("high-contrast");
      if (toggleContrastBtn) {
        toggleContrastBtn.setAttribute("aria-pressed", "true");
      }
    }
  }

  if (toggleContrastBtn) {
    toggleContrastBtn.addEventListener("click", function () {
      const isHigh = body.classList.toggle("high-contrast");
      localStorage.setItem("carecircle_contrast", isHigh ? "high" : "normal");
      toggleContrastBtn.setAttribute("aria-pressed", isHigh ? "true" : "false");
      announce(isHigh ? "High contrast mode enabled" : "Standard contrast mode enabled");
    });
  }

  // Font Scaling
  function initFontSize() {
    const savedSize = localStorage.getItem("carecircle_font_size");
    if (savedSize && fontSizes.includes(savedSize)) {
      currentFontIdx = fontSizes.indexOf(savedSize);
      applyFontSize();
    }
  }

  function applyFontSize() {
    fontSizes.forEach(function (cls) {
      if (cls !== "standard") body.classList.remove(cls);
    });
    const activeClass = fontSizes[currentFontIdx];
    if (activeClass !== "standard") {
      body.classList.add(activeClass);
    }
    localStorage.setItem("carecircle_font_size", activeClass);
    announce("Text size adjusted to " + (activeClass === "standard" ? "standard" : activeClass.replace("font-", "")));
  }

  if (increaseFontBtn) {
    increaseFontBtn.addEventListener("click", function () {
      if (currentFontIdx < fontSizes.length - 1) {
        currentFontIdx++;
        applyFontSize();
      }
    });
  }

  if (decreaseFontBtn) {
    decreaseFontBtn.addEventListener("click", function () {
      if (currentFontIdx > 0) {
        currentFontIdx--;
        applyFontSize();
      }
    });
  }

  // Logout Handler
  const logoutBtn = document.getElementById("btn-logout");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", async function () {
      const meta = document.querySelector('meta[name="csrf-token"]');
      const csrf = meta ? meta.getAttribute("content") : "";
      try {
        await fetch("/auth/logout", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": csrf,
          },
        });
      } catch (e) {
        // Proceed with redirect regardless of network status
      }
      window.location.href = "/";
    });
  }

  // Initialize
  initContrast();
  initFontSize();
})();
