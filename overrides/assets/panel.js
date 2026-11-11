"use strict";
document.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-copy]");
  if (!button) return;
  const target = document.getElementById(button.dataset.copy);
  if (!target) return;
  try {
    await navigator.clipboard.writeText(target.textContent);
    button.textContent = "Nusxalandi ✓";
  } catch {
    button.textContent = "Matnni belgilab nusxalang";
  }
});
document.addEventListener("submit", (event) => {
  const button = event.submitter;
  if (button) {
    button.dataset.originalLabel = button.textContent;
    button.disabled = true;
    button.textContent = "Bajarilmoqda…";
  }
});
window.addEventListener("pageshow", () => {
  // Orqaga qaytilganda eski forma tugmalari ishlasin; server takroriy tasdiqni rad etadi.
  document.querySelectorAll("button:disabled").forEach(b => { b.disabled = false; b.textContent = b.dataset.originalLabel || "Davom etish"; });
});
