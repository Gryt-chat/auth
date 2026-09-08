import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { keycloakify } from "keycloakify/vite-plugin";

export default defineConfig({
  plugins: [
    react(),
    keycloakify({
      // Only the login theme is rebuilt here. The email theme keeps its own
      // hand-written .ftl overrides — those already work and are out of scope.
      accountThemeImplementation: "none",
      // "gryt" is the name the realm already points at, so this replaces the old theme with
      // no realm change. Build with KC_THEME_NAME=gryt-next to install one alongside it.
      themeName: process.env.KC_THEME_NAME || "gryt"
    })
  ]
});
