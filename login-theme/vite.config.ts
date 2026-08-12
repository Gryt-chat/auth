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
      // "gryt" is the name the realm already points at, so shipping under it
      // replaces the old theme with no realm change. Overridable because a
      // theme directory and a theme jar of the same name cannot be compared
      // side by side — build with KC_THEME_NAME=gryt-next to install this
      // alongside the existing one and switch between them in the realm.
      themeName: process.env.KC_THEME_NAME || "gryt"
    })
  ]
});
