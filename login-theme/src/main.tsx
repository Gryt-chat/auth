import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { KcPage } from "./kc.gen";

// Keycloak injects the page's context onto window before this bundle runs.
// Under `vite dev` there is no Keycloak, so this is undefined — use
// `npm run storybook` (keycloakify start-keycloak) to see real pages.
const { kcContext } = window;

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    {kcContext === undefined ? (
      <p>
        No Keycloak context. Run <code>npm run storybook</code> to render these
        pages against a real Keycloak.
      </p>
    ) : (
      <KcPage kcContext={kcContext} />
    )}
  </StrictMode>
);
