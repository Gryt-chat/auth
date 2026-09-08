import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { KcPage } from "./kc.gen";

// Keycloak injects the page's context onto window before this bundle runs; under `vite dev`
// there is none. Use `npm run pages`, not storybook, which shells out to Maven.
const { kcContext } = window;

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    {kcContext === undefined ? (
      <p>
        No Keycloak context. Run <code>npm run pages</code> to look at every page.
      </p>
    ) : (
      <KcPage kcContext={kcContext} />
    )}
  </StrictMode>
);
