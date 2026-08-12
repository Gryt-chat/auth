import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { KcPage } from "./kc.gen";

// Keycloak injects the page's context onto window before this bundle runs.
// Under `vite dev` there is no Keycloak, so this is undefined — use
// `npm run pages` to see every page against the library's mock context.
//
// Not `npm run storybook`: that is keycloakify start-keycloak, which shells out
// to a Maven build, and this repo builds the theme in Docker (build.sh) so that
// nobody needs Maven. It fails with "Apache Maven required".
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
