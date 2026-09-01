/**
 * A page browser for the login theme. `npm run pages`.
 *
 * The documented way to see these pages is `npm run storybook`, which is
 * keycloakify's start-keycloak — and that shells out to a Maven build. This
 * repo builds the theme in Docker (login-theme/build.sh) precisely so nobody
 * needs a JVM or Maven on their machine, so the documented way does not work
 * here. Without something like this, the only way to look at, say, the passkey
 * error page is to reach it in a real flow, which means owning a broken passkey.
 *
 * The context comes from the mock the library already ships and keeps in step
 * with its own KcContext types, so this stays honest for free.
 *
 * Not shipped: the keycloakify build only takes what index.html pulls in.
 */

import { StrictMode, useState } from "react";
import { createRoot } from "react-dom/client";
import { KcPage } from "./kc.gen";
import { getKcContextMock } from "./login/mocks/getKcContextMock";

/**
 * The pages Gryt can actually reach, first, then the rest.
 *
 * What is reachable is decided by the realm: there are no identity providers,
 * no consent, no SAML and no device flow, and UPDATE_PROFILE, UPDATE_EMAIL and
 * TERMS_AND_CONDITIONS are not enabled required actions. The browser flow does
 * offer webauthn-authenticator-passwordless beside the password form, which is
 * what makes select-authenticator and the webauthn pages ordinary rather than
 * exotic.
 *
 * delete-account-confirm moved up here when auth#17 enabled the delete_account
 * required action. Gryt reaches it with kc_action=delete_account rather than
 * through the account console, so it is a login page like the rest.
 */
const REACHABLE = [
  "login.ftl",
  "register.ftl",
  "select-authenticator.ftl",
  "login-verify-email.ftl",
  "login-reset-password.ftl",
  "login-update-password.ftl",
  "webauthn-authenticate.ftl",
  "webauthn-register.ftl",
  "webauthn-error.ftl",
  "login-otp.ftl",
  "login-config-totp.ftl",
  "login-page-expired.ftl",
  "logout-confirm.ftl",
  "delete-account-confirm.ftl",
  "update-email.ftl",
  "login-recovery-authn-code-config.ftl",
  "info.ftl",
  "error.ftl",
] as const;

const REST = [
  "login-update-profile.ftl",
  "terms.ftl",
  "login-oauth-grant.ftl",
  "login-idp-link-confirm.ftl",
  "saml-post-form.ftl",
  "code.ftl",
  "frontchannel-logout.ftl",
] as const;

function Dev() {
  const initial = new URLSearchParams(location.search).get("page") || REACHABLE[0];
  const [pageId, setPageId] = useState<string>(initial);
  // The realm does not set internationalizationEnabled, so production shows no
  // locale switcher at all. The mock turns on all thirty, which buries the page
  // title under seven rows of links — worth being able to see, not the default.
  const [oneLocale, setOneLocale] = useState(true);
  // The library's mock profile collects username, email, firstName, lastName and
  // locale. The gryt realm collects username and email, renders username never
  // because registrationEmailAsUsername is set, and dropped the two name fields
  // in GRYT-180 — so register.ftl on the mock shows two fields nobody will ever
  // be asked for. Verified against the running local Keycloak, which renders
  // email, password and password-confirm and nothing else.
  const [realRealm, setRealRealm] = useState(true);

  let kcContext: unknown;
  let failure: string | null = null;

  try {
    const ctx = getKcContextMock({ pageId: pageId as never }) as Record<string, unknown>;
    if (oneLocale && ctx.locale && typeof ctx.locale === "object") {
      const locale = ctx.locale as { supported?: unknown[] };
      if (Array.isArray(locale.supported)) locale.supported = locale.supported.slice(0, 1);
    }
    if (realRealm) {
      const realm = ctx.realm as Record<string, unknown> | undefined;
      if (realm) realm.registrationEmailAsUsername = true;
      // attributesByName, not attributes — the mock keys them by name and
      // userProfileApi reads Object.values() off that.
      const profile = ctx.profile as
        | { attributesByName?: Record<string, unknown>; attributes?: { name: string }[] }
        | undefined;
      // Email only. The realm's profile also declares username, but with
      // registrationEmailAsUsername set Keycloak omits it from what it sends the
      // page — which is why the real registration form has no username input.
      const keep = (name: string) => name === "email";
      if (profile?.attributesByName) {
        for (const name of Object.keys(profile.attributesByName)) {
          if (!keep(name)) delete profile.attributesByName[name];
        }
      }
      if (Array.isArray(profile?.attributes)) {
        profile.attributes = profile.attributes.filter(a => keep(a.name));
      }

      // The mock names the saved authenticators "label1" and "label2", which
      // reads as placeholder text sitting in the page rather than as data. They
      // are whatever a person called their own device, so they get names that
      // look like ones. The picker only appears at all with more than one.
      const otpLogin = ctx.otpLogin as
        | { userOtpCredentials?: { id: string; userLabel: string }[] }
        | undefined;
      if (otpLogin?.userOtpCredentials) {
        const names = ["iPhone", "1Password"];
        otpLogin.userOtpCredentials = otpLogin.userOtpCredentials.map((c, i) => ({
          ...c,
          userLabel: names[i] ?? c.userLabel
        }));
      }
    }
    kcContext = ctx;
  } catch (e) {
    failure = String(e);
  }

  return (
    <>
      <div className="gryt-dev-bar">
        <select
          value={pageId}
          onChange={e => {
            setPageId(e.target.value);
            history.replaceState(null, "", `?page=${e.target.value}`);
          }}
        >
          <optgroup label="Gryt can reach these">
            {REACHABLE.map(p => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </optgroup>
          <optgroup label="Unreachable on this realm">
            {REST.map(p => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </optgroup>
        </select>

        <label>
          <input
            type="checkbox"
            checked={oneLocale}
            onChange={e => setOneLocale(e.target.checked)}
          />
          one locale
        </label>

        <label title="Trim the mock's user profile to what the gryt realm actually collects">
          <input
            type="checkbox"
            checked={realRealm}
            onChange={e => setRealRealm(e.target.checked)}
          />
          gryt realm
        </label>
      </div>

      {failure !== null ? (
        <pre className="gryt-dev-failure">{failure}</pre>
      ) : (
        <KcPage key={pageId} kcContext={kcContext as never} />
      )}
    </>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Dev />
  </StrictMode>
);
