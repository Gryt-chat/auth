/**
 * A page browser for the login theme, `npm run pages`. keycloakify's start-keycloak shells
 * out to Maven, which this repo avoids on purpose. Not shipped: index.html pulls nothing in.
 */

import { StrictMode, useState } from "react";
import { createRoot } from "react-dom/client";
import { KcPage } from "./kc.gen";
import { getKcContextMock } from "./login/mocks/getKcContextMock";

/**
 * The pages Gryt can actually reach, first, then the rest. The realm has no identity
 * providers, no consent, no SAML and no device flow, and offers passwordless webauthn.
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
  // The realm does not set internationalizationEnabled, so production shows no locale
  // switcher. The mock turns on all thirty, which buries the title under seven rows.
  const [oneLocale, setOneLocale] = useState(true);
  // The library's mock profile collects five fields; the gryt realm collects email only,
  // since registrationEmailAsUsername is set and the name fields went in GRYT-180.
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
      // registrationEmailAsUsername set Keycloak omits it from what it sends the page.
      const keep = (name: string) => name === "email";
      if (profile?.attributesByName) {
        for (const name of Object.keys(profile.attributesByName)) {
          if (!keep(name)) delete profile.attributesByName[name];
        }
      }
      if (Array.isArray(profile?.attributes)) {
        profile.attributes = profile.attributes.filter(a => keep(a.name));
      }

      // The mock names the saved authenticators "label1" and "label2", which reads as
      // placeholder text. They are whatever a person called their own device.
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
