/**
 * Owned from @keycloakify/login-ui 250004.7.2. To restore the original:
 *   npx keycloakify own --path "login/components/Template/Template.tsx" --revert
 *
 * The page shell every login-theme page renders through.
 *
 * Rebuilt on @gryt/ui so the sign-in pages are the same design system as the
 * client, rather than PatternFly with Gryt colours painted over it. The DOM ids
 * Keycloak's own scripts and docs refer to (kc-page-title, kc-content,
 * kc-select-try-another-way-form) are kept — they are an interface, not
 * decoration.
 */

import { Alert, Button } from "@gryt/ui";
import { kcSanitize } from "@keycloakify/login-ui/kcSanitize";
import { useSetClassName } from "@keycloakify/login-ui/tools/useSetClassname";
import type { ReactNode } from "react";
import { useEffect } from "react";
import { useI18n } from "../../i18n";
import { ShaderBackground } from "../ShaderBackground/ShaderBackground";
import { useKcContext } from "../../KcContext";
import { useInitializeTemplate } from "./useInitializeTemplate";

/** Keycloak's message types map onto the library's severities one for one. */
const severityByMessageType = {
  error: "error",
  warning: "warning",
  success: "success",
  info: "info",
} as const;

export function Template(props: {
  displayInfo?: boolean;
  displayMessage?: boolean;
  displayRequiredFields?: boolean;
  headerNode: ReactNode;
  socialProvidersNode?: ReactNode;
  infoNode?: ReactNode;
  documentTitle?: string;
  bodyClassName?: string;
  children: ReactNode;
}) {
  const {
    displayInfo = false,
    displayMessage = true,
    displayRequiredFields = false,
    headerNode,
    socialProvidersNode = null,
    infoNode = null,
    documentTitle,
    bodyClassName,
    children,
  } = props;

  const { kcContext } = useKcContext();
  const { msg, msgStr, currentLanguage, enabledLanguages } = useI18n();

  useEffect(() => {
    document.title =
      documentTitle ??
      msgStr("loginTitle", kcContext.realm.displayName || kcContext.realm.name);
  }, []);

  useSetClassName({ qualifiedName: "html", className: "gryt-auth-html" });
  useSetClassName({
    qualifiedName: "body",
    className: bodyClassName ?? "gryt-auth-body",
  });

  const { isReadyToRender } = useInitializeTemplate();

  if (!isReadyToRender) {
    return null;
  }

  // Keycloak shows the account being signed into rather than the page title
  // when re-authenticating, with a link back to start over.
  const showAttemptedUsername =
    kcContext.auth !== undefined &&
    kcContext.auth.showUsername &&
    !kcContext.auth.showResetCredentials;

  const showTryAnotherWay =
    kcContext.auth !== undefined && kcContext.auth.showTryAnotherWayLink;

  return (
    <>
      <ShaderBackground />

      <div className="gryt-auth-layout">
        {/* The brand panel. This is often the first Gryt surface someone
                sees — arriving from an invite link, before they have any idea
                what Gryt is — so it says so. Copy is the site's own, not
                written for this page. */}
        <aside className="gryt-auth-brand">
          <div className="gryt-auth-wordmark">Gryt</div>

          <div className="gryt-auth-pitch-block">
            <p className="gryt-auth-pitch">Voice, text and video chat.</p>
            <p className="gryt-auth-pitch-sub">Self-hosted and open source.</p>
          </div>

          <ul className="gryt-auth-chips">
            <li>Own your data</li>
            <li>Host your server</li>
            <li>Build your client</li>
          </ul>
        </aside>

        <main className="gryt-auth-main">
          <div className="gryt-auth-shell">
            <header className="gryt-auth-header">
              {enabledLanguages.length > 1 && (
                <nav id="kc-locale" aria-label={msgStr("languages")}>
                  <ul className="gryt-auth-locales">
                    {enabledLanguages.map(({ languageTag, label, href }) => (
                      <li key={languageTag}>
                        <a
                          className="gryt-auth-link"
                          href={href}
                          aria-current={
                            languageTag === currentLanguage.languageTag
                              ? "true"
                              : undefined
                          }
                        >
                          {label}
                        </a>
                      </li>
                    ))}
                  </ul>
                </nav>
              )}

              {showAttemptedUsername ? (
                <div id="kc-username" className="gryt-auth-attempted">
                  <span id="kc-attempted-username">
                    {kcContext.auth!.attemptedUsername}
                  </span>
                  <a
                    id="reset-login"
                    className="gryt-auth-link"
                    href={kcContext.url.loginRestartFlowUrl}
                    aria-label={msgStr("restartLoginTooltip")}
                  >
                    {msg("restartLoginTooltip")}
                  </a>
                </div>
              ) : (
                <h1 id="kc-page-title" className="gryt-auth-title">
                  {headerNode}
                </h1>
              )}

              {displayRequiredFields && (
                <p className="gryt-auth-subtitle">
                  <span aria-hidden>*</span> {msg("requiredFields")}
                </p>
              )}
            </header>

            {/* No card. The brand panel is the page's structure, so a Surface
                around the form here would be a box inside a box. */}
            <div id="kc-content">
              <div id="kc-content-wrapper" className="gryt-auth-form">
                {/* App-initiated actions should not warn about completing
                        the action during login. */}
                {displayMessage &&
                  kcContext.message !== undefined &&
                  (kcContext.message.type !== "warning" ||
                    !kcContext.isAppInitiatedAction) && (
                    <Alert
                      severity={severityByMessageType[kcContext.message.type]}
                    >
                      <span
                        dangerouslySetInnerHTML={{
                          __html: kcSanitize(kcContext.message.summary),
                        }}
                      />
                    </Alert>
                  )}

                {children}

                {/* Other ways in. Keycloak decides at runtime whether any exist
                  — passkeys and OTP both surface here — so this whole region
                  comes and goes, and the rule above it belongs to the region
                  rather than sitting on the page waiting for content. */}
                {(showTryAnotherWay || socialProvidersNode !== null) && (
                  <div className="gryt-auth-alternatives">
                    {showTryAnotherWay && (
                      <form
                        id="kc-select-try-another-way-form"
                        action={kcContext.url.loginAction}
                        method="post"
                      >
                        {/* A submit button, not a link that submits a form from
                          an onClick. This posts and navigates, which is what a
                          button means; as an anchor it lied to assistive tech
                          and did nothing without JavaScript. */}
                        <Button
                          type="submit"
                          name="tryAnotherWay"
                          value="on"
                          id="try-another-way"
                          tone="neutral"
                          size="large"
                        >
                          {msgStr("doTryAnotherWay")}
                        </Button>
                      </form>
                    )}

                    {socialProvidersNode}
                  </div>
                )}
              </div>
            </div>

            {displayInfo && (
              <div id="kc-info" className="gryt-auth-footer">
                {infoNode}
              </div>
            )}
          </div>
        </main>
      </div>
    </>
  );
}
