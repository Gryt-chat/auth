/**
 * Owned from @keycloakify/login-ui 250004.7.2. To restore the original:
 *   npx keycloakify own --path "login/pages/webauthn-authenticate/Page.tsx" --revert
 *
 * Signing in with a passkey. The browser flow offers
 * webauthn-authenticator-passwordless beside the password form, so this is an
 * ordinary page here rather than an exotic one.
 *
 * Every id below is Keycloak's contract: useScript fills #clientDataJSON,
 * #authenticatorData, #signature, #credentialId, #userHandle and #error on the
 * hidden #webauth form, reads the #authn_select form to know which credentials
 * to offer the browser, and hooks the button by id. The button stays
 * type="button" for that reason — the script submits, not the browser.
 *
 * The list of registered authenticators is not a choice. The original rendered
 * it with the same kcClsx classes as select-authenticator's rows, which made it
 * look like something to click; the browser picks the credential, not the page.
 * It is a list of what this account has, so it reads as one.
 */

import { Button } from "@gryt/ui";
import { Fragment } from "react";
import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";
import { useScript } from "./useScript";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "webauthn-authenticate.ftl");

    const { url, realm, registrationDisabled, authenticators, shouldDisplayAuthenticators } =
        kcContext;
    const { msg, msgStr, advancedMsg } = useI18n();

    const webAuthnButtonId = "authenticateWebAuthnButton";
    useScript({ webAuthnButtonId });

    const listed =
        shouldDisplayAuthenticators && authenticators ? authenticators.authenticators : [];

    return (
        <Template
            displayInfo={realm.registrationAllowed && !registrationDisabled}
            infoNode={
                <div id="kc-registration">
                    <span>
                        {msg("noAccount")}{" "}
                        <a className="gryt-auth-link" href={url.registrationUrl}>
                            {msg("doRegister")}
                        </a>
                    </span>
                </div>
            }
            headerNode={msgStr("webauthn-login-title")}
        >
            <div id="kc-form-webauthn" className="gryt-auth-form">
                <form id="webauth" action={url.loginAction} method="post">
                    <input type="hidden" id="clientDataJSON" name="clientDataJSON" />
                    <input type="hidden" id="authenticatorData" name="authenticatorData" />
                    <input type="hidden" id="signature" name="signature" />
                    <input type="hidden" id="credentialId" name="credentialId" />
                    <input type="hidden" id="userHandle" name="userHandle" />
                    <input type="hidden" id="error" name="error" />
                </form>

                {authenticators && (
                    <form id="authn_select">
                        {authenticators.authenticators.map((authenticator, i) => (
                            <input
                                key={i}
                                type="hidden"
                                name="authn_use_chk"
                                value={authenticator.credentialId}
                            />
                        ))}
                    </form>
                )}

                {listed.length > 0 && (
                    <div className="gryt-auth-devices">
                        {listed.length > 1 && (
                            <p className="gryt-auth-note">
                                {msg("webauthn-available-authenticators")}
                            </p>
                        )}
                        <ul>
                            {listed.map((authenticator, i) => (
                                <li key={i} id={`kc-webauthn-authenticator-item-${i}`}>
                                    <span
                                        className="gryt-auth-device-name"
                                        id={`kc-webauthn-authenticator-label-${i}`}
                                    >
                                        {advancedMsg(authenticator.label)}
                                    </span>
                                    <span className="gryt-auth-device-meta">
                                        {authenticator.transports.displayNameProperties?.length ? (
                                            <span
                                                id={`kc-webauthn-authenticator-transport-${i}`}
                                            >
                                                {authenticator.transports.displayNameProperties
                                                    .map((displayNameProperty, j, arr) => ({
                                                        displayNameProperty,
                                                        hasNext: j !== arr.length - 1
                                                    }))
                                                    .map(({ displayNameProperty, hasNext }) => (
                                                        <Fragment key={displayNameProperty}>
                                                            {advancedMsg(displayNameProperty)}
                                                            {hasNext && <span>, </span>}
                                                        </Fragment>
                                                    ))}
                                                {" · "}
                                            </span>
                                        ) : null}
                                        <span id={`kc-webauthn-authenticator-createdlabel-${i}`}>
                                            {msg("webauthn-createdAt-label")}
                                        </span>{" "}
                                        <span id={`kc-webauthn-authenticator-created-${i}`}>
                                            {authenticator.createdAt}
                                        </span>
                                    </span>
                                </li>
                            ))}
                        </ul>
                    </div>
                )}

                <div id="kc-form-buttons" className="gryt-auth-actions">
                    <Button id={webAuthnButtonId} type="button" autoFocus size="large">
                        {msgStr("webauthn-doAuthenticate")}
                    </Button>
                </div>
            </div>
        </Template>
    );
}
