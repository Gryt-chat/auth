/**
 * Owned from @keycloakify/login-ui 250004.7.2. To restore the original:
 *   npx keycloakify own --path "login/pages/webauthn-register/Page.tsx" --revert
 *
 * Adding a passkey. Reachable because webauthn-register-passwordless is an
 * enabled required action on this realm.
 *
 * The button stays outside <form id="register"> exactly as the original had it,
 * and stays type="submit" with that id — useScript looks it up by id, and the
 * script is what calls navigator.credentials.create and fills the hidden inputs
 * before anything is posted. Moving it inside the form would let a browser
 * submit it before the credential exists.
 *
 * The original also put a bare <span> for a key icon inside the page title,
 * styled by a kcClsx class that resolves to nothing here — so it rendered as an
 * empty inline element ahead of the heading text. Dropped rather than replaced:
 * the heading already says what the page is.
 */

import { Button } from "@gryt/ui";
import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";
import { LogoutOtherSessions } from "../../components/LogoutOtherSessions";
import { useScript } from "./useScript";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "webauthn-register.ftl");

    const { msg, msgStr } = useI18n();

    const webAuthnButtonId = "authenticateWebAuthnButton";
    useScript({ webAuthnButtonId });

    return (
        <Template headerNode={msgStr("webauthn-registration-title")}>
            <div className="gryt-auth-form">
                <form id="register" action={kcContext.url.loginAction} method="post">
                    <input type="hidden" id="clientDataJSON" name="clientDataJSON" />
                    <input type="hidden" id="attestationObject" name="attestationObject" />
                    <input
                        type="hidden"
                        id="publicKeyCredentialId"
                        name="publicKeyCredentialId"
                    />
                    <input type="hidden" id="authenticatorLabel" name="authenticatorLabel" />
                    <input type="hidden" id="transports" name="transports" />
                    <input type="hidden" id="error" name="error" />
                    <LogoutOtherSessions />
                </form>

                <div className="gryt-auth-actions">
                    <Button id={webAuthnButtonId} type="submit" size="large">
                        {msgStr("doRegisterSecurityKey")}
                    </Button>

                    {!kcContext.isSetRetry && kcContext.isAppInitiatedAction && (
                        <form
                            action={kcContext.url.loginAction}
                            id="kc-webauthn-settings-form"
                            method="post"
                        >
                            <Button
                                id="cancelWebAuthnAIA"
                                name="cancel-aia"
                                value="true"
                                type="submit"
                                tone="neutral"
                                size="large"
                            >
                                {msg("doCancel")}
                            </Button>
                        </form>
                    )}
                </div>
            </div>
        </Template>
    );
}
