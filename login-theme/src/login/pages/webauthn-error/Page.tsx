/**
 * Owned from @keycloakify/login-ui 250004.7.2. To restore the original:
 *   npx keycloakify own --path "login/pages/webauthn-error/Page.tsx" --revert
 *
 * Where a passkey lands when the browser refuses — cancelled prompt, no
 * matching credential, an authenticator that will not talk. Reachable because
 * the browser flow offers webauthn-authenticator-passwordless.
 *
 * The retry mechanism is Keycloak's and is kept verbatim: the button fills two
 * hidden inputs and submits the form beside it. That is not a pattern worth
 * improving here — the values it writes are what tell the flow which execution
 * to re-run, and the `@ts-expect-error`s below are the original's, kept because
 * the DOM lookups genuinely can return null and Keycloak's code assumes they
 * cannot.
 */

import { Button } from "@gryt/ui";
import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "webauthn-error.ftl");

    const { url, isAppInitiatedAction, execution } = kcContext;
    const { msg, msgStr } = useI18n();

    return (
        <Template displayMessage headerNode={msgStr("webauthn-error-title")}>
            <div className="gryt-auth-form">
                <form
                    id="kc-error-credential-form"
                    action={url.loginAction}
                    method="post"
                >
                    <input type="hidden" id="executionValue" name="authenticationExecution" />
                    <input type="hidden" id="isSetRetry" name="isSetRetry" />
                </form>

                <div className="gryt-auth-actions">
                    <Button
                        id="kc-try-again"
                        name="try-again"
                        type="button"
                        size="large"
                        onClick={() => {
                            // @ts-expect-error: Trusted Keycloak's code
                            document.getElementById("isSetRetry").value = "retry";
                            // @ts-expect-error: Trusted Keycloak's code
                            document.getElementById("executionValue").value = execution;
                            // @ts-expect-error: Trusted Keycloak's code
                            document.getElementById("kc-error-credential-form").requestSubmit();
                        }}
                    >
                        {msgStr("doTryAgain")}
                    </Button>

                    {isAppInitiatedAction && (
                        <form action={url.loginAction} id="kc-webauthn-settings-form" method="post">
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
