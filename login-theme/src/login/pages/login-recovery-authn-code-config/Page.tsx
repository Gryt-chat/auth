/**
 * Owned from @keycloakify/login-ui 250004.7.2. To restore the original:
 *   npx keycloakify own --path "login/pages/login-recovery-authn-code-config/Page.tsx" --revert
 *
 * The one-time codes that get somebody back in when the authenticator is gone.
 *
 * Reachable only once `recovery-codes` is in KC_FEATURES and the
 * CONFIGURE_RECOVERY_AUTHN_CODES required action is registered — both in this
 * PR. Keycloak keeps it behind a flag on 26.5.
 *
 * Two things here are not just restyling.
 *
 * The confirmation checkbox used to reach for the submit button by id and set
 * `.disabled` on it, with an `@ts-expect-error` over the line because the DOM
 * lookup is typed as possibly null. It is React state now, so the button is
 * disabled because the checkbox is unchecked rather than because a side effect
 * got there first.
 *
 * `useScript` is kept, and so are the element ids it binds to —
 * `kc-recovery-codes-list`, `printRecoveryCodes`, `downloadRecoveryCodes`,
 * `copyRecoveryCodes`. It attaches click handlers by id after mount, so renaming
 * any of them silently removes print, download or copy. Those are the only way
 * off this page with the codes, and the page is shown exactly once.
 */

import { Alert, Button } from "@gryt/ui";
import { assert } from "tsafe/assert";
import { useState } from "react";
import { useScript } from "./useScript";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";
import { LogoutOtherSessions } from "../../components/LogoutOtherSessions";

/** The id useScript reads the codes out of. Not decoration — see above. */
const olRecoveryCodesListId = "kc-recovery-codes-list";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "login-recovery-authn-code-config.ftl");

    const { url, recoveryAuthnCodesConfigBean, isAppInitiatedAction } = kcContext;
    const { msg, msgStr } = useI18n();

    const [confirmed, setConfirmed] = useState(false);

    useScript({ olRecoveryCodesListId });

    return (
        <Template headerNode={msg("recovery-code-config-header")}>
            <div className="gryt-auth-form">
                <Alert severity="warning">
                    {msg("recovery-code-config-warning-message")}
                </Alert>

                <ol id={olRecoveryCodesListId} className="gryt-auth-codes">
                    {recoveryAuthnCodesConfigBean.generatedRecoveryAuthnCodesList.map(
                        (code, index) => (
                            <li key={index}>
                                {code.slice(0, 4)}-{code.slice(4, 8)}-{code.slice(8)}
                            </li>
                        )
                    )}
                </ol>

                {/* Type is "button" on all three: they sit outside the form
                    below, but a stray submit here would post the page and the
                    codes are shown once. */}
                <div className="gryt-auth-code-actions">
                    <button id="printRecoveryCodes" className="gryt-auth-link" type="button">
                        {msg("recovery-codes-print")}
                    </button>
                    <button id="downloadRecoveryCodes" className="gryt-auth-link" type="button">
                        {msg("recovery-codes-download")}
                    </button>
                    <button id="copyRecoveryCodes" className="gryt-auth-link" type="button">
                        {msg("recovery-codes-copy")}
                    </button>
                </div>

                <label className="gryt-auth-confirm" htmlFor="kcRecoveryCodesConfirmationCheck">
                    <input
                        type="checkbox"
                        id="kcRecoveryCodesConfirmationCheck"
                        name="kcRecoveryCodesConfirmationCheck"
                        checked={confirmed}
                        onChange={event => setConfirmed(event.target.checked)}
                    />
                    <span>{msg("recovery-codes-confirmation-message")}</span>
                </label>

                <form
                    action={url.loginAction}
                    id="kc-recovery-codes-settings-form"
                    method="post"
                >
                    <input
                        type="hidden"
                        name="generatedRecoveryAuthnCodes"
                        value={recoveryAuthnCodesConfigBean.generatedRecoveryAuthnCodesAsString}
                    />
                    <input
                        type="hidden"
                        name="generatedAt"
                        value={recoveryAuthnCodesConfigBean.generatedAt}
                    />
                    <input
                        type="hidden"
                        id="userLabel"
                        name="userLabel"
                        value={msgStr("recovery-codes-label-default")}
                    />

                    <LogoutOtherSessions />

                    <div id="kc-form-buttons" className="gryt-auth-actions">
                        <Button
                            id="saveRecoveryAuthnCodesBtn"
                            type="submit"
                            size="large"
                            disabled={!confirmed}
                        >
                            {isAppInitiatedAction
                                ? msgStr("recovery-codes-action-complete")
                                : msgStr("doSubmit")}
                        </Button>
                        {isAppInitiatedAction && (
                            <Button
                                type="submit"
                                name="cancel-aia"
                                value="true"
                                tone="neutral"
                                size="large"
                            >
                                {msg("recovery-codes-action-cancel")}
                            </Button>
                        )}
                    </div>
                </form>
            </div>
        </Template>
    );
}
