/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. `useScript` binds print, download and copy by element id.
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
