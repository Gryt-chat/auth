/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. `useScript` binds print, download and copy by element id.
 */

import { Button, Checkbox } from "@gryt/ui";
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
    const [nudged, setNudged] = useState(false);

    useScript({ olRecoveryCodesListId });

    return (
        <Template headerNode={msg("recovery-code-config-header")} subtitleNode={msg("grytRecoverySub")}>
            <div className="gryt-auth-form">

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
                <div className="gryt-auth-providers">
                    <Button id="copyRecoveryCodes" type="button" tone="neutral" size="large">
                        {msg("recovery-codes-copy")}
                    </Button>
                    <Button id="downloadRecoveryCodes" type="button" tone="neutral" size="large">
                        {msg("recovery-codes-download")}
                    </Button>
                </div>

                <label className="gryt-auth-confirm" htmlFor="kcRecoveryCodesConfirmationCheck">
                    <Checkbox
                        id="kcRecoveryCodesConfirmationCheck"
                        checked={confirmed}
                        onCheckedChange={(checked: boolean) => {
                            setConfirmed(checked);
                            setNudged(false);
                        }}
                    />
                    <span>{msg("recovery-codes-confirmation-message")}</span>
                </label>
                {nudged && <span className="gryt-auth-error" role="alert">{msg("grytRecoveryNudge")}</span>}

                <form
                    action={url.loginAction}
                    id="kc-recovery-codes-settings-form"
                    method="post"
                    onSubmit={event => {
                        // Never disabled: an unticked box gets a line saying why, and no submit.
                        if (!confirmed && !(event.nativeEvent as SubmitEvent).submitter?.hasAttribute("name")) {
                            event.preventDefault();
                            setNudged(true);
                        }
                    }}
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
                        >
                            {isAppInitiatedAction
                                ? msgStr("recovery-codes-action-complete")
                                : msgStr("grytContinue")}
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
