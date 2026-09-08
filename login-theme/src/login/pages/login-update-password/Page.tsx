/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. It posts `password-new` and `password-confirm`.
 */

import { Button, TextField } from "@gryt/ui";
import { kcSanitize } from "@keycloakify/login-ui/kcSanitize";
import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";
import { LogoutOtherSessions } from "../../components/LogoutOtherSessions";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "login-update-password.ftl");

    const { msg, msgStr } = useI18n();
    const { url, messagesPerField, isAppInitiatedAction } = kcContext;

    const newError = messagesPerField.existsError("password");
    const confirmError = messagesPerField.existsError("password-confirm");

    return (
        <Template
            displayMessage={!messagesPerField.existsError("password", "password-confirm")}
            headerNode={msgStr("updatePasswordTitle")}
        >
            <form
                id="kc-passwd-update-form"
                className="gryt-auth-form"
                action={url.loginAction}
                method="post"
            >
                <div>
                    <TextField
                        id="password-new"
                        name="password-new"
                        type="password"
                        label={msgStr("passwordNew")}
                        autoFocus
                        autoComplete="new-password"
                        error={newError}
                        aria-invalid={newError}
                    />
                    {newError && (
                        <span
                            id="input-error-password"
                            className="gryt-auth-error"
                            aria-live="polite"
                            dangerouslySetInnerHTML={{
                                __html: kcSanitize(messagesPerField.get("password"))
                            }}
                        />
                    )}
                </div>

                <div>
                    {/* No autoFocus here. The original set it on both fields, so
                        the browser settled on the second one and the cursor
                        started in "confirm" with "new" still empty. */}
                    <TextField
                        id="password-confirm"
                        name="password-confirm"
                        type="password"
                        label={msgStr("passwordConfirm")}
                        autoComplete="new-password"
                        error={confirmError}
                        aria-invalid={confirmError}
                    />
                    {confirmError && (
                        <span
                            id="input-error-password-confirm"
                            className="gryt-auth-error"
                            aria-live="polite"
                            dangerouslySetInnerHTML={{
                                __html: kcSanitize(messagesPerField.get("password-confirm"))
                            }}
                        />
                    )}
                </div>

                <LogoutOtherSessions />

                <div id="kc-form-buttons" className="gryt-auth-actions">
                    <Button type="submit" size="large">
                        {msgStr("doSubmit")}
                    </Button>
                    {isAppInitiatedAction && (
                        <Button
                            type="submit"
                            name="cancel-aia"
                            value="true"
                            tone="neutral"
                            size="large"
                        >
                            {msg("doCancel")}
                        </Button>
                    )}
                </div>
            </form>
        </Template>
    );
}
