/**
 * Owned from @keycloakify/login-ui 250004.7.2. To restore the original:
 *   npx keycloakify own --path "login/pages/login/Form.tsx" --revert
 *
 * Rebuilt on @gryt/ui. Field ids and form field names are Keycloak's contract
 * and are preserved exactly — it posts `username` even when the label says
 * Email, and the WebAuthn script looks the button up by id.
 *
 * Note the label already resolves to "Email" on its own, because the realm sets
 * registrationEmailAsUsername. The old theme's gryt-register.js relabelled this
 * by hand; that was never necessary.
 */

import { Button, Checkbox, TextField } from "@gryt/ui";
import { kcSanitize } from "@keycloakify/login-ui/kcSanitize";
import { useState } from "react";
import { assert } from "tsafe/assert";
import { useI18n } from "../../i18n";
import { useKcContext } from "../../KcContext";
import { useScript } from "./useScript";

export function Form() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "login.ftl");

    const { msg, msgStr } = useI18n();
    const [isLoginButtonDisabled, setIsLoginButtonDisabled] = useState(false);

    const webAuthnButtonId = "authenticateWebAuthnButton";
    useScript({ webAuthnButtonId });

    const hasCredentialError = kcContext.messagesPerField.existsError("username", "password");

    // A wrong password must not tell you whether the account exists, so
    // Keycloak reports one error across both fields. Rendering it once, under
    // whichever field is present, keeps that property.
    const credentialError = hasCredentialError ? (
        <span
            id="input-error"
            className="gryt-auth-error"
            aria-live="polite"
            dangerouslySetInnerHTML={{
                __html: kcSanitize(kcContext.messagesPerField.getFirstError("username", "password"))
            }}
        />
    ) : null;

    if (!kcContext.realm.password) {
        return null;
    }

    return (
        <div id="kc-form">
            <form
                id="kc-form-login"
                className="gryt-auth-form"
                onSubmit={() => {
                    setIsLoginButtonDisabled(true);
                    return true;
                }}
                action={kcContext.url.loginAction}
                method="post"
            >
                {!kcContext.usernameHidden && (
                    <div>
                        <TextField
                            id="username"
                            name="username"
                            type="text"
                            label={
                                !kcContext.realm.loginWithEmailAllowed
                                    ? msgStr("username")
                                    : !kcContext.realm.registrationEmailAsUsername
                                      ? msgStr("usernameOrEmail")
                                      : msgStr("email")
                            }
                            defaultValue={kcContext.login.username ?? ""}
                            autoFocus
                            autoComplete={
                                kcContext.enableWebAuthnConditionalUI
                                    ? "username webauthn"
                                    : "username"
                            }
                            aria-invalid={hasCredentialError}
                        />
                        {credentialError}
                    </div>
                )}

                <div>
                    <TextField
                        id="password"
                        name="password"
                        type="password"
                        label={msgStr("password")}
                        autoComplete="current-password"
                        aria-invalid={hasCredentialError}
                    />
                    {kcContext.usernameHidden && credentialError}
                </div>

                <div className="gryt-auth-row">
                    {kcContext.realm.rememberMe && !kcContext.usernameHidden && (
                        <label className="gryt-auth-remember">
                            <Checkbox
                                id="rememberMe"
                                name="rememberMe"
                                defaultChecked={!!kcContext.login.rememberMe}
                            />
                            {msg("rememberMe")}
                        </label>
                    )}
                    {kcContext.realm.resetPasswordAllowed && (
                        <a className="gryt-auth-link" href={kcContext.url.loginResetCredentialsUrl}>
                            {msg("doForgotPassword")}
                        </a>
                    )}
                </div>

                <div id="kc-form-buttons" className="gryt-auth-actions">
                    <input
                        type="hidden"
                        id="id-hidden-input"
                        name="credentialId"
                        value={kcContext.auth.selectedCredential}
                    />
                    <Button
                        id="kc-login"
                        name="login"
                        type="submit"
                        size="large"
                        disabled={isLoginButtonDisabled}
                    >
                        {msgStr("doLogIn")}
                    </Button>
                </div>
            </form>
        </div>
    );
}
