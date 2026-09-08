/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. `otp` is what Keycloak posts; errors report under `totp`.
 */

import { Button, OtpField, Radio, RadioGroup } from "@gryt/ui";
import { kcSanitize } from "@keycloakify/login-ui/kcSanitize";
import { useState } from "react";
import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "login-otp.ftl");

    const { msg, msgStr } = useI18n();
    const [isSubmitting, setIsSubmitting] = useState(false);

    const hasError = kcContext.messagesPerField.existsError("totp");
    const credentials = kcContext.otpLogin.userOtpCredentials;

    return (
        <Template displayMessage={!hasError} headerNode={msgStr("doLogIn")}>
            <form
                id="kc-otp-login-form"
                className="gryt-auth-form"
                action={kcContext.url.loginAction}
                onSubmit={() => {
                    setIsSubmitting(true);
                    return true;
                }}
                method="post"
            >
                {credentials.length > 1 && (
                    <RadioGroup
                        name="selectedCredentialId"
                        defaultValue={kcContext.otpLogin.selectedCredentialId}
                        className="gryt-auth-credentials"
                    >
                        {credentials.map((otpCredential, index) => (
                            <label
                                key={index}
                                className="gryt-auth-credential"
                                htmlFor={`kc-otp-credential-${index}`}
                            >
                                <Radio id={`kc-otp-credential-${index}`} value={otpCredential.id} />
                                {otpCredential.userLabel}
                            </label>
                        ))}
                    </RadioGroup>
                )}

                <div className="gryt-auth-otp">
                    <label className="gryt-auth-otp-label" htmlFor="otp">
                        {msg("loginOtpOneTime")}
                    </label>
                    <OtpField id="otp" name="otp" length={6} autoFocus aria-invalid={hasError} />
                    {hasError && (
                        <span
                            id="input-error-otp-code"
                            className="gryt-auth-error"
                            aria-live="polite"
                            dangerouslySetInnerHTML={{
                                __html: kcSanitize(kcContext.messagesPerField.get("totp"))
                            }}
                        />
                    )}
                </div>

                <div id="kc-form-buttons" className="gryt-auth-actions">
                    <Button
                        id="kc-login"
                        name="login"
                        type="submit"
                        size="large"
                        disabled={isSubmitting}
                    >
                        {msgStr("doLogIn")}
                    </Button>
                </div>
            </form>
        </Template>
    );
}
