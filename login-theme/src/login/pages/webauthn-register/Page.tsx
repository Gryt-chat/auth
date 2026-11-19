/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. The button stays outside the form, type="submit", with that id.
 */

import { FingerprintIcon } from "@phosphor-icons/react";
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
        <Template
            headerNode={msgStr("webauthn-registration-title")}
            subtitleNode={msgStr("grytPasskeyRegisterSub")}
            iconNode={<FingerprintIcon size={24} weight="fill" />}
        >
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
                                tone="ghost"
                                size="large"
                                className="gryt-auth-quiet"
                            >
                                {msg("grytNotNow")}
                            </Button>
                        </form>
                    )}
                </div>
            </div>
        </Template>
    );
}
