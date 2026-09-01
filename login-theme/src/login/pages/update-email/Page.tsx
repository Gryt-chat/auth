/**
 * Owned from @keycloakify/login-ui 250004.7.2. To restore the original:
 *   npx keycloakify own --path "login/pages/update-email/Page.tsx" --revert
 *
 * Changing the address on an account.
 *
 * Reachable only once `update-email` is in KC_FEATURES and the UPDATE_EMAIL
 * required action is registered — both in this PR. Keycloak keeps this behind a
 * flag on 26.5, so on a server without it the action does not exist and this
 * page is dead code.
 *
 * On this realm the email *is* the username (`registrationEmailAsUsername`), so
 * this changes what somebody signs in with. That is the reason to route people
 * here rather than to UPDATE_PROFILE, which edits the same field and skips the
 * re-verification.
 *
 * The fields come from `UserProfileFormFields` rather than a hand-written input,
 * because the realm's declarative user profile decides what is asked for and
 * what it validates. Hard-coding an email box here would drift from
 * gryt-user-profile.json the first time it changed.
 */

import { Button } from "@gryt/ui";
import { assert } from "tsafe/assert";
import { useState } from "react";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";
import { UserProfileFormFields } from "../../components/UserProfileFormFields";
import { LogoutOtherSessions } from "../../components/LogoutOtherSessions";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "update-email.ftl");

    const { msg, msgStr } = useI18n();
    const { url, messagesPerField, isAppInitiatedAction } = kcContext;

    const [isFormSubmittable, setIsFormSubmittable] = useState(false);

    return (
        <Template
            displayMessage={messagesPerField.exists("global")}
            displayRequiredFields
            headerNode={msg("updateEmailTitle")}
        >
            <form
                id="kc-update-email-form"
                className="gryt-auth-form"
                action={url.loginAction}
                method="post"
            >
                <UserProfileFormFields onIsFormSubmittableValueChange={setIsFormSubmittable} />

                <LogoutOtherSessions />

                <div id="kc-form-buttons" className="gryt-auth-actions">
                    <Button type="submit" size="large" disabled={!isFormSubmittable}>
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
