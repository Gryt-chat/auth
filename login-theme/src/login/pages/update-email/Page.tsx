/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. The fields come from `UserProfileFormFields`, not a hard-coded box.
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
