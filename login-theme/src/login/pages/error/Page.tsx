/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. The message stays sanitised HTML, because it can carry markup.
 */

import { WarningIcon } from "@phosphor-icons/react";
import { Button } from "@gryt/ui";
import { kcSanitize } from "@keycloakify/login-ui/kcSanitize";
import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "error.ftl");

    const { msg, msgStr } = useI18n();
    const backUrl = kcContext.client?.baseUrl;

    return (
        <Template
            displayMessage={false}
            headerNode={msgStr("errorTitle")}
            iconTone="danger"
            iconNode={<WarningIcon size={24} weight="fill" />}
        >
            <div id="kc-error-message" className="gryt-auth-form">
                <p
                    className="gryt-auth-prose"
                    dangerouslySetInnerHTML={{ __html: kcSanitize(kcContext.message.summary) }}
                />

                {!kcContext.skipLink && !!backUrl && (
                    <div className="gryt-auth-actions">
                        <Button
                            render={<a id="backToApplication" href={backUrl} />}
                            nativeButton={false}
                            size="large"
                        >
                            {msg("backToApplication")}
                        </Button>
                    </div>
                )}
            </div>
        </Template>
    );
}
