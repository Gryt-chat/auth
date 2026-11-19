/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. Two actions, two buttons, both on Keycloak's own message keys.
 */

import { ClockIcon } from "@phosphor-icons/react";
import { Button } from "@gryt/ui";
import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "login-page-expired.ftl");

    const { msgStr } = useI18n();

    return (
        <Template
            headerNode={msgStr("pageExpiredTitle")}
            iconNode={<ClockIcon size={24} weight="fill" />}
        >
            <div className="gryt-auth-form">
                <p className="gryt-auth-prose">{msgStr("grytExpiredMsg")}</p>

                <div className="gryt-auth-actions">
                    <Button
                        render={<a id="loginRestartLink" href={kcContext.url.loginRestartFlowUrl} />}
                        nativeButton={false}
                        size="large"
                    >
                        {msgStr("grytStartAgain")}
                    </Button>
                </div>
            </div>
        </Template>
    );
}
