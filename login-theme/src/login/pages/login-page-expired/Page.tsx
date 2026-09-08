/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. Two actions, two buttons, both on Keycloak's own message keys.
 */

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
        <Template headerNode={msgStr("pageExpiredTitle")}>
            <div className="gryt-auth-form">
                <p className="gryt-auth-prose">{msgStr("pageExpiredMsg2")}.</p>

                <div className="gryt-auth-actions">
                    {/* `render` is Base UI's polymorphism, which @gryt/ui's
                        Button passes through. These navigate rather than submit,
                        so they have to be anchors — a button that changes the
                        page is a lie to assistive tech and dies without JS. */}
                    <Button
                        render={<a id="loginContinueLink" href={kcContext.url.loginAction} />}
                        size="large"
                    >
                        {msgStr("doContinue")}
                    </Button>
                    <Button
                        render={
                            <a id="loginRestartLink" href={kcContext.url.loginRestartFlowUrl} />
                        }
                        tone="neutral"
                        size="large"
                    >
                        {msgStr("restartLoginTooltip")}
                    </Button>
                </div>
            </div>
        </Template>
    );
}
