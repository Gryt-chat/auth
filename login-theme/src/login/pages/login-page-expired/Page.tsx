/**
 * Owned from @keycloakify/login-ui 250004.7.2. To restore the original:
 *   npx keycloakify own --path "login/pages/login-page-expired/Page.tsx" --revert
 *
 * The original renders both routes out of this page as "Click here" links buried
 * mid-sentence — twice, in the same paragraph, with the two links reading
 * identically. Somebody who has just been told their page expired then has to
 * parse two sentences to find out which "here" continues and which starts over.
 *
 * They are two actions, so they are two buttons. Continue is primary because it
 * is what nearly everybody wants; restarting throws away a half-finished login.
 * Both labels are Keycloak's own message keys — no invented copy, so this still
 * translates.
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
