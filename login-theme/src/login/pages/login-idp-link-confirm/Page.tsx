/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. Linking first; "review profile" is the way to a separate account.
 */

import { Button } from "@gryt/ui";
import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";

export const idpName = (alias: string) => alias.charAt(0).toUpperCase() + alias.slice(1);

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "login-idp-link-confirm.ftl");

    const { msg, msgStr } = useI18n();
    const idp = idpName(kcContext.idpAlias);

    return (
        <Template displayMessage={false} headerNode={msg("confirmLinkIdpTitle")} subtitleNode={msgStr("grytLinkSub", idp)}>
            <form id="kc-register-form" className="gryt-auth-form" action={kcContext.url.loginAction} method="post">
                <p className="gryt-auth-callout">{msg("grytLinkNote")}</p>
                <div className="gryt-auth-actions">
                    <Button type="submit" name="submitAction" id="linkAccount" value="linkAccount" size="large">
                        {msgStr("confirmLinkIdpContinue", idp)}
                    </Button>
                    <Button type="submit" name="submitAction" id="updateProfile" value="updateProfile" tone="ghost" size="large" className="gryt-auth-quiet">
                        {msgStr("confirmLinkIdpReviewProfile")}
                    </Button>
                </div>
            </form>
        </Template>
    );
}
