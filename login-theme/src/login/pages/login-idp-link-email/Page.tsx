/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. Both of Keycloak's "click here" links go to loginAction.
 */

import { Button } from "@gryt/ui";
import { EnvelopeSimpleIcon } from "@phosphor-icons/react";
import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";
import { idpName } from "../login-idp-link-confirm/Page";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "login-idp-link-email.ftl");

    const { msg, msgStr } = useI18n();
    const idp = idpName(kcContext.idpAlias);

    return (
        <Template displayMessage={false} headerNode={msg("emailLinkIdpTitle")} iconNode={<EnvelopeSimpleIcon size={24} weight="fill" />}>
            <div className="gryt-auth-form">
                <p id="instruction1" className="gryt-auth-prose">
                    {msg("grytLinkEmailSub", idp, kcContext.brokerContext.username)}
                </p>
                <div className="gryt-auth-actions">
                    <Button render={<a href={kcContext.url.loginAction} />} nativeButton={false} tone="neutral" size="large">
                        {msgStr("grytResendEmail")}
                    </Button>
                </div>
                <p className="gryt-auth-note">{msg("grytMailHint")}</p>
                <p className="gryt-auth-footer">
                    <a className="gryt-auth-link" href={kcContext.url.loginAction}>
                        {msg("grytLinkEmailContinue")}
                    </a>
                </p>
            </div>
        </Template>
    );
}
