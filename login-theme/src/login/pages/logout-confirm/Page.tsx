/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. `session_code` and the `confirmLogout` name are the contract.
 */

import { Button } from "@gryt/ui";
import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "logout-confirm.ftl");

    const { url, client, logoutConfirm } = kcContext;
    const { msg, msgStr } = useI18n();

    return (
        <Template headerNode={msgStr("logoutConfirmTitle")}>
            <div id="kc-logout-confirm" className="gryt-auth-form">
                <p className="gryt-auth-prose">{msg("logoutConfirmHeader")}</p>

                <form action={url.logoutConfirmAction} method="POST">
                    <input type="hidden" name="session_code" value={logoutConfirm.code} />
                    <div id="kc-form-buttons" className="gryt-auth-actions">
                        <Button id="kc-logout" name="confirmLogout" type="submit" size="large">
                            {msgStr("doLogout")}
                        </Button>
                    </div>
                </form>

                {!logoutConfirm.skipLink && client.baseUrl && (
                    <div id="kc-info-message" className="gryt-auth-footer">
                        <a className="gryt-auth-link" href={client.baseUrl}>
                            {msg("backToApplication")}
                        </a>
                    </div>
                )}
            </div>
        </Template>
    );
}
