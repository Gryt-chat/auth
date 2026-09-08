/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. Cancel is prominent and deleting plain: the costs differ.
 */

import { Alert, Button } from "@gryt/ui";
import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "delete-account-confirm.ftl");

    const { url, triggered_from_aia } = kcContext;
    const { msg, msgStr } = useI18n();

    return (
        <Template headerNode={msg("deleteAccountConfirm")}>
            <div id="kc-delete-account-confirm" className="gryt-auth-form">
                {/* Keycloak's own strings throughout, not ours. They are
                    translated into every language the realm offers, and a
                    hand-written English line here would be the one thing on the
                    page somebody could not read. */}
                <Alert severity="error">{msg("irreversibleAction")}</Alert>

                <p className="gryt-auth-prose">{msg("deletingImplies")}</p>
                <ul className="gryt-auth-consequences">
                    <li>{msg("loggingOutImmediately")}</li>
                    <li>{msg("errasingData")}</li>
                </ul>
                <p className="gryt-auth-prose">{msg("finalDeletionConfirmation")}</p>

                <form action={url.loginAction} method="post">
                    <div id="kc-form-buttons" className="gryt-auth-actions">
                        {triggered_from_aia && (
                            <Button type="submit" name="cancel-aia" value="true" size="large">
                                {msgStr("doCancel")}
                            </Button>
                        )}
                        <Button
                            id="kc-delete-account-confirm-submit"
                            type="submit"
                            size="large"
                            tone="neutral"
                        >
                            {msgStr("doConfirmDelete")}
                        </Button>
                    </div>
                </form>
            </div>
        </Template>
    );
}
