/**
 * Owned from @keycloakify/login-ui 250004.7.2. To restore the original:
 *   npx keycloakify own --path "login/pages/delete-account-confirm/Page.tsx" --revert
 *
 * Where deleting a Gryt account actually happens.
 *
 * Reachable since auth#17 turned the `delete_account` required action on. It is
 * an application-initiated action, so Gryt sends somebody here with
 * `kc_action=delete_account` and Keycloak sets `triggered_from_aia` — which is
 * the only reason the Cancel button below exists. Arrived at any other way,
 * there is nothing to cancel back to.
 *
 * The version this replaces was PatternFly markup with `#72767b` written into
 * the list and a Cancel button positioned by `calc(100% - 220px)`. The colour is
 * wrong against the Gryt shell, and that offset collapses on a narrow window.
 *
 * Cancel is the prominent button and deleting is the plain one. That is the
 * opposite of every other page in this theme, where the action somebody came for
 * gets the primary. Here the two mistakes do not cost the same.
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
