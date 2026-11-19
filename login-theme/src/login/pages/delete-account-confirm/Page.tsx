/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. Cancel is prominent and deleting plain: the costs differ.
 */

import { WarningIcon } from "@phosphor-icons/react";
import { Button } from "@gryt/ui";
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
        <Template
            headerNode={msg("deleteAccountConfirm")}
            subtitleNode={msg("grytDeleteSub")}
            iconTone="danger"
            iconNode={<WarningIcon size={24} weight="fill" />}
        >
            <form id="kc-delete-account-confirm" action={url.loginAction} method="post">
                <div id="kc-form-buttons" className="gryt-auth-actions">
                    <Button
                        id="kc-delete-account-confirm-submit"
                        type="submit"
                        size="large"
                        tone="danger"
                    >
                        {msgStr("doConfirmDelete")}
                    </Button>
                    {triggered_from_aia && (
                        <Button type="submit" name="cancel-aia" value="true" tone="ghost" size="large" className="gryt-auth-quiet">
                            {msgStr("grytKeepAccount")}
                        </Button>
                    )}
                </div>
            </form>
        </Template>
    );
}
