/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. The link order is the original's: pageRedirectUri, then actionUri.
 */

import { Button } from "@gryt/ui";
import { kcSanitize } from "@keycloakify/login-ui/kcSanitize";
import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "info.ftl");

    const { advancedMsgStr, msg } = useI18n();

    const onward = kcContext.skipLink
        ? null
        : kcContext.pageRedirectUri
          ? { href: kcContext.pageRedirectUri, label: msg("backToApplication") }
          : kcContext.actionUri
            ? { href: kcContext.actionUri, label: msg("proceedWithAction") }
            : kcContext.client.baseUrl
              ? { href: kcContext.client.baseUrl, label: msg("backToApplication") }
              : null;

    return (
        <Template
            displayMessage={false}
            headerNode={
                <span
                    dangerouslySetInnerHTML={{
                        __html: kcSanitize(
                            kcContext.messageHeader
                                ? advancedMsgStr(kcContext.messageHeader)
                                : kcContext.message.summary
                        )
                    }}
                />
            }
        >
            <div id="kc-info-message" className="gryt-auth-form">
                <p
                    className="gryt-auth-prose"
                    dangerouslySetInnerHTML={{
                        __html: kcSanitize(
                            (() => {
                                let html = kcContext.message.summary?.trim();

                                if (kcContext.requiredActions) {
                                    html += " <b>";
                                    html += kcContext.requiredActions
                                        .map(requiredAction =>
                                            advancedMsgStr(`requiredAction.${requiredAction}`)
                                        )
                                        .join(", ");
                                    html += "</b>";
                                }

                                return html;
                            })()
                        )
                    }}
                />

                {onward !== null && (
                    <div className="gryt-auth-actions">
                        <Button render={<a href={onward.href} />} tone="neutral" size="large">
                            {onward.label}
                        </Button>
                    </div>
                )}
            </div>
        </Template>
    );
}
