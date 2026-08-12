/**
 * Owned from @keycloakify/login-ui 250004.7.2. To restore the original:
 *   npx keycloakify own --path "login/pages/error/Page.tsx" --revert
 *
 * Where every flow ends when it goes wrong, so it is worth more than a
 * paragraph and a link that looks like body text.
 *
 * The message is Keycloak's and stays sanitised HTML — it can carry markup, and
 * kcSanitize is what makes that safe. The way back becomes a real button,
 * because it is the only thing on the page and leaving somebody at a dead end is
 * the actual failure here.
 */

import { Button } from "@gryt/ui";
import { kcSanitize } from "@keycloakify/login-ui/kcSanitize";
import { assert } from "tsafe/assert";
import { useKcContext } from "../../KcContext";
import { useI18n } from "../../i18n";
import { Template } from "../../components/Template";

export function Page() {
    const { kcContext } = useKcContext();
    assert(kcContext.pageId === "error.ftl");

    const { msg, msgStr } = useI18n();
    const backUrl = kcContext.client?.baseUrl;

    return (
        <Template displayMessage={false} headerNode={msgStr("errorTitle")}>
            <div id="kc-error-message" className="gryt-auth-form">
                <p
                    className="gryt-auth-prose"
                    dangerouslySetInnerHTML={{ __html: kcSanitize(kcContext.message.summary) }}
                />

                {!kcContext.skipLink && !!backUrl && (
                    <div className="gryt-auth-actions">
                        <Button
                            render={<a id="backToApplication" href={backUrl} />}
                            tone="neutral"
                            size="large"
                        >
                            {msg("backToApplication")}
                        </Button>
                    </div>
                )}
            </div>
        </Template>
    );
}
