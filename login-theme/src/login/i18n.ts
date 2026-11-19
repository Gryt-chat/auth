/**
 * Owned from @keycloakify/login-ui 250004.7.2 — `npx keycloakify own --path <this file>
 * --revert` restores it. English copy follows the Gryt draft; other languages keep Keycloak's.
 */

import { i18nBuilder } from "@keycloakify/login-ui/i18n";
import type { ThemeName } from "../kc.gen";

const { I18nProvider, useI18n } = i18nBuilder
    .withThemeName<ThemeName>()
    .withCustomTranslations({
        en: {
            doLogIn: "Sign in",
            doForgotPassword: "Forgot password?",
            doTryAnotherWay: "Try another way",
            noAccount: "New to Gryt?",
            doRegister: "Create an account",
            showPassword: "Show password",
            hidePassword: "Hide password",
            grytShow: "Show",
            grytHide: "Hide",
            grytOr: "or",
        },
    })
    .build();

export { useI18n, I18nProvider };
