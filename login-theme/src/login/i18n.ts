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
            registerTitle: "Create your account",
            grytRegisterSub: "One account for every Gryt server.",
            grytPasswordHint: "Pick one you don't use anywhere else.",
            grytCreateAccount: "Create account",
            grytTermsBefore: "By creating an account you agree to the",
            grytTerms: "Terms",
            grytTermsAnd: "and the",
            grytPrivacy: "Privacy policy",
            grytHaveAccount: "Already have an account?",
            emailForgotTitle: "Reset your password",
            emailInstruction: "Enter your email and we'll send you a link to set a new one.",
            emailInstructionUsername: "Enter your email and we'll send you a link to set a new one.",
            grytSendResetLink: "Send reset link",
            backToLogin: "Back to sign in",
            updatePasswordTitle: "Set a new password",
            passwordConfirm: "Type it again",
            passwordNew: "New password",
            logoutOtherSessions: "Sign out of my other devices",
            grytSavePassword: "Save password",
        },
    })
    .build();

export { useI18n, I18nProvider };
