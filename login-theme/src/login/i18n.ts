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
            emailVerifyTitle: "Check your inbox",
            emailVerifyInstruction1: "We sent a link to <b>{0}</b>. Open it to finish setting up your account.",
            grytResendEmail: "Resend email",
            grytMailHint: "It can take a minute. Check your spam folder too.",
            backToApplication: "Back to Gryt",
            pageExpiredTitle: "This page timed out",
            grytExpiredMsg: "Sign-in pages expire after a while to keep your account safe. Start again and it'll work.",
            grytStartAgain: "Start again",
            errorTitle: "Something went wrong",
            "webauthn-login-title": "Use your passkey",
            grytPasskeySub: "Your browser will ask you to confirm with Face ID, Touch ID, Windows Hello or a security key.",
            "webauthn-doAuthenticate": "Continue with passkey",
            "webauthn-registration-title": "Create a passkey",
            grytPasskeyRegisterSub: "Sign in with Face ID, Touch ID, Windows Hello or a security key instead of typing a password. The passkey stays on your device.",
            doRegisterSecurityKey: "Create passkey",
            grytNotNow: "Not now",
            "webauthn-error-title": "That didn't go through",
            grytPasskeyErrorSub: "This happens if you close the prompt or wait too long. Your account is fine.",
            deleteAccountConfirm: "Delete your Gryt account?",
            grytDeleteSub: "This removes your account and your sign-in. You can't undo it.",
            doConfirmDelete: "Delete my account",
            grytKeepAccount: "Keep my account",
        },
    })
    .build();

export { useI18n, I18nProvider };
