/**
 * Lint for gryt.css, the only hand-written stylesheet in the theme.
 *
 * ## Why this exists
 *
 * On 2026-09-01 a rule went in without its closing brace:
 *
 *   .gryt-auth-consequences li::marker {
 *     color: var(--gryt-danger, currentColor);
 *   <- missing
 *
 * The 245 lines after it became nested rules inside a `::marker`, which
 * nothing can match, so the bundler dropped all of them. No error, no warning,
 * a build that exits 0. What went missing was the recovery-code and QR pages,
 * the password reveal button, and the background canvas — and losing the
 * canvas's `width: 100%` let it size itself from its own width attribute,
 * which the resize handler multiplies by devicePixelRatio, so on a 2x display
 * the login page grew to 2,458,155px tall and the form was pushed off screen.
 * It shipped and was live for about five hours.
 *
 * ## Why almost no rules
 *
 * The catch above needs no rules at all — stylelint reports a CssSyntaxError
 * whatever the config says, and it named line 598 exactly. The rules listed
 * here are the ones that find mistakes rather than opinions, and every one of
 * them passes on the file as it stands, so this can go in without touching a
 * line of the existing 843. Nothing about ordering, naming, quotes or
 * shorthand: this file was written by hand and reads fine, and a lint that
 * argues with it is a lint that gets disabled.
 *
 * Only `src` is linted. Everything under `public/` is vendored by
 * keycloakify's postinstall — PatternFly and Keycloak's own stylesheets — and
 * is not ours to fix.
 */
export default {
  rules: {
    "block-no-empty": true,
    "comment-no-empty": true,
    "declaration-block-no-duplicate-properties": [
      true,
      // A fallback followed by the real value is the point, not a mistake.
      { ignore: ["consecutive-duplicates-with-different-syntaxes"] }
    ],
    "declaration-block-no-shorthand-property-overrides": true,
    "function-no-unknown": true,
    "keyframe-block-no-duplicate-selectors": true,
    "media-feature-name-no-unknown": true,
    "named-grid-areas-no-invalid": true,
    "no-duplicate-at-import-rules": true,
    // `// like this` is not a CSS comment. It swallows the declaration after it.
    "no-invalid-double-slash-comments": true,
    "no-invalid-position-at-import-rule": true,
    "property-no-unknown": true,
    "selector-pseudo-class-no-unknown": true,
    "selector-pseudo-element-no-unknown": true,
    "string-no-newline": true,
    "unit-no-unknown": true
  }
};
