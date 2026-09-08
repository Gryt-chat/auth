/**
 * Lint for gryt.css. A rule missing its closing brace nested 245 lines inside a `::marker`,
 * the bundler dropped them, and the sign-in page was 2.4M pixels tall for five hours.
 */

/*
 * Almost no rules on purpose: the catch above is a CssSyntaxError whatever the config says.
 * Only `src` is linted — `public/` is vendored by keycloakify and not ours to fix.
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
