<#import "template.ftl" as layout>
<@layout.emailLayout>
  <h2 style="margin:0 0 10px 0;font-size:20px;letter-spacing:-0.02em;line-height:1.25;">
    Verify your email
  </h2>
  <p style="margin:0 0 14px 0;">
    Confirm this email address to finish creating your <strong>${realmName}</strong> account.
  </p>

  <div style="margin:18px 0 14px 0;">
    <a href="${link}" style="display:inline-block;padding:12px 16px;border-radius:12px;border:1px solid rgba(127,127,127,0.42);text-decoration:none;font-weight:800;">
      Verify email
    </a>
  </div>

  <p style="margin:0 0 10px 0;font-size:13px;opacity:0.85;">
    This link expires in ${linkExpirationFormatter(linkExpiration)}.
  </p>

  <p style="margin:0;font-size:12px;opacity:0.78;">
    If the button doesn’t work, copy and paste this link into your browser:
    <br />
    <a href="${link}" style="word-break:break-all;">${link}</a>
  </p>
</@layout.emailLayout>

