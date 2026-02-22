<#-- Gryt email layout.
     Goals:
     - Keep layout/typography consistent with Gryt
     - Do NOT force background/text colors so the email client can apply light/dark mode
     - Use conservative HTML/CSS for broad email client support
-->
<#macro emailLayout>
<!doctype html>
<html lang="${locale.language}" dir="${(ltr)?then('ltr','rtl')}">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="color-scheme" content="light dark" />
    <meta name="supported-color-schemes" content="light dark" />
  </head>
  <body style="margin:0;padding:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;line-height:1.55;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
      <tr>
        <td align="center" style="padding:24px;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:separate;max-width:560px;">
            <tr>
              <td style="padding:4px 0 16px 0;font-weight:800;letter-spacing:-0.02em;font-size:18px;">
                Gryt
              </td>
            </tr>
            <tr>
              <td style="padding:18px 16px;border-radius:16px;border:1px solid rgba(127,127,127,0.28);">
                <#nested>
              </td>
            </tr>
            <tr>
              <td style="padding:14px 0 0 0;font-size:12px;opacity:0.78;">
                If you didn’t request this, you can ignore this email.
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
</#macro>

