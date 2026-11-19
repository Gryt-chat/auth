<#ftl output_format="plainText">
Someone, hopefully you, wants to sign in with ${identityProviderDisplayName} to the Gryt account for ${identityProviderContext.username}.

To link ${identityProviderDisplayName}, open this link:
${link}

This link expires in ${linkExpirationFormatter(linkExpiration)}.

If this wasn’t you, ignore this email.
