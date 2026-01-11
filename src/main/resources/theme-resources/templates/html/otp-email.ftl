<#import "template.ftl" as layout>
<@layout.emailLayout>
<#if refCode??>
<p>${kcSanitize(msg("emailOtpRefCodeLabel"))?no_esc} <strong style="font-family: monospace; font-size: 1.2em; letter-spacing: 0.1em;">${refCode?no_esc}</strong></p>
</#if>
<p>${kcSanitize(msg("emailOtpYourAccessCode"))?no_esc}</p>
<h1>${otp?no_esc}</h1>
<p>${kcSanitize(msg("emailOtpExpiration", (ttl / 60)?int))?no_esc}</p>
</@layout.emailLayout>
