<#ftl output_format="plainText">
<#if refCode??>
${kcSanitize(msg("emailOtpRefCodeLabel"))} ${refCode}

</#if>
${kcSanitize(msg("emailOtpYourAccessCode"))}

${otp}

${kcSanitize(msg("emailOtpExpiration", (ttl / 60)?int))}
