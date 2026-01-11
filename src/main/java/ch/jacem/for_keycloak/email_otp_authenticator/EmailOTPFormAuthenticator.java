package ch.jacem.for_keycloak.email_otp_authenticator;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.security.SecureRandom;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import ch.jacem.for_keycloak.email_otp_authenticator.authentication.authenticators.conditional.AcceptsFullContextInConfiguredFor;
import ch.jacem.for_keycloak.email_otp_authenticator.helpers.ConfigHelper;

import org.jboss.logging.Logger;

public class EmailOTPFormAuthenticator extends AbstractUsernameFormAuthenticator implements AcceptsFullContextInConfiguredFor
{
    public static final String AUTH_NOTE_OTP_KEY = "for-kc-email-otp-key";
    public static final String AUTH_NOTE_OTP_CREATED_AT = "for-kc-email-otp-created-at";
    public static final String AUTH_NOTE_REF_CODE = "for-kc-email-otp-ref-code";

    public static final String USER_ATTR_RATE_LIMIT_TIMESTAMPS = "email_otp_request_timestamps";

    public static final String AUTH_NOTE_INVALID_ATTEMPTS = "for-kc-email-otp-invalid-attempts";

    public static final String OTP_FORM_TEMPLATE_NAME = "login-email-otp.ftl";
    public static final String OTP_FORM_CODE_INPUT_NAME = "email-otp";
    public static final String OTP_FORM_RESEND_ACTION_NAME = "resend-email";

    public static final String OTP_EMAIL_TEMPLATE_NAME = "otp-email.ftl";
    public static final String OTP_EMAIL_SUBJECT_KEY = "emailOtpSubject";

    private static final Logger logger = Logger.getLogger(EmailOTPFormAuthenticator.class);

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();

        UserModel user = context.getUser();
        boolean userEnabled = this.enabledUser(context, user);
        // the brute force lock might be lifted/user enabled in the meantime -> we need to clear the auth session note
        if (userEnabled) {
            context.getAuthenticationSession().removeAuthNote(AbstractUsernameFormAuthenticator.SESSION_INVALID);
        }
        if("true".equals(context.getAuthenticationSession().getAuthNote(AbstractUsernameFormAuthenticator.SESSION_INVALID))) {
            context.getEvent().user(context.getUser()).error(Errors.INVALID_AUTHENTICATION_SESSION);
            // challenge already set by calling enabledUser() above
            return;
        }
        if (!userEnabled) {
            // error in context is set in enabledUser/isDisabledByBruteForce
            context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.SESSION_INVALID, "true");
            return;
        }

        if (inputData.containsKey(OTP_FORM_RESEND_ACTION_NAME)) {
            logger.debug("Resending a new OTP");

            // Check rate limit before resending
            if (this.isRateLimited(context)) {
                long waitSeconds = this.getWaitTimeSeconds(context);
                int waitMinutes = (int) (waitSeconds / 60);
                int waitSecondsRemainder = (int) (waitSeconds % 60);

                LoginFormsProvider form = context.form()
                    .setExecution(context.getExecution().getId())
                    .setAttribute("waitTimeMinutes", waitMinutes)
                    .setAttribute("waitTimeSeconds", waitSecondsRemainder);

                form.setError("emailOtpRateLimitExceeded", String.valueOf(waitMinutes), String.valueOf(waitSecondsRemainder));
                this.addRefCodeToForm(context, form);

                context.failureChallenge(
                    AuthenticationFlowError.INVALID_USER,
                    createLoginForm(form)
                );
                return;
            }

            // Regenerate and resend a new OTP
            this.generateOtp(context, true);

            // Reshow the form
            context.challenge(
                this.challenge(context, null)
            );

            return;
        }

        String otp = inputData.getFirst(OTP_FORM_CODE_INPUT_NAME);

        if (null == otp) {
            context.challenge(
                this.challenge(context, null)
            );

            return;
        }

        if (otp.isEmpty() || !otp.equals(authenticationSession.getAuthNote(AUTH_NOTE_OTP_KEY))) {
            int maxAttempts = ConfigHelper.getMaxInvalidAttempts(context);
            this.incrementInvalidAttempts(context);
            int currentAttempts = this.getInvalidAttempts(context);

            // Check if max attempts exceeded (only if feature is enabled)
            if (maxAttempts > 0 && currentAttempts >= maxAttempts) {
                logger.debug("Max invalid attempts reached, resetting flow");
                context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);

                // Clear all auth notes before resetting
                authenticationSession.removeAuthNote(AUTH_NOTE_OTP_KEY);
                authenticationSession.removeAuthNote(AUTH_NOTE_REF_CODE);
                authenticationSession.removeAuthNote(AUTH_NOTE_INVALID_ATTEMPTS);

                // Reset the entire flow - user must start over
                context.resetFlow();
                return;
            }

            // Show error with remaining attempts
            int remainingAttempts = maxAttempts > 0 ? (maxAttempts - currentAttempts) : -1;

            context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);

            LoginFormsProvider form = context.form()
                .setExecution(context.getExecution().getId());

            if (remainingAttempts > 0) {
                form.setAttribute("remainingAttempts", remainingAttempts);
                form.addError(new FormMessage(OTP_FORM_CODE_INPUT_NAME, "emailOtpInvalidCodeWithAttempts", String.valueOf(remainingAttempts)));
            } else {
                form.addError(new FormMessage(OTP_FORM_CODE_INPUT_NAME, "errorInvalidEmailOtp"));
            }

            this.addRefCodeToForm(context, form);

            context.failureChallenge(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                createLoginForm(form)
            );

            return;
        }

        // Check if the OTP is expired
        if (this.isOtpExpired(context)) {
            // In this case, we generate a new OTP
            this.generateOtp(context, true);

            context.getEvent().user(user).error(Errors.EXPIRED_CODE);
            context.failureChallenge(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                this.challenge(context, "errorExpiredEmailOtp", OTP_FORM_CODE_INPUT_NAME)
            );

            return;
        }

        // OTP is correct
        authenticationSession.removeAuthNote(AUTH_NOTE_OTP_KEY);
        authenticationSession.removeAuthNote(AUTH_NOTE_REF_CODE);
        this.clearInvalidAttempts(context);
        if (!authenticationSession.getAuthenticatedUser().isEmailVerified()) {
            authenticationSession.getAuthenticatedUser().setEmailVerified(true);
        }

        context.success();
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Check rate limit before generating OTP
        if (this.isRateLimited(context)) {
            long waitSeconds = this.getWaitTimeSeconds(context);
            int waitMinutes = (int) (waitSeconds / 60);
            int waitSecondsRemainder = (int) (waitSeconds % 60);

            LoginFormsProvider form = context.form()
                .setExecution(context.getExecution().getId())
                .setAttribute("waitTimeMinutes", waitMinutes)
                .setAttribute("waitTimeSeconds", waitSecondsRemainder);

            form.setError("emailOtpRateLimitExceeded", String.valueOf(waitMinutes), String.valueOf(waitSecondsRemainder));
            this.addRefCodeToForm(context, form);

            context.failureChallenge(
                AuthenticationFlowError.INVALID_USER,
                createLoginForm(form)
            );
            return;
        }

        this.generateOtp(context, false);

        context.challenge(
            this.challenge(context, null)
        );
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    protected String disabledByBruteForceFieldError() {
        return OTP_FORM_CODE_INPUT_NAME;
    }

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        return form.createForm(OTP_FORM_TEMPLATE_NAME);
    }

    @Override
    public boolean configuredFor(AuthenticationFlowContext context, AuthenticatorConfigModel config) {
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();

        if (null == user) {
            return false;
        }

        String configuredRole = ConfigHelper.getRole(config);
        if (null != configuredRole && !configuredRole.isEmpty()) {
            RoleModel role = realm.getRole(configuredRole);
            if (null != role && user.hasRole(role) == ConfigHelper.getNegateRole(config)) {
                return false;
            }
        }

        return null != user.getEmail() && !user.getEmail().isEmpty();
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return null != user.getEmail() && !user.getEmail().isEmpty();
    }

    @Override
    public boolean areRequiredActionsEnabled(KeycloakSession session, RealmModel realm) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
        return null;
    }

    @Override
    public void close() {
    }

    private String generateOtp(AuthenticationFlowContext context, boolean forceRegenerate) {
        // If the OTP is already set in the auth session and we are not forcing a regeneration, return it
        String existingOtp = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_OTP_KEY);
        if (!forceRegenerate && existingOtp != null && !existingOtp.isEmpty() && !this.isOtpExpired(context)) {
            return existingOtp;
        }

        String alphabet = ConfigHelper.getOtpCodeAlphabet(context);
        int length = ConfigHelper.getOtpCodeLength(context);

        // Generate a random `length` character string based on the `alphabet`
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder otpBuilder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            otpBuilder.append(alphabet.charAt(secureRandom.nextInt(alphabet.length())));
        }
        String otp = otpBuilder.toString();

        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_OTP_CREATED_AT, String.valueOf(System.currentTimeMillis() / 1000));
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_OTP_KEY, otp);

        // Generate and store reference code
        String refCode = this.generateRefCode(context);
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_REF_CODE, refCode);

        // Record this OTP request for rate limiting
        this.recordOtpRequest(context);

        this.sendGeneratedOtp(context);

        return otp;
    }

    private void sendGeneratedOtp(AuthenticationFlowContext context) {
        // If the OTP is not set in the auth session, fail
        String otp = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_OTP_KEY);
        if (null == otp || otp.isEmpty()) {
            logger.error("OTP is not set in the auth session.");

            context.getEvent().user(context.getUser()).error(Errors.INVALID_USER_CREDENTIALS);
            context.failureChallenge(
                AuthenticationFlowError.INTERNAL_ERROR,
                this.challenge(context, Messages.INTERNAL_SERVER_ERROR, null)
            );

            return;
        }

        UserModel user = context.getUser();
        String email = user.getEmail();

        if (email == null || email.isEmpty()) {
            logger.error("User does not have an email address configured.");

            context.getEvent().user(user).error(Errors.INVALID_EMAIL);
            context.failureChallenge(
                AuthenticationFlowError.INVALID_USER,
                this.challenge(context, Messages.INVALID_EMAIL, null)
            );

            return;
        }

        try {
            Map<String, Object> attributes = new HashMap<String, Object>();
            attributes.put("otp", otp);
            attributes.put("ttl", ConfigHelper.getOtpLifetime(context));

            String refCode = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_REF_CODE);
            attributes.put("refCode", refCode);

            context.getSession()
                .getProvider(EmailTemplateProvider.class)
                .setRealm(context.getRealm())
                .setUser(user)
                .send(
                    OTP_EMAIL_SUBJECT_KEY,
                    OTP_EMAIL_TEMPLATE_NAME,
                    attributes
                );

            logger.debug("OTP email sent to " + user.getUsername());
        } catch (Exception e) {
            logger.error("Failed to send OTP email", e);

            context.getEvent().user(user).error(Errors.EMAIL_SEND_FAILED);
            context.failureChallenge(
                AuthenticationFlowError.INTERNAL_ERROR,
                this.challenge(context, Messages.EMAIL_SENT_ERROR, null)
            );
        }
    }

    private boolean isOtpExpired(AuthenticationFlowContext context) {
        int lifetime = ConfigHelper.getOtpLifetime(context);
        long createdAt = Long.parseLong(context.getAuthenticationSession().getAuthNote(AUTH_NOTE_OTP_CREATED_AT));
        long now = System.currentTimeMillis() / 1000;

        return ((now - lifetime) > createdAt);
    }

    private String generateRefCode(AuthenticationFlowContext context) {
        // RefCode uses same alphabet as OTP for consistency
        String alphabet = EmailOTPFormAuthenticatorFactory.SETTINGS_DEFAULT_VALUE_CODE_ALPHABET;
        int length = ConfigHelper.getRefCodeLength(context);

        SecureRandom secureRandom = new SecureRandom();
        StringBuilder refCodeBuilder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            refCodeBuilder.append(alphabet.charAt(secureRandom.nextInt(alphabet.length())));
        }

        return refCodeBuilder.toString();
    }

    private void addRefCodeToForm(AuthenticationFlowContext context, LoginFormsProvider form) {
        String refCode = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_REF_CODE);
        if (refCode != null && !refCode.isEmpty()) {
            form.setAttribute("refCode", refCode);
        }
    }

    private boolean isRateLimited(AuthenticationFlowContext context) {
        int maxRequests = ConfigHelper.getRateLimitMaxRequests(context);

        // Rate limiting disabled if maxRequests is 0
        if (maxRequests <= 0) {
            return false;
        }

        int windowSeconds = ConfigHelper.getRateLimitWindowSeconds(context);
        UserModel user = context.getUser();

        List<Long> timestamps = getRequestTimestamps(user);
        long now = System.currentTimeMillis() / 1000;
        long windowStart = now - windowSeconds;

        // Count requests within window
        long requestsInWindow = timestamps.stream()
            .filter(ts -> ts > windowStart)
            .count();

        return requestsInWindow >= maxRequests;
    }

    private long getWaitTimeSeconds(AuthenticationFlowContext context) {
        int windowSeconds = ConfigHelper.getRateLimitWindowSeconds(context);
        UserModel user = context.getUser();

        List<Long> timestamps = getRequestTimestamps(user);
        long now = System.currentTimeMillis() / 1000;
        long windowStart = now - windowSeconds;

        // Find oldest timestamp in window
        long oldestInWindow = timestamps.stream()
            .filter(ts -> ts > windowStart)
            .min(Long::compare)
            .orElse(now);

        // Time until oldest timestamp expires from window
        return (oldestInWindow + windowSeconds) - now;
    }

    private List<Long> getRequestTimestamps(UserModel user) {
        List<String> values = user.getAttributeStream(USER_ATTR_RATE_LIMIT_TIMESTAMPS)
            .findFirst()
            .map(v -> Arrays.asList(v.split(",")))
            .orElse(new ArrayList<>());

        List<Long> timestamps = new ArrayList<>();
        for (String val : values) {
            if (!val.isEmpty()) {
                try {
                    timestamps.add(Long.parseLong(val.trim()));
                } catch (NumberFormatException e) {
                    // Skip invalid entries
                }
            }
        }
        return timestamps;
    }

    private void recordOtpRequest(AuthenticationFlowContext context) {
        int windowSeconds = ConfigHelper.getRateLimitWindowSeconds(context);
        UserModel user = context.getUser();

        List<Long> timestamps = getRequestTimestamps(user);
        long now = System.currentTimeMillis() / 1000;
        long windowStart = now - windowSeconds;

        // Clean up old timestamps and add new one
        List<Long> validTimestamps = new ArrayList<>();
        for (Long ts : timestamps) {
            if (ts > windowStart) {
                validTimestamps.add(ts);
            }
        }
        validTimestamps.add(now);

        // Convert to comma-separated string
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < validTimestamps.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(validTimestamps.get(i));
        }

        user.setSingleAttribute(USER_ATTR_RATE_LIMIT_TIMESTAMPS, sb.toString());
    }

    private int getInvalidAttempts(AuthenticationFlowContext context) {
        String attemptsStr = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_INVALID_ATTEMPTS);
        if (attemptsStr == null || attemptsStr.isEmpty()) {
            return 0;
        }
        try {
            return Integer.parseInt(attemptsStr);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private void incrementInvalidAttempts(AuthenticationFlowContext context) {
        int attempts = getInvalidAttempts(context) + 1;
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_INVALID_ATTEMPTS, String.valueOf(attempts));
    }

    private void clearInvalidAttempts(AuthenticationFlowContext context) {
        context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_INVALID_ATTEMPTS);
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        LoginFormsProvider form = context.form()
            .setExecution(context.getExecution().getId());

        if (error != null) {
            if (field != null) {
                form.addError(new FormMessage(field, error));
            } else {
                form.setError(error);
            }
        }

        // Add refCode to form
        this.addRefCodeToForm(context, form);

        return createLoginForm(form);
    }
}
