package com.agilixbuzz.sample;

/**
 * Thrown when Buzz refuses a request because it used something deprecated
 * (response code "ApiDeprecated", or "unauthorized_client" from the OAuth token
 * endpoint).
 *
 * <p>Deprecated commands, the {@code api.agilixbuzz.com} endpoint and password
 * (Login3) sessions for integration work keep working for existing users and
 * domains, but are refused for new ones. The message is the server's own and
 * says what to use instead. <strong>Never retry</strong>: the request is refused
 * until the code is changed.</p>
 *
 * <p>Extends {@link BuzzApiException} so existing handlers still catch it.</p>
 */
public class BuzzApiDeprecatedException extends BuzzApiException {

    private static final long serialVersionUID = 1L;

    public BuzzApiDeprecatedException(String message) {
        super(message);
    }

    public BuzzApiDeprecatedException(String message, int statusCode) {
        super(message, statusCode);
    }
}
