package com.agilixbuzz.sample;

/**
 * Thrown when a Buzz API call fails or returns a non-OK response code.
 */
public class BuzzApiException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final int statusCode;

    public BuzzApiException(String message) {
        this(message, 0, null);
    }

    public BuzzApiException(String message, Throwable cause) {
        this(message, 0, cause);
    }

    public BuzzApiException(String message, int statusCode) {
        this(message, statusCode, null);
    }

    public BuzzApiException(String message, int statusCode, Throwable cause) {
        super(message, cause);
        this.statusCode = statusCode;
    }

    /**
     * The HTTP status that caused the failure, or 0 if the failure was not an HTTP
     * error status (for example a network error, or a non-OK code in an HTTP 200 envelope).
     */
    public int getStatusCode() {
        return statusCode;
    }
}
