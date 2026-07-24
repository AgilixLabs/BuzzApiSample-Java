package com.agilixbuzz.sample;

/**
 * Thrown when a Buzz API call fails or returns a non-OK response code.
 */
public class BuzzApiException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public BuzzApiException(String message) {
        super(message);
    }

    public BuzzApiException(String message, Throwable cause) {
        super(message, cause);
    }
}
