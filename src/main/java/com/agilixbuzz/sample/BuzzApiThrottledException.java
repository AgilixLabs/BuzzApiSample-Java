package com.agilixbuzz.sample;

import com.google.gson.JsonObject;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Thrown when the Buzz API throttles a request (rate limit, time limit, or backend
 * pressure) and the client has run out of retries, or when items within a batch or
 * multi-object request were throttled.
 *
 * <p>Extends {@link BuzzApiException} so existing handlers still catch it.
 * {@link #getStatusCode()} is 429 or 503 even when the server wrapped the throttle
 * in HTTP 200.</p>
 */
public class BuzzApiThrottledException extends BuzzApiException {

    private static final long serialVersionUID = 1L;

    private final String code;
    private final transient Duration retryAfter;
    private final transient JsonObject response;
    private final List<Integer> throttledItemIndexes;

    public BuzzApiThrottledException(String message, String code, JsonObject response,
                                     List<Integer> throttledItemIndexes, Duration retryAfter, int statusCode) {
        super(message, statusCode);
        this.code = code;
        this.response = response;
        this.throttledItemIndexes = Collections.unmodifiableList(new ArrayList<Integer>(throttledItemIndexes));
        this.retryAfter = retryAfter;
    }

    /**
     * The throttle code from the response envelope (for example "TimeLimit", "RateLimit",
     * "BackendPressure", or "TooManyRequests"), or the OAuth error code for the token
     * endpoint. Null if the server sent no code.
     */
    public String getCode() {
        return code;
    }

    /** How long the server asked the client to wait (Retry-After or X-RateLimit-Reset), or null if it did not say. */
    public Duration getRetryAfter() {
        return retryAfter;
    }

    /**
     * For batch and multi-object requests, the indexes of the items that were throttled
     * and should be resubmitted. Items not listed here completed normally (or failed for
     * other reasons) and should not be resubmitted. Empty when the whole request was throttled.
     */
    public List<Integer> getThrottledItemIndexes() {
        return throttledItemIndexes;
    }

    /** The full response envelope, including the results of any items that were not throttled. May be null. */
    public JsonObject getResponse() {
        return response;
    }
}
