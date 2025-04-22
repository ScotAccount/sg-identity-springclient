package scot.gov.scotaccountclient;

/**
 * Exception thrown when there is an error fetching attributes from the API.
 */
public class AttributeFetchException extends RuntimeException {
    public AttributeFetchException(String message) {
        super(message);
    }

    public AttributeFetchException(String message, Throwable cause) {
        super(message, cause);
    }
}