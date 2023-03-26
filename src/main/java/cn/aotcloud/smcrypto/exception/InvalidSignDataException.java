package cn.aotcloud.smcrypto.exception;

public class InvalidSignDataException extends Exception {

	private static final long serialVersionUID = 1L;

	public InvalidSignDataException(String message) {
        super(message);
    }

    public InvalidSignDataException(String message, Throwable cause) {
        super(message, cause);
    }
}
