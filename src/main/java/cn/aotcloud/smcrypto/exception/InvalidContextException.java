package cn.aotcloud.smcrypto.exception;

public class InvalidContextException extends Exception {

	private static final long serialVersionUID = 1L;
	
    public InvalidContextException(String message) {
        super(message);
    }

    public InvalidContextException(String message, Throwable cause) {
        super(message, cause);
    }
}
