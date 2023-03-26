package cn.aotcloud.smcrypto.exception;

public class InvalidIvException extends Exception {

	private static final long serialVersionUID = 1L;
	
    public InvalidIvException(String message) {
        super(message);
    }

    public InvalidIvException(String message, Throwable cause) {
        super(message, cause);
    }
}
