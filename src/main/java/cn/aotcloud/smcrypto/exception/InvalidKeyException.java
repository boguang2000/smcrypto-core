package cn.aotcloud.smcrypto.exception;

public class InvalidKeyException extends Exception {

	private static final long serialVersionUID = 1L;
	
    public InvalidKeyException(String message) {
        super(message);
    }

    public InvalidKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
