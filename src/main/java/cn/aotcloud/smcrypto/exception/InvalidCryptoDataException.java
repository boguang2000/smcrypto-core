package cn.aotcloud.smcrypto.exception;

public class InvalidCryptoDataException extends Exception {

	private static final long serialVersionUID = 1L;
	
    public InvalidCryptoDataException(String message) {
        super(message);
    }

    public InvalidCryptoDataException(String message, Throwable cause) {
        super(message, cause);
    }
}
