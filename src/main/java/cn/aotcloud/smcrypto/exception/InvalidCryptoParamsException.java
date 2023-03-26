package cn.aotcloud.smcrypto.exception;

public class InvalidCryptoParamsException extends RuntimeException {

	private static final long serialVersionUID = 1L;
	
    public InvalidCryptoParamsException(String message) {
        super(message);
    }

    public InvalidCryptoParamsException(String message, Throwable cause) {
        super(message, cause);
    }
}
