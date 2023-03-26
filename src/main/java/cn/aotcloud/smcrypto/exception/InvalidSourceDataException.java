package cn.aotcloud.smcrypto.exception;

public class InvalidSourceDataException extends Exception {

	private static final long serialVersionUID = 1L;
	
    public InvalidSourceDataException(String message) {
        super(message);
    }

    public InvalidSourceDataException(String message, Throwable cause) {
        super(message, cause);
    }
}
