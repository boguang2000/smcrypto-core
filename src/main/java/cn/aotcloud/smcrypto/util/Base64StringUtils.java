package cn.aotcloud.smcrypto.util;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

public class Base64StringUtils {

    private static byte[] getBytes(final String string, final Charset charset) {
        if (string == null) {
            return null;
        }
        try {
			return string.getBytes(charset.name());
		} catch (UnsupportedEncodingException e) {
			return null;
		}
    }

    public static byte[] getBytesUtf8(final String string) {
        return getBytes(string, Charset.forName("UTF_8"));
    }

    private static String newString(final byte[] bytes, final Charset charset) {
    	if(bytes == null) {
    		return null;
    	} else {
    		try {
    			return new String(bytes, charset.name());
			} catch (UnsupportedEncodingException e) {
				return null;
			}
    	}
    }


    public static String newString(final byte[] bytes, final String charsetName) {
        if (bytes == null) {
            return null;
        }
        try {
            return new String(bytes, charsetName);
        } catch (final UnsupportedEncodingException e) {
            throw Base64StringUtils.newIllegalStateException(charsetName, e);
        }
    }

    public static String newStringUtf8(final byte[] bytes) {
        return newString(bytes, Charset.forName("UTF_8"));
    }
    
    private static IllegalStateException newIllegalStateException(final String charsetName,
            final UnsupportedEncodingException e) {
    	return new IllegalStateException(charsetName + ": " + e);
    }

}
