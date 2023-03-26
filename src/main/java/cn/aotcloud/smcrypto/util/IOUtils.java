package cn.aotcloud.smcrypto.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

public class IOUtils {
	
	private static final Logger logger = LoggerFactory.getLogger(IOUtils.class.getName());

    public static List<String> readLines(InputStream input) throws IOException {
        InputStreamReader reader = new InputStreamReader(input);
        return readLines(reader);
    }

    public static List<String> readLines(InputStream input, String encoding) throws IOException {
        if (encoding == null) {
            return readLines(input);
        } else {
            InputStreamReader reader = new InputStreamReader(input, encoding);
            return readLines(reader);
        }
    }

    public static List<String> readLines(Reader input) throws IOException {
        BufferedReader reader = toBufferedReader(input);
        List<String> list = new ArrayList<String>();
        String line = reader.readLine();
        while (line != null) {
            list.add(line);
            line = reader.readLine();
        }
        return list;
    }
    
    public static BufferedReader toBufferedReader(Reader reader) {
        return reader instanceof BufferedReader ? (BufferedReader) reader : new BufferedReader(reader);
    }
    
	public static void closeQuietly(InputStream inputStream) {
		if (inputStream != null){
            try {
            	inputStream.close();
            } catch (IOException ioe) {
            	logger.warning("IO Close Exception");
            }
        }
	}
	
	public static void closeQuietly(OutputStream outputStream) {
		if (outputStream != null){
            try {
            	outputStream.close();
            } catch (IOException ioe) {
            	logger.warning("IO Close Exception");
            }
        }
	}
	
}
