package cn.aotcloud.smcrypto.util;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.MessageFormat;
import java.util.Date;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

public class LoggerMinFormatter extends Formatter {

	Date dat = new Date();
	
	private final static String format = "{0,time,yyyy-MM-dd HH:mm:ss}";
	
	private MessageFormat formatter;

	private Object args[] = new Object[1];

	@SuppressWarnings({ "restriction" })
	private String lineSeparator = (String) java.security.AccessController.doPrivileged(new sun.security.action.GetPropertyAction("line.separator"));

	public synchronized String format(LogRecord record) {
		StringBuffer sb = new StringBuffer();
		dat.setTime(record.getMillis());
		args[0] = dat;
		StringBuffer text = new StringBuffer();
		if (formatter == null) {
			formatter = new MessageFormat(format);
		}
		formatter.format(args, text, null);
		sb.append(text);
		sb.append(" ");
		String message = formatMessage(record);
		sb.append(record.getLevel().getName());
		sb.append(": ");
		sb.append(message);
		sb.append(lineSeparator);
		if (record.getThrown() != null) {
			try {
				StringWriter sw = new StringWriter();
				PrintWriter pw = new PrintWriter(sw);
				record.getThrown().printStackTrace(pw);
				pw.close();
				sb.append(sw.toString());
			} catch (Exception ex) {
			}
		}
		return sb.toString();
	}
}