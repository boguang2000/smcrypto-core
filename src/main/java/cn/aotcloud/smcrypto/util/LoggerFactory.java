package cn.aotcloud.smcrypto.util;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * JDK自带的Log的工具类
 */
public class LoggerFactory {

	// 正常的日期格式
	public static final String DATE_PATTERN_FULL = "yyyy-MM-dd HH:mm:ss";
	
	/**
	 * 初始化全局Logger
	 * 
	 * @return
	 */
	public static Logger getLogger(Class<?> class_) {
		return getLogger(class_.getName());
	}
	
	/**
	 * 初始化全局Logger
	 * 
	 * @return
	 */
	public static Logger getLogger(String log_name) {
		// 获取Log
		Logger log = Logger.getLogger(log_name);
		// 为log设置全局等级
		log.setLevel(Level.ALL);
		// 添加控制台handler
		addConsoleHandler(log, Level.ALL);
		// 设置不适用父类的handlers，这样不会在控制台重复输出信息
		log.setUseParentHandlers(false);

		return log;
	}

	/**
	 * 为log添加控制台handler
	 * 
	 * @param log	要添加handler的log
	 * @param level	控制台的输出等级
	 */
	public static void addConsoleHandler(Logger log, Level level) {
		// 控制台输出的handler
		ConsoleHandler consoleHandler = new ConsoleHandler();
		// 设置控制台输出的等级（如果ConsoleHandler的等级高于或者等于log的level，则按照FileHandler的level输出到控制台，如果低于，则按照Log等级输出）
		consoleHandler.setLevel(level);
		//consoleHandler.setFormatter(new java.util.logging.SimpleFormatter());
		consoleHandler.setFormatter(new LoggerMinFormatter());
		// 添加控制台的handler
		log.addHandler(consoleHandler);
	}

	/**
	 * 获取当前时间
	 * 
	 * @return
	 */
	public static String getCurrentDateStr(String pattern) {
		Date date = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat(pattern);
		return sdf.format(date);
	}
}
