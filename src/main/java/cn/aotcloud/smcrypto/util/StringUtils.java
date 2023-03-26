package cn.aotcloud.smcrypto.util;

public class StringUtils {

	public static final String SPACE = " ";

	public static final String EMPTY = "";

	public static final int INDEX_NOT_FOUND = -1;

	public StringUtils() {
		super();
	}

	public static boolean isEmpty(final CharSequence cs) {
		return cs == null || cs.length() == 0;
	}

	public static boolean isEmpty(final CharSequence[] array) {
		return array == null || array.length == 0;
	}

	public static boolean isEmpty(final char[] array) {
		return array == null || array.length == 0;
	}

	public static boolean isNotEmpty(final CharSequence cs) {
		return !StringUtils.isEmpty(cs);
	}

	public static boolean isAnyEmpty(CharSequence... css) {
		if (isEmpty(css)) {
			return true;
		}
		for (CharSequence cs : css) {
			if (isEmpty(cs)) {
				return true;
			}
		}
		return false;
	}

	public static boolean isNoneEmpty(CharSequence... css) {
		return !isAnyEmpty(css);
	}

	public static boolean isBlank(final CharSequence cs) {
		int strLen;
		if (cs == null || (strLen = cs.length()) == 0) {
			return true;
		}
		for (int i = 0; i < strLen; i++) {
			if (Character.isWhitespace(cs.charAt(i)) == false) {
				return false;
			}
		}
		return true;
	}

	public static boolean isNotBlank(final CharSequence cs) {
		return !StringUtils.isBlank(cs);
	}

	public static boolean isAnyBlank(CharSequence... css) {
		if (isEmpty(css)) {
			return true;
		}
		for (CharSequence cs : css) {
			if (isBlank(cs)) {
				return true;
			}
		}
		return false;
	}

	public static boolean isNoneBlank(CharSequence... css) {
		return !isAnyBlank(css);
	}

	public static String trim(final String str) {
		return str == null ? null : str.trim();
	}

	public static String trimToNull(final String str) {
		final String ts = trim(str);
		return isEmpty(ts) ? null : ts;
	}

	public static String trimToEmpty(final String str) {
		return str == null ? EMPTY : str.trim();
	}

	public static boolean equals(final CharSequence cs1, final CharSequence cs2) {
		if (cs1 == cs2) {
			return true;
		}
		if (cs1 == null || cs2 == null) {
			return false;
		}
		if (cs1 instanceof String && cs2 instanceof String) {
			return cs1.toString().equals(cs2.toString());
		}
		return regionMatches(cs1, false, 0, cs2, 0,
				Math.max(cs1.length(), cs2.length()));
	}

	public static boolean equalsIgnoreCase(final CharSequence str1,
			final CharSequence str2) {
		if (str1 == null || str2 == null) {
			return str1 == str2;
		} else if (str1 == str2) {
			return true;
		} else if (str1.length() != str2.length()) {
			return false;
		} else {
			return regionMatches(str1, true, 0, str2, 0, str1.length());
		}
	}

	public static int length(final CharSequence cs1) {
		return cs1 == null ? 0 : cs1.length();
	}
	
	private static boolean regionMatches(final CharSequence cs,
			final boolean ignoreCase, final int thisStart,
			final CharSequence substring, final int start, final int length) {
		if (cs instanceof String && substring instanceof String) {
			return ((String) cs).regionMatches(ignoreCase, thisStart,
					(String) substring, start, length);
		} else {
			int index1 = thisStart;
			int index2 = start;
			int tmpLen = length;

			while (tmpLen-- > 0) {
				char c1 = cs.charAt(index1++);
				char c2 = substring.charAt(index2++);

				if (c1 == c2) {
					continue;
				}
				if (!ignoreCase) {
					return false;
				}
				// The same check as in String.regionMatches():
				if (Character.toUpperCase(c1) != Character.toUpperCase(c2)
						&& Character.toLowerCase(c1) != Character.toLowerCase(c2)) {
					return false;
				}
			}
			return true;
		}
	}

}
