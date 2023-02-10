package kr.co.linkhub.auth;

/**
 * Linkhub Operation Exception.
 * @author KimSeongjun
 * @see http://www.linkhub.co.kr
 * @version 1.1.0
 */
public class LinkhubException extends Exception {
	private static final long serialVersionUID = 1L;

	private long code;
	
	public LinkhubException(long code , String Message) {
		super(Message);
		this.code = code;
	}
	
	public LinkhubException(long code , String Message, Throwable innerException) {
		super(Message,innerException);
		this.code = code;
	}
	
	/**
	 * Return Linkhub's result Error code. (ex. -11010009)
	 * In case of -99999999, check the getMessage() for detail.
	 * @return error code.
	 */
	public long getCode() {
		return code;
	}
	
}
