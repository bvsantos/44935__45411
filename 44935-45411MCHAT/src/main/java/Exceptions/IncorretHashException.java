package Exceptions;

public class IncorretHashException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public IncorretHashException() {
        super("Failed FastSecurePayloadCheck");
	}
}
