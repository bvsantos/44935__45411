package Exceptions;

public class AlrdyGotMessageException extends Exception {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public AlrdyGotMessageException(){
        super("Repeated Message");
	}
}
