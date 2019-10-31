package Exceptions;

public class SesssionMetaDataException extends Exception{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	public SesssionMetaDataException() {
		super("Missmatching meta data");
	}

}
