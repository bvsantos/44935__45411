import keystore.GenerateKeys;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Properties;
import java.util.stream.Collectors;

public class Hashing {

    private byte[] IV;
    public Hashing hasher;
    public Properties props;
    public Key sessionKey,macKey;
    public String host,aux;
    Cipher cipher;
    Mac hMac;
    int port;
    public Hashing(int port, Properties props, String hostAddress, String aux) throws CertificateException, UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        this.port = port;
        this.props = props;
        this.host=hostAddress;
        this.aux=aux;
        System.out.println(props.getProperty("SEA")+"/"+props.getProperty("MODE")+"/"+props.getProperty("PADDING"));
        this.sessionKey = GenerateKeys.loadKey(aux+"sessionkey");
        this.macKey = GenerateKeys.loadKey(aux+"mackm");
        this.sessionKey = new SecretKeySpec(this.sessionKey.getEncoded(),props.getProperty("SEA"));
        this.macKey = new SecretKeySpec(this.sessionKey.getEncoded(),props.getProperty("MAC"));
        if(props.getProperty("MODE").equals("NoPadding"));
        	cipher = Cipher.getInstance(props.getProperty("SEA")+"/"+props.getProperty("MODE")+"/"+props.getProperty("PADDING"),"BC");
        hMac = Mac.getInstance(props.getProperty("MAC"));
        hMac.init(this.macKey);
    }
    
    public byte[] encript(byte[] data,String userName) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
    	byte[] securePayload = encriptSecurePayload(data, userName);
    	
    	byte[] sAttributes = computeSAttributes(
    			new ArrayList<byte[]>() {
    	    		/**
					 * 
					 */
					private static final long serialVersionUID = 19159113244506189L;

					{
    	    			add(props.getProperty("SID").getBytes());
    	    			add(((String)(host+":"+port)).getBytes());
    	    			add(props.getProperty("SEA").getBytes());
    	    			add(props.getProperty("MODE").getBytes());
    	    			add(props.getProperty("PADDING").getBytes());
    	    			add(props.getProperty("INTHASH").getBytes());
    	    			add(props.getProperty("MAC").getBytes());
    	    			
    	    		}
    			},
    	    		props.getProperty("SID").getBytes().length+((String)(host+":"+port)).getBytes().length+props.getProperty("SEA").getBytes().length+props.getProperty("MODE").getBytes().length+props.getProperty("PADDING").getBytes().length+props.getProperty("INTHASH").getBytes().length+props.getProperty("MAC").getBytes().length
    	);
    	
    	byte[] sAttributesEncoded = sha256Encoder(sAttributes);
    	
    	byte[] finalMessage = computeSAttributes(
    			new ArrayList<byte[]>() {
    	    		/**
					 * 
					 */
					private static final long serialVersionUID = 8672594177872022946L;

					{
    	    			add(ByteBuffer.allocate( 1 ).put((byte)0).array());
    	    			add(props.getProperty("SEA").getBytes());
    	    			add(ByteBuffer.allocate( 1 ).put((byte) 0x01).array());
    	    			add(sAttributesEncoded);
    	    			add(ByteBuffer.allocate( Integer.BYTES ).putInt(securePayload.length).array());
    	    			add(securePayload);
    	    			
    	    		}
    			},
    	    		1+props.getProperty("SEA").getBytes().length+1+sAttributesEncoded.length+Integer.BYTES+securePayload.length
    			);
    	
    	hMac.update(finalMessage);
    	
    	
    	byte[] returnValue = computeSAttributes(
    			new ArrayList<byte[]>() {
					/**
					 * 
					 */
					private static final long serialVersionUID = 4680585511287574721L;

					{
						add(ByteBuffer.allocate( Integer.BYTES ).putInt(finalMessage.length).array());
						add(ByteBuffer.allocate( Integer.BYTES ).putInt(props.getProperty("SEA").getBytes().length).array());
						add(ByteBuffer.allocate( Integer.BYTES ).putInt(sAttributesEncoded.length).array());
    	    			add(finalMessage);
    	    			add(hMac.doFinal());
    	    			
    	    		}
    			},
    			hMac.getMacLength()+finalMessage.length+3*Integer.BYTES
    			);
    	
		return returnValue;
    }
    
    public byte[] decript(byte[] data) throws BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {
    	int offset = 0;
    	int packageLength = new BigInteger(Arrays.copyOfRange(data, offset, Integer.BYTES)).intValue();
    	offset+=Integer.BYTES;
		int seaLength = new BigInteger(Arrays.copyOfRange(data, offset, offset+Integer.BYTES)).intValue();
		offset+=Integer.BYTES;
		int shaLength = new BigInteger(Arrays.copyOfRange(data, offset, offset+Integer.BYTES)).intValue();
		offset+=Integer.BYTES;
		byte[] encodedMessage = Arrays.copyOfRange(data, offset,packageLength+offset);
		//byte[] encodedMessage = Arrays.copyOfRange(data, offset,hMac.getMacLength());
//		hMac.update(encodedMessage);

		byte vID = encodedMessage[0];
		offset = 1;
		String sID = new String(Arrays.copyOfRange(encodedMessage, offset, offset+seaLength));
		offset += seaLength;
		byte SMCPmsgType = encodedMessage[offset];
		offset++;
		byte[] sha = Arrays.copyOfRange(encodedMessage, offset, offset+shaLength);
		offset+=shaLength;
		int payLoadSize = new BigInteger(Arrays.copyOfRange(encodedMessage, offset, offset+Integer.BYTES)).intValue();
		offset += Integer.BYTES;
		byte[] encodedPayload = Arrays.copyOfRange(encodedMessage, offset, offset+payLoadSize);

    	return decryptSecurePayload(encodedPayload);
	}

    public byte[] sha256Encoder(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(this.props.getProperty("INTHASH"));
        return digest.digest(data);
    }

    public byte[] encriptSecurePayload(byte[] data, String username) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        if(props.getProperty("PADDING").equals("NoPadding"))
        	cipher = Cipher.getInstance(props.getProperty("SEA")+"/"+props.getProperty("MODE")+"/"+props.getProperty("PADDING"),"BC");
        else
        	cipher = Cipher.getInstance(props.getProperty("SEA")+"/"+props.getProperty("MODE")+"/"+props.getProperty("PADDING"));
        	
        byte[] encoded = sha256Encoder(data);
//		TODO: Este é o long que tem de ser incrementado o objectivo nao é ser um random long
        SecureRandom s = new SecureRandom();
        byte[] secured = computeSAttributes(
    			new ArrayList<byte[]>() {
    	    		/**
					 * 
					 */
					private static final long serialVersionUID = -7906419280715964605L;

					{
    	    			add(ByteBuffer.allocate( Integer.BYTES ).putInt(username.getBytes().length).array());
    	    			add(ByteBuffer.allocate( Integer.BYTES ).putInt(data.length).array());
    	    			add(username.getBytes());
    	    			add(ByteBuffer.allocate( Long.BYTES ).putLong(s.nextLong()).array());
    	    			add(data);
    	    			add(encoded);
    	    			
    	    		}
    			},
    			Integer.BYTES*2+username.getBytes().length+ Long.BYTES+data.length+encoded.length
        		);

        cipher.init(Cipher.ENCRYPT_MODE, this.sessionKey);

        byte[] cipherText = new byte[cipher.getOutputSize(secured.length + hMac.getMacLength())];

        int ctLength = cipher.update(secured, 0, secured.length, cipherText, 0);

        hMac.update(secured);

        ctLength += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), cipherText, ctLength);

        IV = cipher.getIV();
        
        byte[] retValue = computeSAttributes(
    			new ArrayList<byte[]>() {

					/**
					 * 
					 */
					private static final long serialVersionUID = -967209232836137478L;

					{
    	    			add(ByteBuffer.allocate( Integer.BYTES ).putInt(Integer.BYTES+cipherText.length+16).array());
    	    			add(IV);
    	    			add(cipherText);
    	    			
    	    		}
    			},
    			Integer.BYTES+16+cipherText.length
        		);
        return retValue;
    }
    
    public byte[] decryptSecurePayload(byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
    	if(props.getProperty("PADDING").equals("NoPadding"))
        	cipher = Cipher.getInstance(props.getProperty("SEA")+"/"+props.getProperty("MODE")+"/"+props.getProperty("PADDING"),"BC");
        else
        	cipher = Cipher.getInstance(props.getProperty("SEA")+"/"+props.getProperty("MODE")+"/"+props.getProperty("PADDING"));
        
        int dataSize = new BigInteger(Arrays.copyOfRange(data, 0, Integer.BYTES)).intValue();
        byte[] mIV = Arrays.copyOfRange(data, Integer.BYTES, Integer.BYTES+16);
        byte[] m = Arrays.copyOfRange(data, Integer.BYTES+16,dataSize);

        if(props.getProperty("MODE").equals("CTR") || props.getProperty("MODE").equals("GCM"))
        	cipher.init(Cipher.DECRYPT_MODE,this.sessionKey , new IvParameterSpec(mIV));
        else
        	cipher.init(Cipher.DECRYPT_MODE,this.sessionKey);

        byte[] plainText = cipher.doFinal(Arrays.copyOfRange(data, Integer.BYTES+16,dataSize));
        int messageLength = plainText.length - hMac.getMacLength();

        hMac.update(plainText, 0, messageLength);

        byte[] messageHash = new byte[hMac.getMacLength()];
        System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);

        int userL,messageL,encodeL;
        byte[] u = Arrays.copyOfRange(plainText, 0,Integer.BYTES);
        userL = new BigInteger(u).intValue();
        messageL = new BigInteger(Arrays.copyOfRange(plainText, Integer.BYTES,Integer.BYTES*2)).intValue();
        byte[] username = Arrays.copyOfRange(plainText, Integer.BYTES*2, Integer.BYTES*2+userL);
        Long rand = ByteBuffer.wrap(Arrays.copyOfRange(plainText, Integer.BYTES*2+userL, Integer.BYTES*2+userL+Long.BYTES)).getLong();
        byte[] msg=Arrays.copyOfRange(plainText, Integer.BYTES*2+userL+Long.BYTES, messageL+Integer.BYTES*2+userL+Long.BYTES);
        byte[] encoded=Arrays.copyOfRange(plainText, messageL+Integer.BYTES*2+userL+Long.BYTES, messageL+Integer.BYTES*2+userL+Long.BYTES+plainText.length);
        return msg;
    }
    
    public byte[] computeSAttributes(ArrayList<byte[]> arr,int totalSize) {
    	byte[] att = new byte[totalSize];
    	int tempSize = 0;
    	byte[] temp;
    	for(int i = 0; i<arr.size();i++) {
    		temp = arr.get(i);
    		System.arraycopy( ByteBuffer.allocate( temp.length ).put(temp).array(),
                    0,
                    att,
                    tempSize,
                    temp.length
            );
    		tempSize+= temp.length;
    	}
        return att;
    }
    
}
