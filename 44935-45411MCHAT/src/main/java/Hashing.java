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
        cipher = Cipher.getInstance(props.getProperty("SEA")+"/"+props.getProperty("MODE")+"/"+props.getProperty("PADDING"),"BC");
        hMac = Mac.getInstance(props.getProperty("MAC"));
        hMac.init(this.macKey);
    }
    
    
    public byte[] decript(byte[] data) throws BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {
    	int offset = 0;
		int seaLength = new BigInteger(Arrays.copyOfRange(data, offset, Integer.BYTES)).intValue();
		offset+=Integer.BYTES;
		int shaLength = new BigInteger(Arrays.copyOfRange(data, offset, offset+Integer.BYTES)).intValue();
		offset+=Integer.BYTES;
		byte[] encodedMessage = Arrays.copyOfRange(data, offset,hMac.getMacLength());
		hMac.update(encodedMessage);

		byte vID = encodedMessage[0];
		offset = 1;
		String sID = new String(Arrays.copyOfRange(encodedMessage, offset, offset+seaLength));
		offset += seaLength;
		byte SMCPmsgType = encodedMessage[offset];
		offset++;
		byte[] sha = Arrays.copyOfRange(encodedMessage, offset, offset+shaLength);
		offset+=shaLength;
		int payLoadSize = new BigInteger(Arrays.copyOfRange(data, offset, offset+Integer.BYTES)).intValue();
		offset += Integer.BYTES;
		byte[] encodedPayload = Arrays.copyOfRange(encodedMessage, offset, offset+payLoadSize);

    	return decryptSecurePayload(encodedMessage);
	}

    public byte[] sha256Encoder(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(this.props.getProperty("INTHASH"));
        System.out.println(data.length);
        return digest.digest(data);
    }

   
    
    public byte[] decryptSecurePayload(byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        cipher = Cipher.getInstance(props.getProperty("SEA")+"/"+props.getProperty("MODE")+"/"+props.getProperty("PADDING"),"BC");
        
        int dataSize = new BigInteger(Arrays.copyOfRange(data, 0, Integer.BYTES)).intValue();
        byte[] mIV = Arrays.copyOfRange(data, Integer.BYTES, Integer.BYTES+16);
        byte[] m = Arrays.copyOfRange(data, Integer.BYTES+16,dataSize);

        cipher.init(Cipher.DECRYPT_MODE,this.sessionKey , new IvParameterSpec(mIV));

        byte[] plainText = cipher.doFinal(m);
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
