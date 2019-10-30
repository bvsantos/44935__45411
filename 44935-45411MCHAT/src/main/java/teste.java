
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Message tampering com HMAC, cifra AES e modo CTR
 */
public class teste
{
    static IvParameterSpec ivSpec;
    static Key             key;
    static Cipher          cipher;
    static String          input;
    static Mac             hMac;
    static Key             hMacKey;
    public static void main(
            String[]    args)
            throws Exception
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        byte[]		    ivBytes = new byte[] {
                0x00, 0x00, 0x00, 0x01, 0x04, 0x05, 0x06, 0x07,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
        ivSpec = new IvParameterSpec(ivBytes);
                  cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
                  input = "Transfer 0000100 to AC 1234-5678";

                     hMac = Mac.getInstance("HMacSHA256");


        KeyGenerator generator = KeyGenerator.getInstance("AES");

        generator.init(256);

        key = generator.generateKey();

        hMacKey =new SecretKeySpec(key.getEncoded(), "HMacSHA256");
        System.out.println("input : " + input);

        hMac.init(hMacKey);
        // cifrar Alice (Correta)

//        byte[] cipherText = securePayloadEncrypt(input.getBytes(),"AWMan");
        byte[] cipherText = securePayloadEncrypt(input.getBytes(),"AWMan");

        // ========================================================
        // Ataque de tampering
        // Mallory ... MiM

        //cipherText[9] ^= '0' ^ '9';

        // Substituir a sintese (mas como ?)

        // ?

        // ========================================================

        // Decifrar (Bob Correto)

        String s = new String(securePayloadDecrypt(cipherText));
//        decode(cipherText);
//        System.out.println("Verified w/ message-integrity and message-authentication :" + MessageDigest.isEqual(hMac.doFinal(), messageHash));
        }

/*    public static void main(String[] args){
//        String name = "AWMan";
//
//        int i = name.getBytes().length;
//        byte[]g = new byte[Integer.BYTES];
        byte[]g = {0,0,0,-103};
//        System.arraycopy( ByteBuffer.allocate( Integer.BYTES ).putInt(i).array(),
//                0,
//                g,
//                0,
//                Integer.BYTES
//        );
        System.out.println(new BigInteger(g).intValue());
    }*/

    public static byte[] sha256Encoder(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    public static byte[] securePayloadEncrypt(byte[] data, String username) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
        byte[] encoded = sha256Encoder(data);
        byte[] secured = new byte[Integer.BYTES*2+username.getBytes().length+ Long.BYTES+data.length+encoded.length];
        System.arraycopy( ByteBuffer.allocate( Integer.BYTES ).putInt(username.getBytes().length).array(),
                0,
                secured,
                0,
                Integer.BYTES
        );
        System.arraycopy( ByteBuffer.allocate( Integer.BYTES ).putInt(data.length).array(),
                0,
                secured,
                Integer.BYTES,
                Integer.BYTES
        );
        // place username in array
        System.arraycopy( ByteBuffer.allocate( username.getBytes().length ).put(username.getBytes()).array(),
                0,
                secured,
                Integer.BYTES*2,
                username.getBytes().length
        );

        //TODO: Este é o long que tem de ser incrementado o objectivo nao é ser um random long
        SecureRandom s = new SecureRandom();
        System.arraycopy( ByteBuffer.allocate( Long.BYTES ).putLong(s.nextLong()).array(),
                0,
                secured,
                Integer.BYTES*2+username.getBytes().length,
                Long.BYTES
        );

        System.arraycopy( ByteBuffer.allocate( data.length ).put(data).array(),
                0,
                secured,
                Integer.BYTES*2+username.getBytes().length+ Long.BYTES,
                data.length
        );

        System.arraycopy( ByteBuffer.allocate( encoded.length ).put(encoded).array(),
                0,
                secured,
                Integer.BYTES*2+username.getBytes().length+ Long.BYTES+data.length,
                encoded.length
        );

        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] cipherText = new byte[cipher.getOutputSize(secured.length + hMac.getMacLength())];

        int ctLength = cipher.update(secured, 0, secured.length, cipherText, 0);

        hMac.update(secured);

        ctLength += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), cipherText, ctLength);

        byte[] IV = cipher.getIV();
        byte[] retValue = new byte[Integer.BYTES+IV.length+cipherText.length];
        System.arraycopy( ByteBuffer.allocate( Integer.BYTES ).putInt(Integer.BYTES+cipherText.length+16).array(),
                0,
                retValue,
                0,
                Integer.BYTES
        );
        System.arraycopy( ByteBuffer.allocate( IV.length ).put(IV).array(),
                0,
                retValue,
                Integer.BYTES,
                IV.length
        );
        System.arraycopy( ByteBuffer.allocate( cipherText.length ).put(cipherText).array(),
                0,
                retValue,
                Integer.BYTES+IV.length,
                cipherText.length
        );
        return retValue;
    }

    public static byte[] securePayloadDecrypt(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchProviderException {
        int dataSize = new BigInteger(Arrays.copyOfRange(data, 0, Integer.BYTES)).intValue();
        byte[] mIV = Arrays.copyOfRange(data, Integer.BYTES, Integer.BYTES+16);
        byte[] m = Arrays.copyOfRange(data, Integer.BYTES+16,dataSize);

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(mIV));

        byte[] plainText = cipher.doFinal(m);
        int messageLength = plainText.length - hMac.getMacLength();

        hMac.update(plainText, 0, messageLength);

        byte[] messageHash = new byte[hMac.getMacLength()];
        System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);

        int userL,messageL,encodeL;
        byte[] u = Arrays.copyOfRange(plainText, 0,Integer.BYTES);
        userL = new BigInteger(u).intValue();
        plainText = Arrays.copyOfRange(plainText, Integer.BYTES,plainText.length);
        messageL = new BigInteger(Arrays.copyOfRange(plainText, 0,Integer.BYTES)).intValue();
        plainText = Arrays.copyOfRange(plainText, Integer.BYTES,plainText.length);
        byte[] username = Arrays.copyOfRange(plainText, 0, userL);
        plainText = Arrays.copyOfRange(plainText, userL,plainText.length);
        Long rand = ByteBuffer.wrap(plainText).getLong();
        byte[] msg=Arrays.copyOfRange(plainText, Long.BYTES, messageL);
        byte[] encoded=Arrays.copyOfRange(plainText, Long.BYTES, plainText.length);


        printByteArray(username);
        printByteArray(msg);
        printByteArray(encoded);

        return plainText;
    }

    public static void printByteArray(byte[] b){
        String s = new String(b);
        System.out.println(s);
    }

    public static byte[] encode(String input) throws ShortBufferException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        cipher.init(Cipher.ENCRYPT_MODE, key,ivSpec);
        byte[] IV = ivSpec.getIV();
        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + hMac.getMacLength())];

        int ctLength = cipher.update(input.getBytes(), 0, input.length(), cipherText, 0);

        hMac.init(hMacKey);
        hMac.update(input.getBytes());

        ctLength += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), cipherText, ctLength);
        byte[] retValue = new byte[cipherText.length+16];
        System.arraycopy( ByteBuffer.allocate( IV.length ).put(IV).array(),
                0,
                retValue,
                0,
                IV.length
        );
        System.arraycopy( ByteBuffer.allocate( cipherText.length ).put(cipherText).array(),
                0,
                retValue,
                16,
                cipherText.length
        );
        return retValue;
    }

    public static void decode(byte[] cipherText) throws BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        byte[] mIV = new byte[16];
        System.arraycopy(cipherText, 0, mIV, 0, mIV.length);
        cipherText = Arrays.copyOfRange(cipherText, 16,cipherText.length);

        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] plainText = cipher.doFinal(cipherText, 0, cipherText.length);
        int    messageLength = plainText.length - hMac.getMacLength();

        hMac.init(hMacKey);
        hMac.update(plainText, 0, messageLength);

        byte[] messageHash = new byte[hMac.getMacLength()];
        System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);

        String s = new String(plainText);
        System.out.println("plain : "+s);
        System.out.println("Verified w/ message-integrity and message-authentication :" + MessageDigest.isEqual(hMac.doFinal(), messageHash));
    }
}