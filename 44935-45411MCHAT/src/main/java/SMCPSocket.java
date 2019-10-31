import javax.crypto.*;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.MulticastSocket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Properties;

public class SMCPSocket extends MulticastSocket {

    public Hashing hasher;

    public SMCPSocket(int port, Properties props, String hostAddress, String aux) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableEntryException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException {
        super(port);
        this.hasher = new Hashing(port,props,hostAddress,aux);
    }

    public void send(DatagramPacket p, String username) throws IOException{
        try {
//          p.setData(securePayloadEncrypt(p.getData(),username));
			p.setData(this.hasher.encriptSecurePayload(p.getData(),username));
           // p.setData(this.hasher.encript(p.getData(),username));
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | ShortBufferException
				| BadPaddingException | IllegalBlockSizeException | NoSuchProviderException e) {
			e.printStackTrace();
		}
        super.send(p);


    }

    public void receive(DatagramPacket p) throws IOException {
	    super.receive(p);
		try {
	        byte[] data;
//        	byte[] data = securePayloadDecrypt(p.getData());
			data = this.hasher.decryptSecurePayload(p.getData());
            //data = this.hasher.decript(p.getData());
	        p.setData(data); 
		} catch ( BadPaddingException | IllegalBlockSizeException
				| InvalidAlgorithmParameterException | NoSuchPaddingException | NoSuchAlgorithmException
				| NoSuchProviderException | InvalidKeyException e) {
			e.printStackTrace();
		}
    }
    
    public static void printByteArray(byte[] b){
        String s = new String(b);
        System.out.println(s);
    }

    
}
