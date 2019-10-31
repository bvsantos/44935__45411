// MulticastChat.java
// Objecto que representa um chat Multicast

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import Exceptions.AlrdyGotMessageException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Properties;

public class MulticastChat extends Thread {


    // Identifica uma op. de JOIN ao chat multicast  //
    public static final int JOIN = 1;

    // Identifica uma op. de LEAVE do chat multicast  //
    public static final int LEAVE = 2;

    // Identifica uma op. de processamento de uma MENSAGEM normal //
    public static final int MESSAGE = 3;

    // N. Magico que funciona como Id unico do Chat
    public static final long CHAT_MAGIC_NUMBER = 4969756929653643804L;

    // numero de milisegundos no teste de pooling de terminacao  //
    public static final int DEFAULT_SOCKET_TIMEOUT_MILLIS = 5000;

    // Multicast socket used to send and receive multicast protocol PDUs
    // Socket Multicast usado para enviar e receber mensagens
    // no ambito das operacoes que tem lugar no Chat

    //protected MulticastSocket msocket;

    //TODO: Usar este multicastocket
    protected SMCPSocket msocket;

//    protected TestSockets msocket;
    // Username / User-Nick-Name do Chat
    protected String username;

    // Grupo IP Multicast utilizado
    protected InetAddress groupAdress;

    // Listener de eventos enviados por Multicast
    protected MulticastChatEventListener listener;

    protected final String PROPS_LOCATION = "src/main/java/Configurations/SMCP.conf";

    // Controlo  - thread de execucao

    protected boolean isActive;
    protected int pport;
    protected long sequence;
    public MulticastChat(String username, InetAddress group, int port,
                         int ttl,
                         MulticastChatEventListener listener) throws ParserConfigurationException, SAXException, IOException, CertificateException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, UnrecoverableEntryException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException {

        this.username = username;
        this.pport = port;
        this.groupAdress = group;
        this.listener = listener;
        isActive = true;
        this.sequence = 0;

        // create & configure multicast socket
        //msocket = new MulticastSocket(port);

        int aux = getXMLTag(port);
        String auxString="";
        if(aux == 0)
            auxString = "A";
        else if(aux == 1)
            auxString = "B";
        else
            auxString = "C";

        msocket = new SMCPSocket(port,getProps(getXMLTag(port)),this.groupAdress.getHostAddress(),auxString);
        msocket.setSoTimeout(DEFAULT_SOCKET_TIMEOUT_MILLIS);
        msocket.setTimeToLive(ttl);
        msocket.joinGroup(group);

        // start receive thread and send multicast join message
        start();

        sendJoin();

    }

    public int getXMLTag(int port){
        switch(this.groupAdress.getHostAddress()+":"+port){
            case "224.5.6.7:9000":
                return 0;
            case "252.10.20.30:12224":
                return 1;
            case "230.100.100.100:6666":
                return 2;
            default:
                System.err.println("No configuration for "+this.groupAdress.getHostAddress()+":"+port);
                System.exit(1);
        }
        return -1;
    }

    public Properties getProps(int server) throws IOException, SAXException, ParserConfigurationException {
        File fXmlFile = new File(PROPS_LOCATION);
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(fXmlFile);
        Properties p = new Properties();
        doc.getDocumentElement().normalize();
        Element el = (Element) doc.getElementsByTagName("arr").item(server);
        p.setProperty("SID",el.getElementsByTagName("SID").item(0).getTextContent());
        p.setProperty("SEA",el.getElementsByTagName("SEA").item(0).getTextContent());
        p.setProperty("SEAKS",el.getElementsByTagName("SEAKS").item(0).getTextContent());
        p.setProperty("MODE",el.getElementsByTagName("MODE").item(0).getTextContent());
        p.setProperty("PADDING",el.getElementsByTagName("PADDING").item(0).getTextContent());
        p.setProperty("INTHASH",el.getElementsByTagName("INTHASH").item(0).getTextContent());
        p.setProperty("MAC",el.getElementsByTagName("MAC").item(0).getTextContent());
        p.setProperty("MAKKS",el.getElementsByTagName("MAKKS").item(0).getTextContent());
        return p;
    }

    /**
     * Request de terminacao assincrona da thread de execucao,
     * e envio de uma mensagem de LEAVE
     */

    public void terminate() throws IOException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, ShortBufferException, InvalidKeyException, NoSuchProviderException {
        isActive = false;
        sendLeave();
    }

    // Issues an error message
    protected void error(String message) {
        System.err.println(new java.util.Date() + ": MulticastChat: "
                + message);
    }

    // Envio de mensagem na op. de JOIN
    //
    protected void sendJoin() throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.writeLong(CHAT_MAGIC_NUMBER);
        dataStream.writeInt(JOIN);
        dataStream.writeUTF(username);
        dataStream.close();

        byte[] data = byteStream.toByteArray();
        DatagramPacket packet = new DatagramPacket(data, data.length, groupAdress,
        		pport);
        msocket.send(packet,username);
    }

    // Processamento de um JOIN ao grupo multicast com notificacao
    //
    protected void processJoin(DataInputStream istream, InetAddress address,
                               int port) throws IOException {
        String name = istream.readUTF();
        if(sequence!=0) {
	        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
	        DataOutputStream dataStream = new DataOutputStream(byteStream);
	
	        dataStream.writeLong(CHAT_MAGIC_NUMBER);
	        dataStream.writeInt(4);
	        dataStream.writeLong(this.sequence);
	        dataStream.close();
	
	        byte[] data = byteStream.toByteArray();
	        DatagramPacket packet = new DatagramPacket(data, data.length, groupAdress,
	        		pport);
	        msocket.send(packet,this.username);
        }
        try {
            listener.chatParticipantJoined(name, address, port);
        } catch (Throwable e) {}
    }

    // Envio de mensagem de LEAVE para o Chat
    protected void sendLeave() throws IOException {

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.writeLong(CHAT_MAGIC_NUMBER);
        dataStream.writeInt(LEAVE);
        dataStream.writeUTF(username);
        dataStream.close();

        byte[] data = byteStream.toByteArray();
        DatagramPacket packet = new DatagramPacket(data, data.length, groupAdress,
        		pport);
        msocket.send(packet,username);
    }

    // Processes a multicast chat LEAVE PDU and notifies listeners
    // Processamento de mensagem de LEAVE  //
    protected void processLeave(DataInputStream istream, InetAddress address,
                                int port) throws IOException {
        String username = istream.readUTF();

        try {
            listener.chatParticipantLeft(username, address, port);
        } catch (Throwable e) {}
    }

    // Envio de uma mensagem normal
    //
    public void sendMessage(String message) throws IOException {

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        DataOutputStream dataStream = new DataOutputStream(byteStream);

        dataStream.writeLong(CHAT_MAGIC_NUMBER);
        dataStream.writeInt(MESSAGE);
        dataStream.writeLong(this.sequence+1);
        dataStream.writeUTF(username);
        dataStream.writeUTF(message);
        dataStream.close();
        System.out.println(this.sequence);
        byte[] data = byteStream.toByteArray();
        DatagramPacket packet = new DatagramPacket(data, data.length, groupAdress,
        		pport);
        msocket.send(packet,username);
    }


    // Processamento de uma mensagem normal  //
    //
    protected void processMessage(DataInputStream istream,
                                  InetAddress address,
                                  int port) throws IOException, AlrdyGotMessageException {
    	long msgSeq=istream.readLong();
        String username = istream.readUTF();
        String message = istream.readUTF();
        if(msgSeq<=this.sequence)
        	throw new AlrdyGotMessageException();
        else
	        try {
	        	this.sequence=msgSeq+1;
	            listener.chatMessageReceived(username, address, port, message);
	        } catch (Throwable e) {}
    }

    // Loops - recepcao e desmultiplexagem de datagramas de acordo com
    // as operacoes e mensagens
    //
    public void run() {
        byte[] buffer = new byte[65508];
        DatagramPacket packet;

        while (isActive) {
            try {

                // Comprimento do DatagramPacket RESET antes do request
            	packet = new DatagramPacket(buffer, buffer.length, groupAdress,
            			pport);
//            	packet.setLength(buffer.length);
                msocket.receive(packet);
                DataInputStream istream =
                        new DataInputStream(new ByteArrayInputStream(packet.getData(),
                                0, packet.getLength()));

                long magic = istream.readLong();

                if (magic != CHAT_MAGIC_NUMBER) {
                    continue;

                }
                int opCode = istream.readInt();
                switch (opCode) {
                    case JOIN:
                        processJoin(istream, packet.getAddress(), packet.getPort());
                        break;
                    case LEAVE:
                        processLeave(istream, packet.getAddress(), packet.getPort());
                        break;
                    case MESSAGE:
                        processMessage(istream, packet.getAddress(), packet.getPort());
                        break;
                    case 4:
                    	sequence = istream.readLong();
                    	break;
                    default:
                        error("Cod de operacao desconhecido " + opCode + " enviado de "
                                + packet.getAddress() + ":" + packet.getPort());
                }

            }catch(SocketTimeoutException e){

                /*Triggered pelo timeout, util para verificar a flag isActive*/
            }catch (Throwable e) {
                error("Processing error: " + e.getClass().getName() + ": "
                        + e.getMessage());
            }
        }

        try {
            msocket.close();
        } catch (Throwable e) {}
    }
}
