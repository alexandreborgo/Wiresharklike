
import java.lang.String;
import java.util.Arrays;

public class EthernetProtocol extends Protocolx{

    private String destination;
    private String source;
    private Protocol protocol;

    private final byte[] ipv4 = {(byte)0x08, (byte)0x00};

    public EthernetProtocol(byte[] bytes) {
        super(bytes);
    }

    public void parse() {
        this.destination = this.parseDestination();
        this.source = this.parseSource();
        this.protocol = this.parseProtocol();
    }

    public String parseDestination() {
        byte[] dst = Arrays.copyOfRange(this.data, 0, 6);        
        String destination = "";
        for(int i=0; i<6; i++) {
            destination += String.format("%02X:", dst[i]);
        }
        destination = destination.substring(0, destination.length() - 1);
        return destination;
    }

    public String parseSource() {
        byte[] src = Arrays.copyOfRange(this.data, 6, 12);        
        String source = "";
        for(int i=0; i<6; i++) {
            source += String.format("%02X:", src[i]);
        }
        source = source.substring(0, source.length() - 1);
        return source;
    }

    public Protocol parseProtocol() {
        byte[] prc = Arrays.copyOfRange(this.data, 12, 14);
        Protocol protocol;
        if(Arrays.equals(prc, this.ipv4)) {
            protocol = Protocol.IPv4;
        }
        else {
            protocol = Protocol.Unknown;
        }
        return protocol;
    }

    public void print() {
        System.out.println("Ethernet:\tDestination: " + this.destination + "\tSource: " + this.source + "\tProtocol: " + this.protocol);
    }
}