
import java.lang.String;
import java.util.Arrays;

public class Ethernetx {

    private byte[] bytes;
    private String destination;
    private String source;
    private String protocol;

    private final byte[] ipv4 = {(byte)0x08, (byte)0x00};

    public Ethernetx(byte[] bytes) {
        this.bytes = bytes;
    }

    public void parse() {
        this.destination = this.parseDestination();
        this.source = this.parseSource();
        this.protocol = this.parseProtocol();
    }

    public String parseDestination() {
        byte[] dst = Arrays.copyOfRange(this.bytes, 0, 6);        
        String destination = "";
        for(int i=0; i<6; i++) {
            destination += String.format("%02X:", dst[i]);
        }
        destination = destination.substring(0, destination.length() - 1);
        return destination;
    }

    public String parseSource() {
        byte[] src = Arrays.copyOfRange(this.bytes, 6, 12);        
        String source = "";
        for(int i=0; i<6; i++) {
            source += String.format("%02X:", src[i]);
        }
        source = source.substring(0, source.length() - 1);
        return source;
    }

    public String parseProtocol() {
        byte[] prc = Arrays.copyOfRange(this.bytes, 12, 14);
        String protocol = "";
        if(Arrays.equals(prc, this.ipv4)) {
            protocol = "IPv4";
        }
        else {
            protocol = "unknown";
        }
        return protocol;
    }

    public void print() {
        System.out.println("Destination: \t" + this.destination);
        System.out.println("Source: \t" + this.source);
        System.out.println("Protocol: \t" + this.protocol);
    }
}