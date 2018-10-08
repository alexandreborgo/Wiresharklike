
import java.util.Arrays;

public class InternetProtocol extends Protocolx {
    private int length;

    private Protocol protocol;
    private String source;
    private String destination;

    private final byte[] tcp = {(byte)0x06};

    public InternetProtocol(byte[] bytes) {
        super(bytes);
    }

    public void parse() {
        this.parseLength();
        this.parseProtocol();
        this.parseSource();
        this.parseDestination();
    }

    public void parseLength() {
        byte[] lth = Arrays.copyOfRange(this.data, 2, 4);        
        this.length = Wiresharklike.bytesToInt(lth);
    }

    public void parseProtocol() {
        byte[] prc = Arrays.copyOfRange(this.data, 9, 10);        
        
        if(Arrays.equals(prc, this.tcp)) {
            protocol = Protocol.TCP;
        }
        else {
            protocol = Protocol.Unknown;
        }
    }

    public void parseSource() {
        byte[] src = Arrays.copyOfRange(this.data, 12, 16);        
        String source = "";
        for(int i=0; i<4; i++) {
            source += Integer.parseInt(String.format("%X", src[i]), 16) + ".";
        }
        source = source.substring(0, source.length() - 1);
        this.source = source;
    }

    public void parseDestination() {
        byte[] dst = Arrays.copyOfRange(this.data, 16, 20);        
        String destination = "";
        for(int i=0; i<4; i++) {
            destination += Integer.parseInt(String.format("%X", dst[i]), 16) + ".";
        }
        destination = destination.substring(0, destination.length() - 1);
        this.destination = destination;
    }

    public void print() {
        System.out.println("IP:\tDestination: " + this.destination + "\tSource: " + this.source + "\tProtocol: " + this.protocol);
    }
}