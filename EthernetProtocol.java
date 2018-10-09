
import java.lang.String;
import java.util.Arrays;

public class EthernetProtocol extends Protocol {

    /* Ethernet 14B header + data */

    private String destination;
    private String source;
    private Protocol protocol;

    public EthernetProtocol(byte[] bytes) {
        super(bytes, "Ethernet");
    }

    public void parse() {
        this.parseDestination();
        this.parseSource();
        this.parseProtocol();
    }

    private void parseDestination() {
        byte[] dst = Arrays.copyOfRange(this.data, 0, 6);        
        String destination = "";
        for(int i=0; i<6; i++) {
            destination += String.format("%02X:", dst[i]);
        }
        destination = destination.substring(0, destination.length() - 1);
        this.destination = destination;
    }

    private void parseSource() {
        byte[] src = Arrays.copyOfRange(this.data, 6, 12);        
        String source = "";
        for(int i=0; i<6; i++) {
            source += String.format("%02X:", src[i]);
        }
        source = source.substring(0, source.length() - 1);
        this.source = source;
    }

    private void parseProtocol() {
        byte[] prc = Arrays.copyOfRange(this.data, 12, 14);
        if(Arrays.equals(prc, InternetProtocol.hexaValue)) {
            this.protocol = new InternetProtocol(Arrays.copyOfRange(this.data, 14, this.data.length));
        }
        else {
            this.protocol = null;
        }
        if(this.protocol != null) {
            this.protocol.parse();
        }
    }

    public void print() {
        System.out.println("Ethernet:\t" + this.source + " -> " + this.destination + " (" + this.protocol.name + ")");
        this.protocol.print();
    }
}