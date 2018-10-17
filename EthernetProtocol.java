
import java.lang.String;
import java.util.Arrays;

public class EthernetProtocol extends Protocol {

    /* Ethernet 14B header + data */

    private String destination;     /* @MAC destination */
    private String source;          /* @MAC source */
    private Protocol protocol;      /* protocol encapsulated by ethernet */

    public EthernetProtocol(Packet packet, byte[] bytes) {
        super(packet, bytes, "Ethernet");
    }

    public EthernetProtocol(Packet packet) {
        super(packet, "Ethernet");
    }

    public void parse() {
        this.parseDestination();
        this.parseSource();
        this.parseProtocol();
    }

    private void parseDestination() {
        this.destination = Wiresharklike.parseMac(Arrays.copyOfRange(this.data, 0, 6));
    }

    private void parseSource() {
        this.source = Wiresharklike.parseMac(Arrays.copyOfRange(this.data, 6, 12));
    }

    private void parseProtocol() {
        this.protocol = Wiresharklike.parseProtocolType(this.packet, Arrays.copyOfRange(this.data, 12, 14));        
        this.protocol.setData(Arrays.copyOfRange(this.data, 14, this.data.length));
        this.protocol.parse();
    }

    public void print() {
        super.print();
        System.out.println(this.source + " -> " + this.destination);
    }
}