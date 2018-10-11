
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

    public EthernetProtocol() {
        super("Ethernet");
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
        this.protocol = Wiresharklike.parseProtocolType(Arrays.copyOfRange(this.data, 12, 14));
        this.protocol.setData(Arrays.copyOfRange(this.data, 14, this.data.length));
        this.protocol.parse();
    }

    public void print() {
        super.print();
        System.out.println(this.source + " -> " + this.destination + " (" + this.protocol.name + ")");
        this.protocol.print();
    }
}