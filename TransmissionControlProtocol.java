
import java.util.Arrays;

public class TransmissionControlProtocol extends Protocol {

    private Protocol protocol;
    private int source;
    private int destination;

    public static final byte[] hexaValue = {(byte)0x06};

    public TransmissionControlProtocol(Packet packet, byte[] bytes) {
        super(packet, bytes, "TCP");
    }

    public TransmissionControlProtocol(Packet packet) {
        super(packet, "TCP");
    }

    public void parse() {
        this.parseSource();
        this.parseDestination();
        this.parseProtocol();
    }

    private void parseSource() {
        this.source = Wiresharklike.bytesToInt(Arrays.copyOfRange(this.data, 0, 2));
    }

    private void parseDestination() {
        this.destination = Wiresharklike.bytesToInt(Arrays.copyOfRange(this.data, 2, 4));
    }

    private void parseProtocol() {
        this.protocol = new UnknownProtocol(this.packet);
    }

    public void print() {
        super.print();
        System.out.println(this.source + " -> " + this.destination + " (" + this.protocol.name + ")");
    }
}