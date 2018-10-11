
import java.util.Arrays;

public class TransmissionControlProtocol extends Protocol {

    private Protocol protocol;
    private int source;
    private int destination;

    public static final byte[] hexaValue = {(byte)0x06};

    public TransmissionControlProtocol(byte[] bytes) {
        super(bytes, "TCP");
    }

    public TransmissionControlProtocol() {
        super("TCP");
    }

    public void parse() {
        this.parseSource();
        this.parseDestination();
        this.parseProtocol();
    }

    private void parseSource() {
        byte[] src = Arrays.copyOfRange(this.data, 0, 2);
        this.source = Wiresharklike.bytesToInt(src);
    }

    private void parseDestination() {
        byte[] dst = Arrays.copyOfRange(this.data, 2, 4);
        this.destination = Wiresharklike.bytesToInt(dst);
    }

    private void parseProtocol() {
        this.protocol = new UnknownProtocol();
    }

    public void print() {
        super.print();
        System.out.println(this.source + " -> " + this.destination + " (" + this.protocol.name + ")");
    }
}