
import java.util.Arrays;

public class UserDatagramProtocol extends Protocol {

    private Protocol protocol;
    private int source;
    private int destination;
    private int payloadSize;

    private InternetProtocol ip;

    public static final byte[] hexaValue = {(byte)0x11};

    public UserDatagramProtocol(Packet packet, byte[] bytes) {
        super(packet, bytes, "UDP");
        this.ip = this.packet.ip;
    }

    public UserDatagramProtocol(Packet packet) {
        super(packet, "UDP");
        this.ip = this.packet.ip;
    }

    public void parse() {
        this.parseSource();
        this.parseDestination();
        this.parsePayloadLength();
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

    private void parsePayloadLength() {
        this.payloadSize = Wiresharklike.bytesToInt(Arrays.copyOfRange(this.data, 4, 6)) - 8;
    }

    public void print() {
        super.print();
        System.out.print(this.source + " -> " + this.destination + " ");
        System.out.print("len=" + this.payloadSize);
        System.out.println("");
    }
}