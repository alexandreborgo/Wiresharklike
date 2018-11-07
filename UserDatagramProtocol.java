
import java.util.Arrays;

public class UserDatagramProtocol extends Protocol {

    private Protocol protocol;
    public int source;
    public int destination;
    private int payloadSize;
    private byte[] payload;

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
        this.parsePayload();
        this.parseProtocol();
    }

    private void parseSource() {
        this.source = Wiresharklike.bytesToInt(Arrays.copyOfRange(this.data, 0, 2));
    }

    private void parseDestination() {
        this.destination = Wiresharklike.bytesToInt(Arrays.copyOfRange(this.data, 2, 4));
    }

    private void parseProtocol() {
        ProtocolAnalysis pa = new ProtocolAnalysis(this.packet, this.source, this.destination, this.payload);
        this.protocol = pa.analysis();
        this.protocol.parse();
    }

    private void parsePayload() {
        this.payloadSize = Wiresharklike.bytesToInt(Arrays.copyOfRange(this.data, 4, 6)) - 8;
        this.payload = Arrays.copyOfRange(this.data, 8, this.data.length);
    }

    public void print() {
        super.print();
        System.out.print(this.source + " -> " + this.destination + " ");
        System.out.println("len=" + this.payloadSize);
        System.out.print("Data: ");
        System.out.print(Wiresharklike.byteToAscii(this.payload));
    }
}