
import java.util.Arrays;

public class InternetProtocol extends Protocol {

    private int length;
    private Protocol protocol = null;
    private String source = "";
    private String destination = "";
    private int headerSize;
    private int version;
    private byte[] payload;
    private byte[] id;
    private boolean reservedbit;
    private boolean donotfragment;
    private boolean morefragments;

    public static final byte[] hexaValue = {(byte)0x08, (byte)0x00};

    public InternetProtocol(Packet packet, byte[] bytes) {
        super(packet, bytes, "IPv4");
    }

    public InternetProtocol(Packet packet) {
        super(packet, "IPv4");
    }

    public void parse() {
        this.parseVersion();
        this.parseHeaderSize();
        this.parseSource();
        this.parseDestination();
        this.parsePayload();
        this.parseLength();
        this.parseFlag();
        this.parseId();
        this.parseProtocol();
    }

    private void parseFlag() {
        int[] flags = Arrays.copyOfRange(Wiresharklike.toBits(Arrays.copyOfRange(this.data, 6, 7)[0]), 0, 3);
        if(flags[0] == 1)
            this.reservedbit = true;
        else
            this.reservedbit = false;
        if(flags[1] == 1)
            this.donotfragment = true;
        else
            this.donotfragment = false;
        if(flags[2] == 1)
            this.morefragments = true;
        else
            this.morefragments = false;     
    }

    private void parseId() {
        this.id = Arrays.copyOfRange(this.data, 4, 6);
    }

    private void parseLength() {
        this.length = Wiresharklike.bytesToInt(Arrays.copyOfRange(this.data, 2, 4));        
    }

    private void parseProtocol() {
        this.protocol = Wiresharklike.parseProtocolType(this.packet, Arrays.copyOfRange(this.data, 9, 10));
        this.protocol.setData(Arrays.copyOfRange(this.payload, 0, this.payload.length));
        this.protocol.parse();
    }

    private void parseSource() {
        this.source = Wiresharklike.parseIp(Arrays.copyOfRange(this.data, 12, 16));
    }

    private void parseDestination() {
        this.destination = Wiresharklike.parseIp(Arrays.copyOfRange(this.data, 16, 20));
    }

    private void parseVersion() {
        this.version = Wiresharklike.restoreInt(Arrays.copyOfRange(Wiresharklike.toBits(Arrays.copyOfRange(this.data, 0, 1)[0]), 0, 4));
    }

    private void parseHeaderSize() {
        this.headerSize = Wiresharklike.restoreInt(Arrays.copyOfRange(Wiresharklike.toBits(Arrays.copyOfRange(this.data, 0, 1)[0]), 4, 8));
    }

    private void parsePayload() {
        /* offset = sizeof(word)=32 * nb words=(headersize) / sizeof(byte) */
        this.payload = Arrays.copyOfRange(this.data, (32 * this.headerSize) / 8, this.data.length);
    }

    public void print() {
        super.print();
        System.out.println(this.source + " -> " + this.destination);
    }
}