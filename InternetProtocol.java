
import java.util.Arrays;

public class InternetProtocol extends Protocol {

    private int length;
    private Protocol protocol = null;
    private String source = "";
    private String destination = "";
    private int headerSize;
    private int version;
    private byte[] payload;

    // plus pr les flags : Wiresharklike.toBits(Arrays.copyOfRange(this.data, 0, 1)[0]);

    public static final byte[] hexaValue = {(byte)0x08, (byte)0x00};

    public InternetProtocol(byte[] bytes) {
        super(bytes, "IPv4");
    }

    public void parse() {
        this.parseVersion();
        this.parseHeaderSize();
        this.parseSource();
        this.parseDestination();
        this.parsePayload();
        this.parseLength();
        this.parseProtocol();
    }

    private void parseLength() {
        byte[] lth = Arrays.copyOfRange(this.data, 2, 4);        
        this.length = Wiresharklike.bytesToInt(lth);
    }

    private void parseProtocol() {
        byte[] prc = Arrays.copyOfRange(this.data, 9, 10);
        if(Arrays.equals(prc, TransmissionControlProtocol.hexaValue)) {
            this.protocol = new TransmissionControlProtocol(Arrays.copyOfRange(this.payload, 0, this.payload.length));
        }
        else {
            this.protocol = new UnknownProtocol();
        }
        if(this.protocol != null) {
            this.protocol.parse();
        }
    }

    private void parseSource() {
        byte[] src = Arrays.copyOfRange(this.data, 12, 16);        
        String source = "";
        for(int i=0; i<4; i++) {
            source += Integer.parseInt(String.format("%X", src[i]), 16) + ".";
        }
        source = source.substring(0, source.length() - 1);
        this.source = source;
    }

    private void parseDestination() {
        byte[] dst = Arrays.copyOfRange(this.data, 16, 20);        
        String destination = "";
        for(int i=0; i<4; i++) {
            destination += Integer.parseInt(String.format("%X", dst[i]), 16) + ".";
        }
        destination = destination.substring(0, destination.length() - 1);
        this.destination = destination;
    }

    private void parseVersion() {
        int[] bits = Wiresharklike.toBits(Arrays.copyOfRange(this.data, 0, 1)[0]);
        this.version = Wiresharklike.restoreInt(Arrays.copyOfRange(bits, 0, 4));
    }

    private void parseHeaderSize() {
        int[] bits = Wiresharklike.toBits(Arrays.copyOfRange(this.data, 0, 1)[0]);
        this.headerSize = Wiresharklike.restoreInt(Arrays.copyOfRange(bits, 4, 8));
    }

    private void parsePayload() {
        int offset = (32 * this.headerSize) / 8; /* sizeof word * nb words / sizeof byte */
        this.payload = Arrays.copyOfRange(this.data, offset, this.data.length);
    }

    public void print() {
        System.out.println("Internet:\t" + this.source + " -> " + this.destination + " (" + this.protocol.name + ")");
        this.protocol.print();
    }
}