import java.util.Arrays;

public class Packet {
    /* 128b = 16B */

    private int dataSize;

    /* raw information */
    private byte[] header;
    private byte[] data;
    private byte[] ts_sec;         /* 32b timestamp seconds */
    private byte[] ts_usec;        /* 32b timestamp microseconds */
    private byte[] incl_len;       /* 32b number of octets of packet saved in file */
    private byte[] orig_len;       /* 32b actual length of packet */

    private EthernetProtocol ethernet;
    private InternetProtocol internet;

    public Packet(byte[] bytes) {
        this.header = bytes;
        this.ts_sec = Arrays.copyOfRange(this.header, 0, 4);
        this.ts_usec = Arrays.copyOfRange(this.header, 4, 8);
        this.incl_len = Arrays.copyOfRange(this.header, 8, 12);
        this.orig_len = Arrays.copyOfRange(this.header, 12, 16);
        
        Wiresharklike.reverse(this.incl_len);
        this.dataSize = Wiresharklike.bytesToInt(this.incl_len);
    }

    public int getDataSize() {
        return this.dataSize;
    }

    public void setData(byte[] bytes) {
        this.data = bytes;
    }

    public void print() {
        System.out.println("Ethernet: ");
        this.ethernet.print();
        System.out.println("Internet Protocol: ");
        this.internet.print();
        System.out.println();
    }

    public void parse() {
        this.ethernet = new EthernetProtocol(Arrays.copyOfRange(this.data, 0, 14));
        this.ethernet.parse();
        this.internet = new InternetProtocol(Arrays.copyOfRange(this.data, 14, 34));
        this.internet.parse();
    }
}