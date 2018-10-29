import java.util.ArrayList;
import java.util.Arrays;

public class Packet {
    /* 128b = 16B */

    private int uid;
    private int dataSize;           /* size of the packet */

    /* raw information */
    private byte[] header;
    private byte[] data;
    private byte[] ts_sec;          /* 32b timestamp seconds */
    private byte[] ts_usec;         /* 32b timestamp microseconds */
    private byte[] incl_len;        /* 32b number of octets of packet saved in file */
    private byte[] orig_len;        /* 32b actual length of packet */
    
    public ArrayList<Protocol> protocols = new ArrayList<Protocol>();
    public InternetProtocol ip;
    private Protocol protocol;

    public Packet(int uid, byte[] bytes) {
        this.uid = uid;
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
        System.out.println("[" + this.uid + "]");
        for(int i=0; i<this.protocols.size(); i++) {
            this.protocols.get(i).print();
        }
        System.out.println();
        System.out.println();
    }

    public void parse() {
        /* first protocol will always be ethernet (because it only has to support ethernet) */
        this.protocol = new EthernetProtocol(this, Arrays.copyOfRange(this.data, 0, this.data.length));
        this.protocol.parse();        
    }

    public void flow() {
        for(int i=0; i<this.protocols.size(); i++) {
            this.protocols.get(i).flow();
        }
    }

    public int getUid() {
        return this.uid;
    }
}