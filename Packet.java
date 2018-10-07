import java.util.Arrays;

public class Packet {
    /* 128b = 16B */
    private byte[] header;
    private byte[] data;
    private int dataSize;
    private byte[] ts_sec;         /* 32b timestamp seconds */
    private byte[] ts_usec;        /* 32b timestamp microseconds */
    private byte[] incl_len;       /* 32b number of octets of packet saved in file */
    private byte[] orig_len;       /* 32b actual length of packet */

    private Ethernetx ethernet;

    public Packet(byte[] bytes) {
        this.header = bytes;
        this.ts_sec = Arrays.copyOfRange(this.header, 0, 4);
        this.ts_usec = Arrays.copyOfRange(this.header, 4, 8);
        this.incl_len = Arrays.copyOfRange(this.header, 8, 12);
        this.orig_len = Arrays.copyOfRange(this.header, 12, 16);
        
        this.reverse(this.incl_len);
        this.dataSize = this.bytesToInt(this.incl_len);
    }

    public int getDataSize() {
        return this.dataSize;
    }

    public void reverse(byte[] array) {
        for(int i=0; i<array.length/2; i++) {
            byte tmp = array[i];
            array[i] = array[array.length - i - 1];
            array[array.length - i - 1] = tmp;
        }
    }

    public int bytesToInt(byte[] bytes) {
        int v = 0;
        for(int i=0; i<bytes.length; i++) {
            v = v << 8;
            v = v | (bytes[i] & 0xFF);
        }
        return v;
    }

    public void setData(byte[] bytes) {
        this.data = bytes;
    }

    public void print() {
        this.ethernet.print();
        System.out.println("1 packet");
    }

    public void parse() {
        this.ethernet = new Ethernetx(Arrays.copyOfRange(this.data, 0, 14));
        this.ethernet.parse();
    }
}