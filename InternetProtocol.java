
import java.util.Arrays;

public class InternetProtocol extends Protocol {

    private int length;
    private Protocol protocol = null;
    public String source = "";
    public String destination = "";
    private int headerSize;
    private int payloadSize;
    private int version;
    private byte[] payload;
    private int id;
    private boolean reservedbit;
    private boolean donotfragment;
    private boolean morefragments;
    private int offset;
    private boolean fragment = false;
    private boolean lastfragment = false;
    private IPFragmentsGroup ipfraggroup;

    public static final byte[] hexaValue = {(byte)0x08, (byte)0x00};

    public InternetProtocol(Packet packet, byte[] bytes) {
        super(packet, bytes, "IPv4");
        this.packet.ip = this;
    }

    public InternetProtocol(Packet packet) {
        super(packet, "IPv4");
        this.packet.ip = this;
    }

    public void parse() {
        this.parseVersion();
        this.parseHeaderSize();
        this.parseSource();
        this.parseDestination();
        this.parseLength();
        this.parsePayload();
        this.parseFlags();
        this.parseId();

        if(this.offset == 0 && !this.morefragments) {
            this.parseProtocol();
        }
        else {
            // this is a fragment
            this.fragment = true;
            IPFragmentsGroup ifg = Wiresharklike.findIpFragmentsGroup(this.id, this.source, this.destination);
            if(ifg == null) {
                this.ipfraggroup = new IPFragmentsGroup(this.id, this.source, this.destination);
                Wiresharklike.ipfraggroup.add(this.ipfraggroup);
            }
            else {
                this.ipfraggroup = ifg;
            }
            this.ipfraggroup.add(this);
        }
    }

    private void parseFlags() {
        int[] flags = Wiresharklike.binToBits(Arrays.copyOfRange(this.data, 6, 7)[0]);
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
        
        int[] flags2 = Wiresharklike.binToBits(Arrays.copyOfRange(this.data, 7, 8)[0]);

        int[] offset = new int[13];
        int i = 0;
        for(int j = 3; j<8; j++) {
            offset[i++] = flags[j];
        }
        for(int j = 0; j<8; j++) {
            offset[i++] = flags2[j];
        }

        this.offset = Wiresharklike.restoreInt(offset) * 8;
    }

    private void parseId() {
        this.id = Wiresharklike.bytesToInt(Arrays.copyOfRange(this.data, 4, 6));
    }

    private void parseLength() {
        this.length = Wiresharklike.bytesToInt(Arrays.copyOfRange(this.data, 2, 4));
    }

    public void parseProtocol() {
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
        this.payloadSize = this.length - (32 * this.headerSize) / 8;
        this.payload = Arrays.copyOfRange(this.data, (32 * this.headerSize) / 8, this.data.length);
    }

    public void print() {
        super.print();
        System.out.println(this.source + " -> " + this.destination);
        if(this.fragment) {
            if(this.ipfraggroup.rebuildpacketid != this.packet.getUid())
                System.out.println("IP Fragment, reassembled in [" + this.ipfraggroup.rebuildpacketid + "] (id=" + this.id + ", offset=" + this.offset + ").");
            else 
                System.out.println("Reassembled from fragments: [" + this.ipfraggroup.fragmentsids + "] (id=" + this.id + ", offset=" + this.offset + ").");
        }
    }

    public int getOffset() {
        return this.offset;
    }

    public int getPayloadLength() {
        return this.payloadSize;
    }

    public byte[] getPayload() {
        return this.payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = payload;
    }

    public void setLastFragment() {
        this.lastfragment = true;
    }

    public String getSource() {
        return this.source;
    }

    public String getDestination() {
        return this.destination;
    }

    public int getId() {
        return this.id;
    }
}