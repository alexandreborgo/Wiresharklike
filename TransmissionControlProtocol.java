
import java.util.Arrays;

public class TransmissionControlProtocol extends Protocol {

    private Protocol protocol;
    private int source;
    private int destination;
    private int headerSize;
    private int payloadSize;
    private byte[] payload;

    private boolean syn = false;
    private boolean ack = false;
    private boolean reset = false;
    private boolean fin = false;
    private boolean push = false;
    private boolean urgent = false;
    private boolean echo = false;
    private boolean congest = false;
    private boolean nonce = false;
    private boolean handshake = false;

    private boolean segment = false;
    private boolean lastsegment = false;
    private int reassembledpacket;

    private int ackof = -1;

    private long sequence;
    private long acknowledgment;

    private InternetProtocol ip;

    private TCPStream tcpstream;

    public static final byte[] hexaValue = {(byte)0x06};

    public TransmissionControlProtocol(Packet packet, byte[] bytes) {
        super(packet, bytes, "TCP");
        this.ip = this.packet.ip;
    }

    public TransmissionControlProtocol(Packet packet) {
        super(packet, "TCP");
        this.ip = this.packet.ip;
    }

    public void parse() {
        this.parseSource();
        this.parseDestination();
        this.parseFlags();
        this.parseAcknowledgment();
        this.parseSequence();
        this.parseHeaderSize();
        this.parsePayload();
        
        TCPStream ts = Wiresharklike.findTCPStream(this.ip.getSource(), this.ip.getDestination(), this.source, this.destination);
        if(ts == null) {
            this.tcpstream = new TCPStream(this.ip.getSource(), this.ip.getDestination(), this.source, this.destination);
            Wiresharklike.tcpstreams.add(this.tcpstream);
        }
        else
            this.tcpstream = ts;
    
        this.tcpstream.add(this);
    }

    private void parseSource() {
        this.source = Wiresharklike.bytesToInt(Arrays.copyOfRange(this.data, 0, 2));
    }

    private void parseDestination() {
        this.destination = Wiresharklike.bytesToInt(Arrays.copyOfRange(this.data, 2, 4));
    }

    public void parseProtocol() {
        this.protocol = new UnknownProtocol(this.packet);
    }

    private void parseFlags() {
        int[] flags1 = Wiresharklike.binToBits(Arrays.copyOfRange(this.data, 12, 13)[0]);
        int[] flags2 = Wiresharklike.binToBits(Arrays.copyOfRange(this.data, 13, 14)[0]);

        if(flags2[7] == 1) this.fin = true;
        if(flags2[6] == 1) this.syn = true;
        if(flags2[5] == 1) this.reset = true;
        if(flags2[4] == 1) this.push = true;
        if(flags2[3] == 1) this.ack = true;
        if(flags2[2] == 1) this.urgent = true;
        if(flags2[1] == 1) this.echo = true;
        if(flags2[0] == 1) this.congest = true;
        if(flags1[7] == 1) this.nonce = true;
    }

    private void parseSequence() {
        this.sequence = Wiresharklike.bytesToLong(Arrays.copyOfRange(this.data, 4, 8));
    }

    private void parseAcknowledgment() {
        this.acknowledgment = Wiresharklike.bytesToLong(Arrays.copyOfRange(this.data, 8, 12));
    }

    private void parsePayload() {
        /* IP payload size - TCP header size */
        this.payloadSize = this.ip.getPayloadLength() - this.headerSize;
        this.payload = Arrays.copyOfRange(this.data, this.data.length-this.payloadSize, this.data.length);
    }

    private void parseHeaderSize() {
        this.headerSize = (Wiresharklike.restoreInt(Arrays.copyOfRange(Wiresharklike.toBits(Arrays.copyOfRange(this.data, 12, 13)[0]), 0, 4)) * 32) / 8;
    }

    public void print() {
        super.print();
        System.out.print(this.source + " -> " + this.destination + " [ ");
        if(this.syn) System.out.print("SYN ");
        if(this.ack) System.out.print("ACK ");
        if(this.fin) System.out.print("FIN ");
        if(this.push) System.out.print("PSH ");
        System.out.print("] (seq=" + this.sequence + ", ack=" + this.acknowledgment + ") len=" + this.payloadSize + " ");
        if(this.handshake && this.syn && !this.ack) System.out.print("- HANDSHAKE SYN");
        if(this.handshake && this.syn && this.ack) System.out.print("- HANDSHAKE SYN ACK");
        if(this.handshake && this.fin && this.ack) System.out.print("- HANDSHAKE FIN ACK");
        if(this.handshake && !this.syn && this.ack && !this.fin) System.out.print("- HANDSHAKE ACK");
        System.out.println("");
        if(this.segment)
            System.out.println("TCP segments reassembled in [" + this.reassembledpacket + "]");
        if(this.ack && this.ackof != -1)
            System.out.println("TCP acknoledgment of [" + this.ackof + "]");
        if(this.payloadSize > 0 && (!this.segment || this.lastsegment)) { 
            System.out.print("Data: ");
            System.out.print(Wiresharklike.byteToAscii(this.payload));
        }
        System.out.println("");
    }

    public boolean getSyn() {
        return this.syn;
    }

    public boolean getFin() {
        return this.fin;
    }

    public boolean getAck() {
        return this.ack;
    }

    public InternetProtocol getIp() {
        return this.ip;
    }

    public int getPortSrc() { 
        return this.source; 
    }
    public int getPortDst() { 
        return this.destination; 
    }

    public long getSequence() {
        return this.sequence;
    }

    public long getAcknowledgment() {
        return this.acknowledgment;
    }

    public void setHandshake() {
        this.handshake = true;
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

    public void setSegment() {
        this.segment = true;
    }

    public void setLastSegment() {
        this.lastsegment = true;
    }

    public void setReassembledPacket(int reassembledpacket) {
        this.reassembledpacket = reassembledpacket;
    }

    public void setAckof(int packet) {
        this.ackof = packet;
    }
}