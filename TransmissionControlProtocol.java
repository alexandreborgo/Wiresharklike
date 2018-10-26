
import java.util.Arrays;

public class TransmissionControlProtocol extends Protocol {

    private Protocol protocol;
    private int source;
    private int destination;

    private boolean syn = false;
    private boolean ack = false;
    private boolean reset = false;
    private boolean fin = false;
    private boolean push = false;
    private boolean urgent = false;
    private boolean echo = false;
    private boolean congest = false;
    private boolean nonce = false;

    private long sequence;
    private long acknowledgment;

    public static final byte[] hexaValue = {(byte)0x06};

    public TransmissionControlProtocol(Packet packet, byte[] bytes) {
        super(packet, bytes, "TCP");
    }

    public TransmissionControlProtocol(Packet packet) {
        super(packet, "TCP");
    }

    public void parse() {
        this.parseSource();
        this.parseDestination();
        this.parseFlags();
        this.parseAcknowledgment();
        this.parseSequence();
        this.parseProtocol();
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

    private void parseFlags() {
        int[] flags1 = Wiresharklike.binToBits(Arrays.copyOfRange(this.data, 12, 13)[0]);
        int[] flags2 = Wiresharklike.binToBits(Arrays.copyOfRange(this.data, 13, 14)[0]);

        if(flags2[7] == 1) this.fin = true;
        if(flags2[6] == 1) this.syn = true;
        if(flags2[5] == 1)  this.reset = true;
        if(flags2[4] == 1)  this.push = true;
        if(flags2[3] == 1)  this.ack = true;
        if(flags2[2] == 1)  this.urgent = true;
        if(flags2[1] == 1)  this.echo = true;
        if(flags2[0] == 1)  this.congest = true;
        if(flags1[7] == 1)  this.nonce = true;
    }

    private void parseSequence() {
        this.sequence = Wiresharklike.bytesToLong(Arrays.copyOfRange(this.data, 4, 8));
    }

    private void parseAcknowledgment() {
        this.acknowledgment = Wiresharklike.bytesToLong(Arrays.copyOfRange(this.data, 8, 12));
    }

    public void print() {
        super.print();
        System.out.print(this.source + " -> " + this.destination + " [ ");
        if(this.syn) System.out.print("SYN ");
        if(this.ack) System.out.print("ACK ");
        if(this.fin) System.out.print("FIN ");
        if(this.push) System.out.print("PSH ");
        System.out.println("] (seq=" + this.sequence + ", ack=" + this.acknowledgment + ").");
    }
}