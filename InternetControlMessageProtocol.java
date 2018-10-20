
import java.util.Arrays;
import java.lang.NumberFormatException;

public class InternetControlMessageProtocol extends Protocol {
    
    public static final byte[] hexaValue = {(byte)0x01};
    private int type;
    private int id;
    private int sequence;
    private byte[] payload;
    private ICMPStream icmpstream;

    public InternetControlMessageProtocol(Packet packet, byte[] bytes) {
        super(packet, bytes, "ICMP");
    }

    public InternetControlMessageProtocol(Packet packet) {
        super(packet, "ICMP");
    }

    public void parse() {
        this.parseType();
        this.parseId();
        this.parseSequence();
        this.parsePayload();
    }

    private void parseType() {
        this.type = Wiresharklike.bytesToInt(Arrays.copyOfRange(this.data, 0, 1));
    }

    private void parseId() {
        this.id = Wiresharklike.bytesToInt(Arrays.copyOfRange(this.data, 4, 6));
    }

    private void parseSequence() {
        this.sequence = Wiresharklike.bytesToInt(Arrays.copyOfRange(this.data, 6, 8));
    }

    private void parsePayload() {
        this.payload = Arrays.copyOfRange(this.data, 16, this.data.length - 16);
    }

    public void print() {
        super.print();
        if(this.type == 8) {
            System.out.print("Echo (ping) request, reply in [" + this.icmpstream.getReply().getPacket().getUid() + "]");
        }
        else if(this.type == 0) {
            System.out.print("Echo (ping) reply, request in [" + this.icmpstream.getRequest().getPacket().getUid() + "]");
        }
        System.out.println(" (id=" + this.icmpstream.getId() + ", seq=" + this.icmpstream.getSequence() + ")");
        System.out.print("Data: ");
        String pl = "";
        for(int i=0; i<this.payload.length && i<100; i++) {
            System.out.format("%02X ", this.payload[i]);
        }
        System.out.println(pl);
    }

    public void flow() {        
        if(this.type == 8) {
            this.icmpstream = new ICMPStream(this.id, this.sequence);
            this.icmpstream.setRequest(this);
            Wiresharklike.icmpstreams.add(this.icmpstream);
        }
        else if(this.type == 0) {
            this.icmpstream = Wiresharklike.findICMPStream(this.id, this.sequence);
            this.icmpstream.setReply(this);
        }
    }
}