
import java.util.Arrays;
import java.lang.NumberFormatException;

public class InternetControlMessageProtocol extends Protocol {
    
    public static final byte[] hexaValue = {(byte)0x01};
    private int type = -1;
    private int id;
    private int packetrequest = -1;
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
        this.parsePayload();
        if(this.type == 8 || this.type == 0) {
            this.parseId();
            this.parseSequence();
            ICMPStream is = Wiresharklike.findICMPStream(this.id, this.sequence);

            if(is == null) {
                is = new ICMPStream(this.id, this.sequence);
                Wiresharklike.icmpstreams.add(is);
            }
            this.icmpstream = is;

            if(this.type == 8)       
                this.icmpstream.setRequest(this);
            else if(this.type == 0)
                this.icmpstream.setReply(this);
        }
        else if(this.type == 11 || this.type == 3) {
            // contain packet with ip as protocol
            Packet packet = new Packet(0, null);
            packet.setData(this.payload);
            packet.parseIp();
            int id = packet.ip.getId();
            for(int i=0; i<this.packet.getUid(); i++) {
                if(Wiresharklike.packets.get(i).ip.getId() == id) {
                    this.packetrequest = i;
                    break;
                }
            }
        }
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
        this.payload = Arrays.copyOfRange(this.data, 8, this.data.length);
    }

    public void print() {
        super.print();
        if(this.type == 8) {
            System.out.print("Echo (ping) request, reply in [" + this.icmpstream.getReply().getPacket().getUid() + "]");
            System.out.println(" (id=" + this.id + ", seq=" + this.sequence + ")");
        }
        else if(this.type == 0) {
            System.out.print("Echo (ping) reply, request in [" + this.icmpstream.getRequest().getPacket().getUid() + "]");
            System.out.println(" (id=" + this.id + ", seq=" + this.sequence + ")");
        }
        else if(this.type == 11)
            System.out.println("Time to live exceeded, reponse to [" + this.packetrequest + "]");
        else if(this.type == 3)
            System.out.println("Destination unreachable, reponse to [" + this.packetrequest + "]");

        if(this.type == 8 || this.type == 0) {
            System.out.print("Data: ");
            System.out.print(Wiresharklike.byteToAscii(this.payload));
        }
    }
}