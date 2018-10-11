
import java.util.Arrays;

public class AddressResolutionProtocol extends Protocol {

    private int opcode;
    private String senderMac;
    private String targetMac;
    private String senderIp;
    private String targetIp;

    public static final byte[] hexaValue = {(byte)0x08, (byte)0x06};
    public static final byte[] request = {(byte)0x00, (byte)0x01};
    public static final byte[] reply = {(byte)0x00, (byte)0x02};

    public AddressResolutionProtocol(byte[] bytes) {
        super(bytes, "ARP");
    }

    public AddressResolutionProtocol() {
        super("ARP");
    }

    public void parse() {
        this.parseOpcode();
        this.parseSenderMac();
        this.parseTargetMac();
        this.parseSenderIp();
        this.parseTargetIp();
    }   

    private void parseOpcode() {
        byte[] opcode = Arrays.copyOfRange(this.data, 6, 8);
        if(Arrays.equals(opcode, AddressResolutionProtocol.request)) {
            this.opcode = 1;
        }
        else if(Arrays.equals(opcode, AddressResolutionProtocol.reply)) {
            this.opcode = 2;
        }
        else {
            this.opcode = 0;
        }
    }
    
    private void parseSenderMac() {
        this.senderMac = Wiresharklike.parseMac(Arrays.copyOfRange(this.data, 8, 14));
    }

    private void parseTargetMac() {
        this.targetMac = Wiresharklike.parseMac(Arrays.copyOfRange(this.data, 18, 24));
    }

    private void parseSenderIp() {
        this.senderIp = Wiresharklike.parseIp(Arrays.copyOfRange(this.data, 14, 18));
    }

    private void parseTargetIp() {
        this.targetIp = Wiresharklike.parseIp(Arrays.copyOfRange(this.data, 24, 28));        
    }

    public void print() {
        super.print();
        if(this.opcode == 1) {
            System.out.println("Who has " + this.targetIp + "? Tell " + this.senderIp);
        }
        else if (this.opcode == 2) {
            System.out.println(this.senderIp + " is at " + this.senderMac);
        }
        else {
            System.out.println("Erreur");
        }
    }
}