
public class UnknownProtocol extends Protocol {

    public UnknownProtocol(Packet packet) {
        super(packet, "Unknown");
    }

    public void print() {
        System.out.println("Unknown protocol");
    }
}