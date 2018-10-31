
public class Protocol {

    public byte[] data;
    public String name;
    public Packet packet;

    public Protocol(Packet packet, String name) {
        this.name = name;
        if(packet != null) {
            this.packet = packet;
            this.packet.protocols.add(this);
        }
    }

    public Protocol(Packet packet, byte[] data, String name) {
        this.data = data;
        this.name = name;
        this.packet = packet;
        this.packet.protocols.add(this);
    }

    public void setData(byte[] bytes) {
        this.data = bytes;
    }

    public void print() {
        System.out.print(this.name + ": ");
    }

    public Packet getPacket() {
        return this.packet;
    }

    public byte[] getData() {
        return this.data;
    }

    public void parse() {}
    public void flow() {}
}