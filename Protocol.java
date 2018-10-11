
public class Protocol {

    public byte[] data;
    public String name;

    public Protocol(String name) {
        this.name = name;
    }

    public Protocol(byte[] data, String name) {
        this.data = data;
        this.name = name;
    }

    public void parse() {

    }

    public void setData(byte[] bytes) {
        this.data = bytes;
    }

    public void print() {
        System.out.print(this.name + ": ");
    }
}