
public class ProtocolAnalysis {

    private byte[] data;
    private String ascii;
    private int port_src;
    private int port_dst;
    private Packet packet;

    public static final String[] http_versions = {"HTTP/1.1", "HTTP/1.0", "HTTP/0.9"};
    public static final String[] http_methods = {"GET", "HEAD", "POST", "OPTIONS", "CONNECT", "TRACE", "PUT", "PATCH", "DELETE"};

    public ProtocolAnalysis(Packet packet, int port_src, int port_dst, byte[] data) {
        this.data = data;
        this.port_src = port_src;
        this.port_dst = port_dst;
        this.packet = packet;
    }

    public Protocol analysis() {
        Protocol protocol = null;
        if(this.port_src == 80 || this.port_dst == 80) {
            if(this.tryHTTP()) {
                protocol = new HypertextTransferProtocol(this.packet, this.data);
            }
        }
        else {
            protocol = this.tryALL();
        }
        
        if(protocol == null) {
            protocol = this.tryALL();
        }
        
        return protocol;
    }

    public Protocol tryALL() {
        if(this.tryHTTP()) {
           return new HypertextTransferProtocol(this.packet, this.data);
        }
        return new UnknownProtocol(this.packet);
    }

    public boolean tryHTTP() {
        this.ascii = Wiresharklike.byteToAscii(this.data);
        String[] lines = this.ascii.split("\n");

        if(lines.length > 1) {
            String[] words = this.ascii.split(" ");
            if(words.length > 1) {
                if( ProtocolAnalysis.findValueIn(ProtocolAnalysis.http_versions, words[0]) ||
                    ProtocolAnalysis.findValueIn(ProtocolAnalysis.http_methods, words[0])) {
                    return true;
                }
            }
        }

        return false;
    }

    public static boolean findValueIn(String[] keywords, String word) {
        for(String keyword : keywords)
            if(keyword.equals(word))
                return true;
        return false;
    }
}