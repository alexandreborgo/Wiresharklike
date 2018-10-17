public class ICMPStream {
    
    private int id;
    private int sequence;
    private InternetControlMessageProtocol request;
    private InternetControlMessageProtocol reply;
    
    public ICMPStream(int id, int sequence) {
        this.id = id;
        this.sequence = sequence;
    }

    public void setRequest(InternetControlMessageProtocol request) {
        this.request = request;
    }
    
    public void setReply(InternetControlMessageProtocol reply) {
        this.reply = reply;
    }
    
    public InternetControlMessageProtocol getRequest() {
        return this.request;
    }
    
    public InternetControlMessageProtocol getReply() {
        return this.reply;
    }

    public int getId() {
        return this.id;
    }

    public int getSequence() {
        return this.sequence;
    }
}