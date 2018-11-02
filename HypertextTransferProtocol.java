
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.io.ByteArrayInputStream;
import java.util.zip.GZIPInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class HypertextTransferProtocol extends Protocol {

    private int headerSize;
    private int payloadSize;

    private boolean response;
    private boolean request;

    private ArrayList<String> headers;
    private String content = "";

    private String http;
    private String method;
    private int status;
    private String message;
    private String host;
    private String path;
    private Map<String, String> post_params = null;

    private String content_type = "";
    private String content_length = "";
    private String user_agent = "";
    private String content_encoding = "";

    public HypertextTransferProtocol(Packet packet, byte[] bytes) {
        super(packet, bytes, "HTTP");
    }

    public HypertextTransferProtocol(Packet packet) {
        super(packet, "HTTP");
    }

    public void parse() {
        this.headers = new ArrayList<String>();
        String ascii = Wiresharklike.byteToAscii(this.data);

        String[] lines = ascii.split("\n");
        int c = 0;
        while(true) {
            this.headers.add(lines[c]);
            if(lines[c++].equals(""))
                break;
            else if(c >= lines.length)
                break; 
        }

        while(c < lines.length) {
            this.content += lines[c] + "\n";
            c++;
        }

        for(int i = 0; i<this.headers.size(); i++) {
            if(i == 0) {
                String[] words = this.headers.get(0).split(" ");
                if(ProtocolAnalysis.findValueIn(ProtocolAnalysis.http_versions, words[0])) {
                    this.response = true;
                    this.http = words[0];

                    this.status = Integer.parseInt(words[1]);
                    switch(this.status) {
                        case 200:
                            this.message = "OK";
                            break;
                        case 301:
                            this.message = "Moved Permanently";
                            break;
                        case 400:
                            this.message = "Bad Request";
                            break;
                        case 401:
                            this.message = "Unauthorized";
                            break;
                        case 403:
                            this.message = "Forbidden";
                        break;
                        case 404:
                            this.message = "Not Found";
                            break;
                        case 405:
                            this.message = "Method Not Allowed";
                            break;
                        case 500:
                            this.message = "Internal Server Error";
                            break;
                        case 501:
                            this.message = "Not Implemented";
                            break;
                        case 503:
                            this.message = "Service Unavailable";
                            break;
                    }
                }
                else if(ProtocolAnalysis.findValueIn(ProtocolAnalysis.http_methods, words[0])) {
                    this.request = true;
                    this.method = words[0];
                    this.path = words[1];
                    this.http = words[2];
                }
            }
            else {
                String[] words = this.headers.get(i).split(": ");
                switch(words[0]) {
                    case "Content-Type":
                        this.content_type = words[1];
                        break;
                    case "Content-Encoding":
                        this.content_encoding = words[1];
                        break;
                    case "Content-Length":
                        this.content_length = words[1];
                        break;
                    case "Host":
                        this.host = words[1];
                        break;
                    case "User-Agent":
                        this.user_agent = words[1];
                        break;
                }
            }
        }

        if(this.method != null && this.method.equals("POST")) {
            this.post_params = new HashMap<String, String>();
            String[] params = this.content.replace("\n", "").split("&");
            for(String param : params) {
                String[] kv = param.split("=");
                this.post_params.put(kv[0], kv[1]);
            }
        }

        if(this.content_encoding.equals("gzip")) {
            try {
                byte[] content_byte = Arrays.copyOfRange(this.data, this.data.length-Integer.parseInt(this.content_length), this.data.length);
                
                ByteArrayInputStream bytein = new java.io.ByteArrayInputStream(content_byte);
                GZIPInputStream gzin = new java.util.zip.GZIPInputStream(bytein);
                ByteArrayOutputStream byteout = new java.io.ByteArrayOutputStream();

                int res = 0;
                byte buf[] = new byte[1024];
                while(res >= 0) {
                    res = gzin.read(buf, 0, buf.length);
                    if (res > 0) {
                        byteout.write(buf, 0, res);
                    }
                }
                byte uncompressed[] = byteout.toByteArray();
                this.content = Wiresharklike.byteToAscii(uncompressed);

            } catch(IOException exception) {
                this.content = "IOException can't uncompress the content (GZIP).";
            }
        }
    }

    public void print() {
        if(this.request) 
            System.out.print(this.http + ": " + this.method + " " + this.host + this.path + ", user-agent=" + this.user_agent);
        if(this.response) {
            System.out.print(this.http + ": " + this.status + " " + this.message + ", type=" + this.content_type + ", len=" + this.content_length);
            if(this.content_encoding != "") System.out.print(", encoding=" + this.content_encoding);
        }
        System.out.println("");
        if(this.method != null && this.method.equals("POST") && this.post_params != null) {
            System.out.println("POST parameters:");
            for(Map.Entry<String, String> entry : this.post_params.entrySet()) 
                System.out.println(entry.getKey() + " = " + entry.getValue());
        }
        else if(this.content != "") System.out.println("\n"+this.content);
    }
}