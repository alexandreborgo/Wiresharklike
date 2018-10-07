
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.io.FileNotFoundException;
import java.io.IOException;

public class Wiresharklike {
    public static void main(String[] args) {

        final int globalHeaderSize = 24;
        final int packetHeaderSize = 16;

        try {
            /* parsing pcap file */
            InputStream is = new FileInputStream("C:/Users/Alexandre/Documents/Programmation/wiresharklike/http.pcap");
            
            byte[] globalHeaderBuffer = new byte[globalHeaderSize];
            if(is.read(globalHeaderBuffer) == globalHeaderSize) {
                GlobalHeader globalHeader = new GlobalHeader(globalHeaderBuffer);
            }
            
            ArrayList<Packet> packets = new ArrayList<Packet>();
            byte[] packetHeaderBuffer = new byte[packetHeaderSize];
            Packet packet;
            byte[] packetDataBuffer;
            while(is.read(packetHeaderBuffer) == packetHeaderSize) {
                packet = new Packet(packetHeaderBuffer);
                packetDataBuffer = new byte[packet.getDataSize()];
                is.read(packetDataBuffer);
                packet.setData(packetDataBuffer);
                packets.add(packet);
            }

            System.out.println(packets.size() + " packets found.");
            is.close();

            /* parsing packets */
            for(int i=0; i<packets.size(); i++) {
                packets.get(i).parse();
                packets.get(i).print();
            }
        }
        catch(FileNotFoundException exception) {
            System.out.println("File not found.");
            exception.printStackTrace();
            System.exit(-1);
        }
        catch(IOException exception) {
            System.out.println("Reading error.");
            exception.printStackTrace();
            System.exit(-1);
        }
        catch(PcapException exception) {
            exception.printStackTrace();
            System.exit(-1);
        }
    }
}