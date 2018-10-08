
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
            /* get the pcap file from argument */
            if(args.length == 0) {
                System.out.println("No pcap given.");
                System.exit(-1);
            }
            System.out.print("File: " + args[0] + ", ");
            /* parsing pcap file */
            InputStream is = new FileInputStream(args[0]);
            
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
            System.out.println();
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

    /* util functions */

    public static void reverse(byte[] array) {
        for(int i=0; i<array.length/2; i++) {
            byte tmp = array[i];
            array[i] = array[array.length - i - 1];
            array[array.length - i - 1] = tmp;
        }
    }    

    public static void printBytes(byte[] array) {
        for (byte b : array) {
            System.out.format("%02X ", b);
        }
        System.out.println();
    }

    public static int bytesToInt(byte[] bytes) {
        int v = 0;
        for(int i=0; i<bytes.length; i++) {
            v = v << 8;
            v = v | (bytes[i] & 0xFF);
        }
        return v;
    }
}