
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.io.FileNotFoundException;
import java.io.IOException;

public class Wiresharklike {

    public static ArrayList<ICMPStream> icmpstreams = new ArrayList<ICMPStream>();

    public static ICMPStream findICMPStream(int id, int sequence) {
        for(ICMPStream is : Wiresharklike.icmpstreams) {
            if(id == is.getId() && sequence == is.getSequence()) {
                return is;
            }
        }
        System.out.println("error");
        return null;
    }
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
                packet = new Packet(packets.size(), packetHeaderBuffer);
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
            }
            /* rebuild flow */
            for(int i=0; i<packets.size(); i++) {
                packets.get(i).flow();
            }
            /* print */
            for(int i=0; i<packets.size(); i++) {
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

    /* reverse an array */
    public static void reverse(byte[] array) {
        for(int i=0; i<array.length/2; i++) {
            byte tmp = array[i];
            array[i] = array[array.length - i - 1];
            array[array.length - i - 1] = tmp;
        }
    }    

    /* print a byte array in hexadecimal */
    public static void printBytes(byte[] array) {
        for (byte b : array) {
            System.out.format("%02X ", b);
        }
        System.out.println();
    }

    /* transform an array of bytes into an int */
    public static int bytesToInt(byte[] bytes) {
        int v = 0;
        for(int i=0; i<bytes.length; i++) {
            v = v << 8;
            v = v | (bytes[i] & 0xFF);
        }
        return v;
    }

    /* transform a byte into an array of int */
    public static int[] toBits(byte B) {
        int[] bits = new int[8];
        for(int i=0; i<8; i++) {
            bits[7-i] = (B >> i) & 1;
        }
        return bits;
    }

    /* transform an array byte into an array of int */
    public static int[] arrayToBits(byte[] B) {
        int[] bits = new int[B.length * 8];
        for(int j=0; j<B.length; j++) {
            for(int i=0; i<8; i++) {
                bits[7-i] = (B[j] >> i) & 1;
            }
        }
        return bits;
    }

    /* transform an array of int (bits) into an int */
    public static int restoreInt(int[] bits) {
        int v = 0;
        for(int i=0; i<bits.length; i++) {
            v = (v << 1) | bits[i];
        }
        return v;
    }

    /* return @Mac in String from byte[] @Mac */
    public static String parseMac(byte[] bytes) {        
        String mac = "";
        for(int i=0; i<6; i++) {
            mac += String.format("%02X:", bytes[i]);
        }
        mac = mac.substring(0, mac.length() - 1);
        return mac;
    }

    /* return @IP in String from byte[] @IP */
    public static String parseIp(byte[] bytes) {
        String ip = "";
        for(int i=0; i<4; i++) {
            ip += Integer.parseInt(String.format("%X", bytes[i]), 16) + ".";
        }
        ip = ip.substring(0, ip.length() - 1);
        return ip;
    }

    /* return Protocol from byte[] type */
    public static Protocol parseProtocolType(Packet packet, byte[] bytes) {
        Protocol protocol = null;
        if(Arrays.equals(bytes, InternetProtocol.hexaValue)) {
            protocol = new InternetProtocol(packet);
        }
        else if(Arrays.equals(bytes, AddressResolutionProtocol.hexaValue)) {
            protocol = new AddressResolutionProtocol(packet);
        }
        else if(Arrays.equals(bytes, TransmissionControlProtocol.hexaValue)) {
            protocol = new TransmissionControlProtocol(packet);
        }
        else if(Arrays.equals(bytes, InternetControlMessageProtocol.hexaValue)) {
            protocol = new InternetControlMessageProtocol(packet);
        }
        else {
            protocol = new UnknownProtocol(packet);
        }
        return protocol;
    }
}