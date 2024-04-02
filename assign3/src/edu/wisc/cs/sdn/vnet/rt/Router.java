package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

public class Router extends Device {
    // Constants for network protocols
    private static final byte[] BROADCAST_MAC = {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
    private static final int RIP_MULTICAST_IP_INT = 0xE0000009; // 224.0.0.9
    private static final short UDP_RIP_PORT = 520;

    // Routing table, ARP cache, and RIP configuration
    private RouteTable routeTable;
    private ArpCache arpCache;
    private boolean useStaticRouteTable;
    private boolean ripEnabled;
    private List<RIPv2Entry> ripEntries;

    public Router(String host, DumpFile logfile, String routeTableFile) {
        super(host, logfile);
        this.routeTable = new RouteTable();
        this.arpCache = new ArpCache();
        this.useStaticRouteTable = (routeTableFile != null);
        this.ripEnabled = !useStaticRouteTable; // Enable RIP if no static route table is provided
        this.ripEntries = new LinkedList<>();
        if (useStaticRouteTable) {
            loadRouteTable(routeTableFile);
        }
    }

    public void startRIP() {
		System.out.println("START RIP");
        // Send RIP request out all interfaces
        // sendRIPRequest();
        handleSendRIPRequest();

        // Add entries to the RIP table for directly reachable subnets
        for (Map.Entry<String, Iface> entry : this.interfaces.entrySet()) {
            Iface iface = entry.getValue();
            int address = iface.getIpAddress();
            int subnetMask = iface.getSubnetMask();

            // Add entry to RIP table
            RIPv2Entry ripEntry = new RIPv2Entry(address, subnetMask, 0, System.currentTimeMillis(), true);
            this.ripEntries.add(ripEntry);
        }

        // Start sending unsolicited RIP responses every 10 seconds
        new Thread(() -> {
            while (ripEnabled) {
                sendUnsolicitedRIPResponse();
                try {
                    Thread.sleep(10000); // 10 seconds interval
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    private void handleSendRIPRequest() {
        // System.out.println("HANDLE SEND REQUEST");

        // Create a RIP request packet
        RIPv2 ripPacket = new RIPv2();
        ripPacket.setCommand(RIPv2.COMMAND_REQUEST);
		ripPacket.setEntries(ripEntries);

        // Send the RIP request packet out of each interface
        for (Map.Entry<String, Iface> entry : this.interfaces.entrySet()) {
            Iface iface = entry.getValue();
            // sendRIPPacket(ripPacket, iface);
            sendRIPRequest(ripPacket, iface);
        }
    }

    private void sendUnsolicitedRIPResponse() {
		// System.out.println("HANDLE SEND UNSOLICITED RESPONSE");

        // Create a RIPv2 response packet
        RIPv2 ripPacket = new RIPv2();
        ripPacket.setCommand(RIPv2.COMMAND_RESPONSE);
        ripPacket.setEntries(ripEntries);

        // Send the RIP response packet out of each interface
        for (Map.Entry<String, Iface> entry : this.interfaces.entrySet()) {
            Iface iface = entry.getValue();
            // sendRIPPacket(ripPacket, iface);
            sendRIPResponse(ripPacket, iface);
        }
    }

    private void sendRIPRequest(RIPv2 ripPayload, Iface inIface) {
        // System.out.println("SEND REQUEST");

        // Create a RIPv2 response packet
        RIPv2 ripResponse = ripPayload; // new RIPv2();
        ripResponse.setCommand(RIPv2.COMMAND_REQUEST);
    
        // Add entries to the request packet for directly reachable subnets
        for (Map.Entry<String, Iface> entry : this.interfaces.entrySet()) {
            Iface iface = entry.getValue();
            int address = iface.getIpAddress();
            int subnetMask = iface.getSubnetMask();
    
            // Add entry to RIP response packet
            RIPv2Entry ripEntry = new RIPv2Entry(address, subnetMask, 0, System.currentTimeMillis(), true);
            ripResponse.addEntry(ripEntry);
        }
    
        // Create Ethernet packet
        Ethernet ethPacket = new Ethernet();
        ethPacket.setEtherType(Ethernet.TYPE_IPv4);
        ethPacket.setSourceMACAddress(inIface.getMacAddress().toBytes());
        ethPacket.setDestinationMACAddress(inIface.getMacAddress().toBytes());
    
        // Create IPv4 packet
        IPv4 ipv4Packet = new IPv4();
        ipv4Packet.setProtocol(IPv4.PROTOCOL_UDP);
        ipv4Packet.setTtl((byte) 1); // Set TTL to 1 to limit scope
        ipv4Packet.setSourceAddress(inIface.getIpAddress());
        ipv4Packet.setDestinationAddress(ipv4Packet.getSourceAddress()); // Source and destination IP are the same
    
        // Create UDP packet
        UDP udpPacket = new UDP();
        udpPacket.setSourcePort(UDP_RIP_PORT);
        udpPacket.setDestinationPort(UDP_RIP_PORT);
        udpPacket.setPayload(ripResponse);
    
        // Set packets as payload for each other
        ipv4Packet.setPayload(udpPacket);
        ethPacket.setPayload(ipv4Packet);
    
        // Send the Ethernet packet out of the interface that received the request
        sendPacket(ethPacket, inIface);
    }

    private void sendRIPResponse(RIPv2 ripPayload, Iface inIface, boolean broadcast) {
		// System.out.println("SEND RESPONSE");

        // Create a RIPv2 response packet
        RIPv2 ripResponse = ripPayload; // new RIPv2();
        ripResponse.setCommand(RIPv2.COMMAND_RESPONSE);
    
        // Add entries to the response packet for directly reachable subnets
        for (Map.Entry<String, Iface> entry : this.interfaces.entrySet()) {
            Iface iface = entry.getValue();
            int address = iface.getIpAddress();
            int subnetMask = iface.getSubnetMask();
    
            // Add entry to RIP response packet
            RIPv2Entry ripEntry = new RIPv2Entry(address, subnetMask, 0, System.currentTimeMillis(), true);
            ripResponse.addEntry(ripEntry);
        }
    
        // Create Ethernet packet
        Ethernet ethPacket = new Ethernet();
        ethPacket.setEtherType(Ethernet.TYPE_IPv4);

        ethPacket.setSourceMACAddress(inIface.getMacAddress().toBytes());
        if(broadcast) {
            ethPacket.setDestinationMACAddress(BROADCAST_MAC);
        } else {
            ethPacket.setDestinationMACAddress(inIface.getMacAddress().toBytes());
        }
    
        // Create IPv4 packet
        IPv4 ipv4Packet = new IPv4();
        ipv4Packet.setProtocol(IPv4.PROTOCOL_UDP);
        ipv4Packet.setTtl((byte) 1); // Set TTL to 1 to limit scope

        ipv4Packet.setSourceAddress(inIface.getIpAddress());
        if(broadcast) {
            ipv4Packet.setDestinationAddress(RIP_MULTICAST_IP_INT);
        } else {
            ipv4Packet.setDestinationAddress(ipv4Packet.getSourceAddress()); // Source and destination IP are the same
        }
        // Create UDP packet
        UDP udpPacket = new UDP();
        udpPacket.setSourcePort(UDP_RIP_PORT);
        udpPacket.setDestinationPort(UDP_RIP_PORT);
        udpPacket.setPayload(ripResponse);
    
        // Set packets as payload for each other
        ipv4Packet.setPayload(udpPacket);
        ethPacket.setPayload(ipv4Packet);
    
        // Send the Ethernet packet out of the interface that received the request
        sendPacket(ethPacket, inIface);
    }
    

    /**
     * @return routing table for the router
     */
    public RouteTable getRouteTable() {
        return this.routeTable;
    }

    /**
     * Handle an Ethernet packet received on a specific interface.
     * 
     * @param etherPacket the Ethernet packet that was received
     * @param inIface     the interface on which the packet was received
     */

    public void handlePacket(Ethernet etherPacket, Iface inIface) {
        System.out.println("*** -> Router Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));

        // Check if the Ethernet frame contains an IPv4 packet
        if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
            return; // Drop the packet if it's not IPv4
        }

        // Extract the IPv4 packet
        IPv4 ipv4Packet = (IPv4) etherPacket.getPayload();

        // Check if the packet is UDP and RIP
        if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_UDP) {
            UDP udpPacket = (UDP) ipv4Packet.getPayload();
            if (udpPacket.getDestinationPort() == UDP_RIP_PORT) {
                RIPv2 ripPayload = (RIPv2) udpPacket.getPayload();
                if (ripPayload.getCommand() == RIPv2.COMMAND_REQUEST) {
                    // Handle RIP request
                    sendRIPResponse(ripPayload, inIface);
                } else if (ripPayload.getCommand() == RIPv2.COMMAND_RESPONSE) {
                    // Handle RIP response
                    handleRIPPacket(ripPayload, inIface);
                }
                System.out.println("*** -> Router Sent RIPv2 Packet: " +
                    etherPacket.toString().replace("\n", "\n\t"));
                return;
            }
        }
        System.out.println("241--HANDLE OF NORMAL PACKET");

        System.out.println("243--CHECKSUM CHECK");
        // Verify the checksum of the IPv4 packet
        if (!verifyChecksum(ipv4Packet)) {
            return; // Drop the packet if the checksum is incorrect
        }

        // Decrement the TTL of the IPv4 packet
        ipv4Packet.setTtl((byte) (ipv4Packet.getTtl() - 1));

        System.out.println("252--TTL CHECK");
        // Drop the packet if the TTL is 0
        if (ipv4Packet.getTtl() == 0) {
            return;
        }

        // Determine whether the packet is destined for one of the router's interfaces
        for (Map.Entry<String, Iface> iface : this.interfaces.entrySet()) {
            System.out.println("260--DESTINED FOR ROUTER CHECK");
            // Drop packet if it matches a router interface IP
            if (iface.getValue().getIpAddress() == ipv4Packet.getDestinationAddress())
                return;
        }

        // Lookup the RouteEntry
        RouteEntry routeEntry = this.routeTable.lookup(ipv4Packet.getDestinationAddress());

        System.out.println("269--NOT IN ROUTE TABLE CHECK");
        // Drop the packet if no matching entry found
        if (routeEntry == null) {
            return;
        }

        // Lookup the next-hop IP address
        int nextHopIp = routeEntry.getGatewayAddress();
        if (nextHopIp == 0) {
            nextHopIp = ipv4Packet.getDestinationAddress();
        }

        // Lookup MAC address corresponding to next-hop IP address
        MACAddress nextHopMac = this.arpCache.lookup(nextHopIp).getMac();
        System.out.println("283--NOT IN ARP CACHE CHECK");
        if (nextHopMac == null) {
            return; // Drop the packet if MAC address not found
        }

        // Update Ethernet header
        etherPacket.setDestinationMACAddress(nextHopMac.toBytes());
        etherPacket.setSourceMACAddress(routeEntry.getInterface().getMacAddress().toBytes());

        ipv4Packet.setChecksum((short)0);
        ipv4Packet.serialize();

        System.out.println("299--SENDING REGULAR PACKET");
        // Send the packet out the correct interface
        this.sendPacket(etherPacket, routeEntry.getInterface());

        System.out.println("*** -> Router Sent IPv4 Packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
    }

    private void handleRIPPacket(RIPv2 ripPacket, Iface inIface) {
        // Update RIP entries based on received RIP packet
        List<RIPv2Entry> receivedEntries = ripPacket.getEntries();
        for (RIPv2Entry receivedEntry : receivedEntries) {
            // TODO is the below correct? -- address when doing time and vacating
            receivedEntry.updateTime(); // Update timestamp

            RIPv2Entry existingEntry = findRIPEntry(receivedEntry);
            if (existingEntry == null) {
                ripEntries.add(receivedEntry);
            } else if (existingEntry.getMetric() > receivedEntry.getMetric() + 1) {
                existingEntry.setMetric(receivedEntry.getMetric() + 1);
            }
        }
    }

    private RIPv2Entry findRIPEntry(RIPv2Entry entry) {
        for (RIPv2Entry ripEntry : ripEntries) {
            if (ripEntry.getAddress() == entry.getAddress() && ripEntry.getSubnetMask() == entry.getSubnetMask()) {
                return ripEntry;
            }
        }
        return null;
    }

    /**
     * Load a new routing table from a file.
     * 
     * @param routeTableFile the name of the file containing the routing table
     */
    public void loadRouteTable(String routeTableFile) {
        if (!routeTable.load(routeTableFile, this)) {
            System.err.println("Error setting up routing table from file "
                    + routeTableFile);
            System.exit(1);
        }

        System.out.println("Loaded static route table");
        System.out.println("-------------------------------------------------");
        System.out.print(this.routeTable.toString());
        System.out.println("-------------------------------------------------");
    }

    /**
     * Load a new ARP cache from a file.
     * 
     * @param arpCacheFile the name of the file containing the ARP cache
     */
    public void loadArpCache(String arpCacheFile) {
        if (!arpCache.load(arpCacheFile)) {
            System.err.println("Error setting up ARP cache from file "
                    + arpCacheFile);
            System.exit(1);
        }

        System.out.println("Loaded static ARP cache");
        System.out.println("----------------------------------");
        System.out.print(this.arpCache.toString());
        System.out.println("----------------------------------");
    }

    private boolean verifyChecksum(IPv4 ipv4Packet) {
        int headerLength = ipv4Packet.getHeaderLength();
        byte[] headerData = ipv4Packet.serialize();
        int checksum = ipv4Packet.getChecksum();

        // Zero out the checksum field
        headerData[10] = 0;
        headerData[11] = 0;

        // Compute the checksum
        int accumulation = 0;
        for (int i = 0; i < headerLength * 2; ++i) {
            accumulation += (0xff & headerData[i * 2]) << 8 | (0xff & headerData[i * 2 + 1]);
        }

        accumulation = ((accumulation >> 16) & 0xffff) + (accumulation & 0xffff);
        if ((accumulation & 0x10000) != 0) {
            accumulation = (accumulation & 0xffff) + 1; // Add carry bit
        }
        short computedChecksum = (short) (~accumulation & 0xffff);

        // Compare computed checksum with packet's checksum
        return computedChecksum == checksum;
    }
}
