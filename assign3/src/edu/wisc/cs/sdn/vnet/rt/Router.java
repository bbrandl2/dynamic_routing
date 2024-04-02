package edu.wisc.cs.sdn.vnet.rt;

import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
	public static final int BROADCAST_REQ = 0;
	public static final int BROADCAST_RES = 1;
	public static final int UNICAST_REQ = 2;
	public static final int UNICAST_RES = 3;

    private RouteTable routeTable;
    private ArpCache arpCache;
    private boolean isStatic;
    private RIPv2 ripTable;

	/**
	 * Creates a router for a specific host.
	 * 
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile) {
        super(host, logfile);
        this.routeTable = new RouteTable();
        this.arpCache = new ArpCache();
        this.ripTable = new RIPv2();
	}

	public void setStatic(boolean b){
        this.isStatic = b;
    }
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable() {
		return this.routeTable;
	}

	/**
	 * Load a new routing table from a file.
	 * 
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile) {
		if (isStatic) {
            if (!routeTable.load(routeTableFile, this)) {
                System.err.println("Error setting up routing table from file " + routeTableFile);
                System.exit(1);
            }
            System.out.println("Loaded static route table");
            System.out.println("-------------------------------------------------");
            System.out.print(this.routeTable.toString());
            System.out.println("-------------------------------------------------");
        } else {    
            for (Map.Entry<String, Iface> iface : this.interfaces.entrySet()) {
                ripTable.addEntry(new RIPv2Entry(iface.getValue().getIpAddress(), iface.getValue().getSubnetMask(), 0, System.currentTimeMillis(), true));
            }
            System.out.println("Loaded dynamic route table");
            System.out.println("-------------------------------------------------");
            System.out.print(this.ripTable.toString());
            System.out.println("-------------------------------------------------");
        }
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

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * 
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface     the interface on which the packet was received
	 */

	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		// Print a message indicating that the router received a packet
		System.out.println("*** -> Router Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));
		System.out.println("110");
		// Check if the packet is not IPv4, drop it if not
		System.out.println(etherPacket.getEtherType());
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}
		System.out.println("115");
		// Extract the IPv4 packet from the Ethernet frame
		IPv4 ipv4Packet = (IPv4) etherPacket.getPayload();
	
		// Verify the checksum of the IPv4 packet, drop it if the checksum is incorrect
		if (!verifyChecksum(ipv4Packet)) {
			return;
		}
		System.out.println("123");
		// Decrement the TTL of the IPv4 packet
		ipv4Packet.setTtl((byte) (ipv4Packet.getTtl() - 1));
	
		// Drop the packet if the TTL is 0
		if (ipv4Packet.getTtl() == 0) {
			return;
		}
		System.out.println("131");
		// Handle the packet based on the routing type (static or dynamic)
		if (this.isStatic) {
			handleStaticRouting(etherPacket, ipv4Packet);
		} else {
			handleDynamicRouting(etherPacket, ipv4Packet);
		}

		// Print a message indicating that the router sent a packet
		System.out.println("*** -> Router Sent packet: " +
				etherPacket.toString().replace("\n", "\n\t"));
	}
	
	// Helper function to handle static routing for IPv4 packets
	private void handleStaticRouting(Ethernet etherPacket, IPv4 ipv4Packet) {
		// Drop the packet if it's destined for one of the router's interfaces
		System.out.println("147");
		for (Map.Entry<String, Iface> iface : this.interfaces.entrySet()) {
			if (iface.getValue().getIpAddress() == ipv4Packet.getDestinationAddress())
				return;
		}
		System.out.println("152");
		// Lookup the route entry in the routing table
		RouteEntry routeEntry = this.routeTable.lookup(ipv4Packet.getDestinationAddress());
		
		// Drop the packet if no matching entry found in the routing table
		if (routeEntry == null) {
			return;
		}
		System.out.println("160");
		// Determine the next-hop IP address
		int nextHopIp = routeEntry.getGatewayAddress();
		if (nextHopIp == 0) {
			nextHopIp = ipv4Packet.getDestinationAddress();
		}
	
		// Lookup the MAC address corresponding to the next-hop IP address in the ARP cache
		MACAddress nextHopMac = this.arpCache.lookup(nextHopIp).getMac();
		if (nextHopMac == null) {
			return;
		}
		System.out.println("172");
		// Update the Ethernet header with the MAC addresses
		etherPacket.setDestinationMACAddress(nextHopMac.toBytes());
		etherPacket.setSourceMACAddress(routeEntry.getInterface().getMacAddress().toBytes());
	
		// Recalculate the checksum of the IPv4 packet and serialize it
		ipv4Packet.setChecksum((short)0);
		ipv4Packet.serialize();
	
		// Send the packet out the correct interface
		this.sendPacket(etherPacket, routeEntry.getInterface());
	}
	
	// Helper function to handle dynamic routing for IPv4 packets
	private void handleDynamicRouting(Ethernet etherPacket, IPv4 ipv4Packet) {
		if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_UDP && (((UDP) ipv4Packet.getPayload()).getDestinationPort() == 520)) {
			// Handle RIP packets
			handleRIPPacket(etherPacket, ipv4Packet);
		} else {
			// Handle non-RIP packets
			handleNonRIPPacket(etherPacket, ipv4Packet);
		}
	}
	
	// Helper function to handle RIP packets
	private void handleRIPPacket(Ethernet etherPacket, IPv4 ipv4Packet) {
		// Extract the RIP packet from the UDP payload
		UDP udpPacket = (UDP) ipv4Packet.getPayload();
		RIPv2 ripPacket = (RIPv2) udpPacket.getPayload();
		
		// Check if the RIP packet is a req or res
		if (ripPacket.getCommand() == RIPv2.COMMAND_REQUEST) {
			Iface outIface = getOutgoingIface(etherPacket);
			// send the response on the same interface as the request
			System.out.println("206");
			sendRIPPacket(UNICAST_RES, etherPacket, ipv4Packet.getSourceAddress(), outIface);
		} else if (ripPacket.getCommand() == RIPv2.COMMAND_RESPONSE) {
			// Process each entry in the RIP packet
			System.out.println("210");
			for (RIPv2Entry ripEntry : ripPacket.getEntries()) {
				int addr = ripEntry.getAddress();
				RIPv2Entry thisEntry = this.ripTable.lookup(addr);
		
				if (thisEntry == null) {
					// Add a new entry to the RIP table if not already present
					RIPv2Entry newEntry = new RIPv2Entry(addr, ripEntry.getSubnetMask(), ripEntry.getMetric() + 1, System.currentTimeMillis(), false);
					ripTable.addEntry(newEntry);
				} else {
					// Update existing entry if a shorter path is found
					System.out.println("221");
					if ((ripEntry.getMetric() + 1) < thisEntry.getMetric()) {
						thisEntry.setNextHopAddress(addr);
						thisEntry.updateTime();
					} else if ((thisEntry.getMetric() + 1) < ripEntry.getMetric()) {
						Iface out = getOutgoingIface(etherPacket);
						this.sendRIPPacket(UNICAST_RES, etherPacket, ipv4Packet.getSourceAddress(), out);
					}
				}
			}
		}
		System.out.println("232");
	}
	
	// Helper function to handle non-RIP packets
	private void handleNonRIPPacket(Ethernet etherPacket, IPv4 ipv4Packet) {
		// Lookup the entry corresponding to the destination IP address in the RIP table
		RIPv2Entry RIProuteEntry = this.ripTable.lookup(ipv4Packet.getDestinationAddress());
	
		// Drop the packet if no matching entry found in the RIP table
		if (RIProuteEntry == null) {
			return;
		}
		System.out.println("224");
		// Determine the next-hop IP address
		int nextHopIp = RIProuteEntry.getNextHopAddress();
	
		// Lookup the MAC address corresponding to the next-hop IP address in the ARP cache
		MACAddress nextHopMac = this.arpCache.lookup(nextHopIp).getMac();
		if (nextHopMac == null) {
			return;
		}
		System.out.println("253");
		Iface outIface = null;
		// Get the outgoing interface based on the next hop IP address of the packet
		for (Iface iface : this.interfaces.values()) {
			if ((iface.getSubnetMask() & iface.getIpAddress()) == (iface.getSubnetMask() & nextHopIp)) {
				outIface = iface;
			}
		}
		if (outIface == null) {
			System.out.println("Packet dropped.\n");
			return;
		}
		System.out.println("265");
		// Update the Ethernet header with the MAC addresses
		etherPacket.setDestinationMACAddress(nextHopMac.toBytes());
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());
	
		// Serialize the IPv4 packet
		ipv4Packet.serialize();
	
		// Send the packet out the correct interface
		this.sendPacket(etherPacket, outIface);
	}

	private Iface getOutgoingIface(Ethernet etherPacket){
		for (Map.Entry<String, Iface> iface : this.interfaces.entrySet()) {
			if (iface.getValue().getMacAddress() == etherPacket.getDestinationMAC()){
				return (Iface) iface;
			}
		}
		return null;
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

	public void sendRIPPacket(int directive, Ethernet etherPacket, int ipAddr, Iface outIface){
		if (directive == BROADCAST_REQ || directive == UNICAST_REQ) {
			ripTable.setCommand((byte) 1);	// COMMAND_REQUEST
		} else if (directive == BROADCAST_RES || directive == UNICAST_RES)	{
			ripTable.setCommand((byte) 2);  // COMMAND_RESPONSE
		}

		if (directive == BROADCAST_REQ || directive == BROADCAST_RES) {	// Send RIP response out of all interfaces, called every 10 seconds
			if (etherPacket == null || outIface == null) System.out.println("NULL 314");
			for (Map.Entry<String, Iface> iface : this.interfaces.entrySet()) {
				// Create Ethernet packet
				Ethernet etherpacket = new Ethernet();
				etherpacket.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
				etherpacket.setEtherType(Ethernet.TYPE_IPv4);
				etherpacket.setSourceMACAddress(iface.getValue().getMacAddress().toString());
	
				// Create IPv4 packet, add as Ether payload
				IPv4 ipPacket = new IPv4();
				ipPacket.setProtocol(IPv4.PROTOCOL_UDP);
				ipPacket.setSourceAddress(iface.getValue().getIpAddress());
				ipPacket.setDestinationAddress("224.0.0.9");
				ipPacket.setParent(etherpacket);
	
				etherpacket.setPayload(ipPacket);
	
				// Create UDP packet, add as IP payload
				UDP udpPacket = new UDP();
				udpPacket.setDestinationPort((short) 520);
				udpPacket.setSourcePort((short) 520);
				udpPacket.setParent(ipPacket);
	
				ipPacket.setPayload(udpPacket);
	
				udpPacket.setPayload(ripTable);
	
				// Send packet out of current interface
				this.sendPacket(etherpacket, iface.getValue());
			}
		}
		else if (directive == UNICAST_REQ || directive == UNICAST_RES) {	// Send directed response
			if (etherPacket == null || outIface == null) System.out.println("NULL 346");
			Ethernet etherpacket = new Ethernet();
			etherpacket.setDestinationMACAddress(etherPacket.getSourceMACAddress());
			etherpacket.setEtherType(Ethernet.TYPE_IPv4);
			etherpacket.setSourceMACAddress(outIface.getMacAddress().toString());

			// Create IPv4 packet, add as Ether payload
			IPv4 ipPacket = new IPv4();
			ipPacket.setProtocol(IPv4.PROTOCOL_UDP);
			ipPacket.setSourceAddress(outIface.getIpAddress());
			ipPacket.setDestinationAddress(ipAddr);
			ipPacket.setParent(etherpacket);

			etherpacket.setPayload(ipPacket);

			// Create UDP packet, add as IP payload
			UDP udpPacket = new UDP();
			udpPacket.setDestinationPort((short) 520);
			udpPacket.setSourcePort((short) 520);
			udpPacket.setParent(ipPacket);

			ipPacket.setPayload(udpPacket);

			udpPacket.setPayload(ripTable);

			// Send packet out of current interface
			this.sendPacket(etherpacket, outIface);
		}
		
	}

	public void checkEntryTimes(){
		for (RIPv2Entry entry : this.ripTable.getEntries()){
			if (System.currentTimeMillis() - entry.getTime() >= 30000){
				this.ripTable.getEntries().remove(entry);
			}
		}
	}

}