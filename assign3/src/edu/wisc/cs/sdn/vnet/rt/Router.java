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
    private RouteTable routeTable;
    private ArpCache arpCache;
    private boolean isStatic;
    private RIPv2 ripTable;
    private Timer ripResponseTimer;

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
        this.ripResponseTimer = new Timer();
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
		System.out.println("*** -> Router Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		// Check if the Ethernet frame contains an IPv4 packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return; // Drop the packet if it's not IPv4
		}

		// Extract the IPv4 packet
		IPv4 ipv4Packet = (IPv4) etherPacket.getPayload();

		// Verify the checksum of the IPv4 packet
		if (!verifyChecksum(ipv4Packet)) {
			return; // Drop the packet if the checksum is incorrect
		}

		// Decrement the TTL of the IPv4 packet
		ipv4Packet.setTtl((byte) (ipv4Packet.getTtl() - 1));

		// Drop the packet if the TTL is 0
		if (ipv4Packet.getTtl() == 0) {
			return;
		}

		// Determine whether the packet is destined for one of the router's interfaces
		for (Map.Entry<String, Iface> iface : this.interfaces.entrySet()) {
			// Drop packet if it matches a router interface IP
			if (iface.getValue().getIpAddress() == ipv4Packet.getDestinationAddress())
				return;
		}


		if (this.isStatic){ // Static route table
			// Lookup the RouteEntry
			RouteEntry routeEntry = this.routeTable.lookup(ipv4Packet.getDestinationAddress());

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
			if (nextHopMac == null) {
				return; // Drop the packet if MAC address not found
			}

			// Update Ethernet header
			etherPacket.setDestinationMACAddress(nextHopMac.toBytes());
			etherPacket.setSourceMACAddress(routeEntry.getInterface().getMacAddress().toBytes());

			ipv4Packet.setChecksum((short)0);
			ipv4Packet.serialize();

			// Send the packet out the correct interface
			this.sendPacket(etherPacket, routeEntry.getInterface());
		}
		else { // Dynamic route table
			if ( (ipv4Packet.getProtocol() == IPv4.PROTOCOL_UDP) && (((UDP) ipv4Packet.getPayload()).getDestinationPort() == 520) ){	// RIP packet
				System.out.println("\n***RIP PACKET***\n");

				UDP udpPacket = (UDP) ipv4Packet.getPayload();
				RIPv2 refTable = (RIPv2) udpPacket.getPayload();

				for (RIPv2Entry ripEntry : refTable.getEntries()){
					int addr = ripEntry.getAddress();
					RIPv2Entry thisEntry = this.ripTable.lookup(addr);

					if (thisEntry == null){ // Corresponding entry not in table
						RIPv2Entry newEntry = new RIPv2Entry(addr, ripEntry.getSubnetMask(), ripEntry.getMetric() + 1, System.currentTimeMillis(), false);
						ripTable.addEntry(newEntry);
					}
					else {	// Entry already exists
						if ((ripEntry.getMetric() + 1) < thisEntry.getMetric()){ // Incoming entry has lower cost path
							thisEntry.setNextHopAddress(addr);
							thisEntry.updateTime();
						}
						else if ((thisEntry.getMetric() + 1) < ripEntry.getMetric()){
							// Send a response back to other router indicating a shorter path
						}
					}
				}
			}
			else {	// Non RIP packet
				RIPv2Entry RIProuteEntry = this.ripTable.lookup(ipv4Packet.getDestinationAddress());

				// Drop the packet if no matching entry found
				if (RIProuteEntry == null) {
					return;
				}

				// Lookup the next-hop IP address
				int nextHopIp = RIProuteEntry.getNextHopAddress();

				// Lookup MAC address corresponding to next-hop IP address
				MACAddress nextHopMac = this.arpCache.lookup(nextHopIp).getMac();
				if (nextHopMac == null) {
					return; // Drop the packet if MAC address not found
				}

 				// Get the outgoing interface based on the IP address of the router interface
				// that sent the RIP request
				Iface outIface = getOutgoingInterface(ipv4Packet.getSourceAddress());

				// Update Ethernet header
				etherPacket.setDestinationMACAddress(nextHopMac.toBytes());
				etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

				ipv4Packet.serialize();

				// Send the packet out the correct interface
				this.sendPacket(etherPacket, outIface);
			}
		}
		
		System.out.println("*** -> Router Sent packet: " +
				etherPacket.toString().replace("\n", "\n\t"));
	}

	private Iface getOutgoingInterface(int ipAddress) {
		for (Iface iface : this.interfaces.values()) {
			if (iface.getIpAddress() == ipAddress) {
				return iface;
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

	public void sendResponse(boolean all){
		if (all){	// Send RIP response out of all interfaces, called every 10 seconds
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
	
				// Add RIPv2 packet (route table) as UDP payload
				// ripTable.setParent(udpPacket); // Is this needed?
	
				udpPacket.setPayload(ripTable);
	
				// Send packet out of current interface
				this.sendPacket(etherpacket, iface.getValue());
			}
		}
		else {	// Send directed response
			
		}
		
	}

}

/*
 * TODO
 * Send a request out of all interfaces upon initialization
 * Distinguish between requests and responses in handlePacket
 * Handle non-RIP packet forwarding for dynamic route tables
 * Handle 30 second RIP entry checks:
 * 	Do we check all of a router's entries every 30 seconds or
 * 	somehow have route entries individually check their update status?
 */
