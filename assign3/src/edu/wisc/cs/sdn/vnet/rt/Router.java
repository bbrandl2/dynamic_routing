package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.Map;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	private boolean isStatic;

	/**
	 * Creates a router for a specific host.
	 * 
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile) {
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable() {
		return this.routeTable;
	}

	// Set static RT variable
	public void setStatic(boolean b){
		this.isStatic = b;
	}

	/**
	 * Load a new routing table from a file.
	 * 
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile) {
		if (isStatic) {
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
		else {	
			// Add entries to RT reachable by router
			for (Map.Entry<String, Iface> iface : this.interfaces.entrySet()) {
				routeTable.insert(iface.getValue().getIpAddress() & iface.getValue().getSubnetMask(), 0, iface.getValue().getSubnetMask(), iface.getValue());
			}
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
		// remote comment

		// Send the packet out the correct interface
		this.sendPacket(etherPacket, routeEntry.getInterface());

		System.out.println("*** -> Router Sent packet: " +
				etherPacket.toString().replace("\n", "\n\t"));
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
