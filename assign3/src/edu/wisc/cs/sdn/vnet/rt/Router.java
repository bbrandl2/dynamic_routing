import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;

public class Router extends Device {
    // Define constants
    private static final int RIP_PORT = 520;
    private static final String RIP_MULTICAST_IP = "224.0.0.9";
    private static final long RIP_RESPONSE_INTERVAL = 10 * 1000; // 10 seconds in milliseconds
    private static final long ROUTE_TIMEOUT = 30 * 1000; // 30 seconds in milliseconds

		/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

    // Timer for sending RIP responses
    private Timer ripResponseTimer;

	

    public Router(String host, DumpFile logfile) {
        super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
        this.ripResponseTimer = new Timer();
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

	public void loadRIPRouteTable(String routeTableFile) {
		for (Map.Entry<String, Iface> entry : this.interfaces.entrySet()) {
			Iface iface = entry.getValue();
			int subnet = iface.getIpAddress() & iface.getSubnetMask();
			this.routeTable.insert(subnet, 0, iface.getIpAddress(), iface);
			this.ripTable.addEntry(new RIPv2Entry(subnet, iface.getSubnetMask(), 0, System.currentTimeMillis(), true));
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

	
    public void startRIPv2() {
		// load the RIP route table

		for (Map.Entry<String, Iface> entry : this.interfaces.entrySet()) {
			Iface iface = entry.getValue();
			int subnet = iface.getIpAddress() & iface.getSubnetMask();
			this.routeTable.insert(subnet, 0, iface.getIpAddress(), iface);
			this.ripTable.addEntry(new RIPv2Entry(subnet, iface.getSubnetMask(), 0, System.currentTimeMillis(), true));
		}
        // Send RIP requests out all router interfaces
        sendRIPRequest();

        // Schedule sending unsolicited RIP responses every 10 seconds
        this.ripResponseTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                sendRIPResponse(false);
            }
        }, RIP_RESPONSE_INTERVAL, RIP_RESPONSE_INTERVAL);
    }

    // In Router.java, add method to send RIP requests
	private void sendRIPRequest() {
		sendRIPResponse(true); // Send RIP requests out of all interfaces
	}

	public void sendRIPResponse(boolean all) {
		if (all) {
			for (Map.Entry<String, Iface> entry : this.interfaces.entrySet()) {
				Iface iface = entry.getValue();
				Ethernet etherPacket = new Ethernet();
				etherPacket.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
				etherPacket.setSourceMACAddress(iface.getMacAddress().toBytes());
				etherPacket.setEtherType(Ethernet.TYPE_IPv4);

				IPv4 ipPacket = new IPv4();
				ipPacket.setSourceAddress(iface.getIpAddress());
				ipPacket.setDestinationAddress("224.0.0.9");
				ipPacket.setProtocol(IPv4.PROTOCOL_UDP);
				ipPacket.setTtl((byte) 64);
				etherPacket.setPayload(ipPacket);

				UDP udpPacket = new UDP();
				udpPacket.setSourcePort(UDP.RIP_PORT);
				udpPacket.setDestinationPort(UDP.RIP_PORT);
				udpPacket.setPayload(this.ripTable);
				ipPacket.setPayload(udpPacket);

				sendPacket(etherPacket, iface);
			}
		} else {
			// Send directed RIP response
			for (Map.Entry<String, Iface> entry : this.interfaces.entrySet()) {
				Iface iface = entry.getValue();
	
				// Check if this interface has pending updates
				if (iface.hasPendingRIPUpdates()) {
					Ethernet etherPacket = new Ethernet();
					etherPacket.setDestinationMACAddress(iface.getMacAddress().toBytes());
					etherPacket.setSourceMACAddress(iface.getMacAddress().toBytes());
					etherPacket.setEtherType(Ethernet.TYPE_IPv4);
	
					IPv4 ipPacket = new IPv4();
					ipPacket.setSourceAddress(iface.getIpAddress());
					ipPacket.setDestinationAddress(iface.getPendingRIPDestination());
					ipPacket.setProtocol(IPv4.PROTOCOL_UDP);
					ipPacket.setTtl((byte) 64);
					etherPacket.setPayload(ipPacket);
	
					UDP udpPacket = new UDP();
					udpPacket.setSourcePort(UDP.RIP_PORT);
					udpPacket.setDestinationPort(UDP.RIP_PORT);
	
					RIPv2 ripPayload = new RIPv2();
					// Add only the pending updates for this interface
					ripPayload.addEntry(iface.getPendingRIPUpdate());
	
					udpPacket.setPayload(ripPayload);
					ipPacket.setPayload(udpPacket);
	
					// Send the packet
					sendPacket(etherPacket, iface);
	
					// Mark the pending updates as sent
					iface.clearPendingRIPUpdates();
				}
			}
		}
	}


    @Override
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

		// Handle RIP packet
		if (ipv4Packet.getProtocol() == IPv4.PROTOCOL_UDP) {
            UDP udpPacket = (UDP) ipv4Packet.getPayload();
            if (udpPacket.getSourcePort() == UDP.RIP_PORT && udpPacket.getDestinationPort() == UDP.RIP_PORT) {
                handleRIPPacket(udpPacket, inIface);
                return;
            }
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

		// Send the packet out the correct interface
		this.sendPacket(etherPacket, routeEntry.getInterface());

		System.out.println("*** -> Router Sent packet: " +
				etherPacket.toString().replace("\n", "\n\t"));
        // Other packet handling code
    }

    private void handleRIPPacket(RIPv2 ripPacket, Iface inIface) {
        // Update route table based on received RIP packet
        for (RIPv2Entry entry : ripPacket.getEntries()) {
            // Update route table with RIP entries
            boolean updated = this.routeTable.update(entry, inIface);
            if (updated) {
                // Reset timeout for this route
                this.routeTable.resetTimeout(entry);
            }
        }
		// Send necessary RIP response packets
    	sendRIPResponse(false);
    }

	private void timeoutRouteEntries() {
		long currentTime = System.currentTimeMillis();
		for (RouteEntry entry : this.routeTable.getAllEntries()) {
			if (!entry.isDirectlyConnected() && currentTime - entry.getLastUpdateTime() > 30000) {
				this.routeTable.remove(entry.getDestinationAddress(), entry.getMask());
			}
		}
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
