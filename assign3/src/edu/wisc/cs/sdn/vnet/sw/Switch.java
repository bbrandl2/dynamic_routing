package edu.wisc.cs.sdn.vnet.sw;

import java.util.HashMap;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import net.floodlightcontroller.packet.Ethernet;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

public class Switch extends Device
{
    private Map<Long, MacEntry> macTable;
    private Timer timer;

    public Switch(String host, DumpFile logfile)
    {
        super(host, logfile);
        this.macTable = new HashMap<>();
        this.timer = new Timer();

		// TODO should this go here?
		startTimeoutChecker();
    }

	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
				etherPacket.toString().replace("\n", "\n\t"));

		// Record incoming link and MAC address of sending host
		long srcMacAddress = Ethernet.toLong(etherPacket.getSourceMACAddress());

		// Update MAC table
		if (!macTable.containsKey(srcMacAddress)) {
			macTable.put(srcMacAddress, new MacEntry(inIface));
		} else {
			MacEntry entry = macTable.get(srcMacAddress);
			entry.setLastSeen(System.currentTimeMillis());
		}

		// Index switch table using MAC destination address
		long destMacAddress = Ethernet.toLong(etherPacket.getDestinationMACAddress());
		Iface outIface = lookupInterface(destMacAddress);

		// Forward packet according to switch table
		if (outIface != null && !outIface.equals(inIface)) {
			// Entry found for destination and it's not on the same interface as incoming
			this.sendPacket(etherPacket, outIface);
			System.out.println("*** -> Sent packet: " +
				etherPacket.toString().replace("\n", "\n\t"));
			return;
		}

		// Entry not found for destination or destination on same interface, flood the packet
		for (Iface iface : interfaces.values()) {
			if (!iface.equals(inIface)) {
				this.sendPacket(etherPacket, iface);
				System.out.println("*** -> Flooded packet: " +
					etherPacket.toString().replace("\n", "\n\t"));
			}
		}
	}

	/**
	 * Look up the interface associated with a given MAC address in the MAC table.
	 * @param macAddress the MAC address to look up
	 * @return the interface associated with the MAC address, or null if not found
	 */
	private Iface lookupInterface(long macAddress) {
		MacEntry entry = macTable.get(macAddress);
		if (entry != null) {
			return entry.getIface();
		}
		return null;
	}


    private class MacEntry {
        private Iface iface;
        private long lastSeen;

        public MacEntry(Iface iface) {
            this.iface = iface;
            this.lastSeen = System.currentTimeMillis();
        }

        public Iface getIface() {
            return iface;
        }

        public void setIface(Iface iface) {
            this.iface = iface;
        }

        public long getLastSeen() {
            return lastSeen;
        }

        public void setLastSeen(long lastSeen) {
            this.lastSeen = lastSeen;
        }
    }

    // Periodically check and remove entries older than 15 seconds
    private void startTimeoutChecker() {
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                long currentTime = System.currentTimeMillis();
                macTable.entrySet().removeIf(entry ->
                        (currentTime - entry.getValue().getLastSeen()) > 15000);
            }
        }, 1000, 1000); // Check every second
    }
}
