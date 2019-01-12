package udpdetection;

import java.io.File;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.protocol.lan.Ethernet;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.io.*;
import java.net.*;
import java.io.DataOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

class Destination {

    public String destinationAddress;   // monitorovana cielova adresa
    public long fromDestination = 0;    // pocet udp paketov odoslanych z cielovej adresy
    public long toDestination = 0;      // poct udp paketov prijatych na cielovej adrese
}

public class Detector {

    private List<String> monitoredIP = new ArrayList<String>();

    private double MAX_RATIO = 300.0;       // maximalny povoleny pomer medzi prijatymi/odoslanymi udp paketmi
    private long TTL = 5;                   // casove okno pocas ktore sa nesmie presiahnut dovoleny pomer

    // zdrovoja adresa : monitorovana cielova adresa
    private HashMap<String, Destination> monitor = new HashMap<String, Destination>();

    // TTL pre zdrojove adresy
    private HashMap<String, Long> ttl = new HashMap<String, Long>();
    // Trieda na posielanie dat do DB
    private DBConn db = new DBConn(--HOST--, --USER--, --PASS--);

    Detector(String args[]) {
        for (int i = 0; i < args.length; i++) {
            monitoredIP.add(args[i]);
        }
    }

    // vypocet ratio fukcie
    private double ratio(Destination dst) {
        long from = dst.fromDestination;
        long to = dst.toDestination;

        double ratio = 0.0;

        if (from == 0) {
            ratio = (double) to;
        } else {
            ratio = (double) (to / from);
        }

        return ratio;
    }

    // detekcia UDP flood, vola sa po kazdom novom udp pakete
    private void detection() throws IOException {
        for (Map.Entry<String, Destination> entry : monitor.entrySet()) {
            String key = entry.getKey();
            Destination value = entry.getValue();
            double r = ratio(value);

            // experimentalna hodnota
            if (r >= MAX_RATIO && isWithinTTL(key) == true) {
                System.out.println("UDP flood alert to " + key + " from " + value.destinationAddress);

                try {
                    String msg = "UDP flood alert to " + key + " from " + value.destinationAddress;
                    Socket socket = new Socket("147.175.106.17", 9999);
                    DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                    output.writeUTF(msg);
                    socket.close();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                db.SendUDPFlood(key, value.destinationAddress);
            }
        }
    }

    // skontroluje ci je dana zdrojova adresa v ramci TTL
    private boolean isWithinTTL(String address) {
        if (ttl.containsKey(address)) {
            long startTime = ttl.get(address);
            long currentTime = System.currentTimeMillis();

            TimeUnit unit = TimeUnit.SECONDS;
            long passedSeconds = unit.convert(currentTime - startTime, TimeUnit.MILLISECONDS);

            if (passedSeconds < TTL) {
                return true;
            } else {
                return false;
            }
        }

        return true;
    }

    // parsovanie pcap suboru
    public void run(File pcapFile) {
        StringBuilder errbuf = new StringBuilder();
        Pcap pcap = Pcap.openOffline(pcapFile.getAbsolutePath(), errbuf);

        if (pcap == null) {
            System.out.println(errbuf);
            return;
        }

        PcapHeader hdr = new PcapHeader(JMemory.POINTER);
        JBuffer buf = new JBuffer(JMemory.POINTER);
        Ip4 ip = new Ip4();
        Udp udp = new Udp();
        Ethernet eth = new Ethernet();
        int id = JRegistry.mapDLTToId(pcap.datalink());

        while (pcap.nextEx(hdr, buf) == Pcap.NEXT_EX_OK) {
            PcapPacket packet = new PcapPacket(hdr, buf);
            packet.scan(id);

            byte[] d_IP = new byte[4];
            byte[] s_IP = new byte[4];

            s_IP = buf.getByteArray(12, 4);
            d_IP = buf.getByteArray(16, 4);

            byte protocol = buf.getByte(9);

            String dip = org.jnetpcap.packet.format.FormatUtils.ip(d_IP);
            String sip = org.jnetpcap.packet.format.FormatUtils.ip(s_IP);

            // mame udp paket
            if (protocol == 17) {
                boolean isMonitored = true;
                String _ip = "";

                for (String i : monitoredIP) {
                    if (i.equals(sip) || i.equals(dip)) {
                        isMonitored = true;
                        _ip = i;
                        break;
                    }
                }

                // ak ano...
                if (isMonitored) {
                    if (_ip.equals(dip)) {
                        if (monitor.containsKey(sip)) {
                            long td = monitor.get(sip).toDestination;
                            td++;
                            monitor.get(sip).toDestination = td;
                        } else {
                            Destination newDst = new Destination();
                            newDst.destinationAddress = _ip;
                            newDst.toDestination = 1;

                            ttl.put(sip, System.currentTimeMillis());
                            monitor.put(sip, newDst);
                        }
                    }

                    if (_ip.equals(sip)) {
                        if (monitor.containsKey(dip)) {
                            long fd = monitor.get(dip).fromDestination;
                            fd++;
                            monitor.get(dip).fromDestination = fd;
                        } else {
                            Destination newDst = new Destination();
                            newDst.destinationAddress = _ip;
                            newDst.fromDestination = 1;

                            ttl.put(dip, System.currentTimeMillis());
                            monitor.put(dip, newDst);
                        }
                    }
                }

                detection();

                for (Map.Entry<String, Long> entry : ttl.entrySet()) {
                    long currentTime = System.currentTimeMillis();

                    TimeUnit unit = TimeUnit.SECONDS;
                    long passedSeconds = unit.convert(currentTime - entry.getValue(), TimeUnit.MILLISECONDS);

                    if (passedSeconds > TTL) {
                        entry.setValue(currentTime);

                        // vvynulovanie monitora
                        if (monitor.containsKey(entry.getKey())) {
                            monitor.get(entry.getKey()).fromDestination = 0;
                            monitor.get(entry.getKey()).toDestination = 0;
                        }
                    }
                }
            }
        }

        pcap.close();
    }
}
