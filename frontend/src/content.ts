/**
 * Copy for the indexable part of the landing page.
 *
 * It lives in one module because it gets rendered twice: once as the page a
 * person reads, and once as the FAQPage JSON-LD a search engine reads. Schema
 * markup is only supposed to describe content that is actually on the page, so
 * a single source keeps the two from drifting apart.
 */

export interface Faq {
    question: string;
    /** Plain text. Also emitted verbatim as the schema.org acceptedAnswer. */
    answer: string;
}

export const AUTHOR = {
    name: 'Jason Eissayou',
    site: 'https://www.eissayou.com/',
    repo: 'https://github.com/Eissayou/PcapExplorer',
    caseStudy: 'https://www.eissayou.com/projects/pcap-tracker.html',
    projects: 'https://www.eissayou.com/projects.html',
} as const;

export const STEPS = [
    {
        title: 'Drop in a capture',
        body: 'Any .pcap, .pcapng or .cap file up to 100 MB, whether it came from tcpdump, Wireshark, tshark or a firewall export. No account, no install.',
    },
    {
        title: 'Pick a host, or let it choose',
        body: 'Leave the field blank and PCAP Explorer analyzes the busiest host in the file, which is usually the machine the capture came from.',
    },
    {
        title: 'Read the traffic',
        body: 'Packets and throughput over time, the peers your host talked to most, and every public destination plotted on a world map.',
    },
] as const;

export const FEATURES = [
    {
        title: 'Destination map',
        body: 'Every public IP your host sent packets to, located offline against the MaxMind GeoLite2 city database and sized by packet volume.',
    },
    {
        title: 'Traffic timeline',
        body: 'Packets per second and bytes per second, split by direction, so bursts, beacons and bulk transfers are easy to spot.',
    },
    {
        title: 'Top talkers',
        body: 'The peers that dominated the conversation each way, ranked. This is the quickest answer to "who is this machine talking to?"',
    },
    {
        title: 'IPv4 and IPv6',
        body: 'Dual-stack captures get parsed the same way, so v6 flows are not quietly dropped from the totals.',
    },
    {
        title: 'Switch hosts instantly',
        body: 'Every endpoint in the capture is listed after the first run, so you can change which host you are looking at without uploading again.',
    },
    {
        title: 'Nothing is kept',
        body: 'Captures are parsed for the length of the request and then thrown away. No accounts, no storage, and the source is public.',
    },
] as const;

export const FAQS: Faq[] = [
    {
        question: 'What is a PCAP file?',
        answer:
            'A PCAP (packet capture) file is a recording of network traffic, written by tools like tcpdump, Wireshark and tshark. Each entry holds one packet: when it was seen, who sent it, who it was addressed to, and the bytes it carried. PCAPNG is the newer version of the same idea, and PCAP Explorer reads both.',
    },
    {
        question: 'Can I analyze a PCAP file without installing Wireshark?',
        answer:
            'Yes. PCAP Explorer runs in the browser. Drop in a capture and you get a traffic timeline, the busiest peers and a map of destinations, with no software to install. It answers "where is this machine sending traffic?" quickly, while Wireshark is still the better tool once you need to inspect individual packets and protocol fields.',
    },
    {
        question: 'Is my capture file private?',
        answer:
            'Your file is sent to the server so it can be parsed, then thrown away as soon as the response is written. It is never saved to a database, and there is no account or sign-in involved. PCAP Explorer is open source, so you can read exactly what the server does with an upload, or clone it and run the whole thing locally.',
    },
    {
        question: 'Does PCAP Explorer support PCAPNG and IPv6?',
        answer:
            'Both. The file format is detected from its magic bytes, so PCAP and PCAPNG captures are handled without you picking anything, and IPv4 and IPv6 packets are analyzed side by side in the same capture.',
    },
    {
        question: 'Where does the location data come from?',
        answer:
            'Destinations are resolved against a local copy of the MaxMind GeoLite2 City database, so no third-party lookup service is called and your addresses never leave the server. GeoLite2 is approximate by nature. It places an IP near the network that announces it, which for cloud and CDN addresses means the data centre rather than any person.',
    },
    {
        question: 'Why does it only analyze TCP traffic?',
        answer:
            'TCP carries the conversations most people are trying to account for: web, API, SSH, mail and file transfer. Restricting the parser to it keeps results readable instead of drowning them in broadcast noise. UDP, ICMP and ARP packets are skipped, so a capture made up mainly of those comes back close to empty.',
    },
    {
        question: 'How do I capture a .pcap file myself?',
        answer:
            'On macOS or Linux, run sudo tcpdump -i any -w capture.pcap and stop it with Ctrl-C once you have enough traffic. On Windows, Wireshark records the same thing: pick your interface, click the shark-fin button, then use File then Save As and choose pcap or pcapng. Both files work here as-is.',
    },
    {
        question: 'How large a capture can I upload?',
        answer:
            'Up to 100 MB per file, which is roughly a million packets. If your capture is bigger, slice it first with editcap -c 500000 big.pcap part.pcap, or narrow it at capture time with a filter like tcpdump -i any tcp -w capture.pcap.',
    },
];
