from scapy.all import *

UBNT_types = {
	1: "MAC",
	2: "MAC_IP",
	3: "LONG_VERSION",
	10:"UPTIME",
	11:"HOSTNAME",
	12:"MODEL1",
	13:"ESSID",
	14:"WIRELESSMODE",
	16:"SYSTEMID",
	18:"SEQ",
	19:"MAC2",
	20:"MODEL",
	21:"MODEL2",
	22:"SHORT_VERSION",
	23:"UNKNOWN2",
	24:"UNKNOWN3",
	25:"UNKNOWN4",
	26:"UNKNOWN5",
	27:"ULTRA_SHORT_VERSION",

}

def get_UBNT_type(name):
	for i in UBNT_types.keys():
		if UBNT_types[i] == name:
			return i
	return None

class UBNT_discovery_options(Packet):
    fields_desc = [
        ByteEnumField("type", 0, UBNT_types),
        FieldLenField("len", 0),
        ConditionalField(
            MACField("mac", None),
            lambda pkt:pkt.type == get_UBNT_type("MAC") or pkt.type == get_UBNT_type("MAC_IP")
        ),
        ConditionalField(
            IPField("ip","127.0.0.1"),
            lambda pkt:pkt.type == get_UBNT_type("MAC_IP")
        ),
        ConditionalField(
            IntField("uptime",None),
            lambda pkt:pkt.type == get_UBNT_type("UPTIME")
        ),
        ConditionalField(
            XShortField("system-id",None),
            lambda pkt:pkt.type == get_UBNT_type("SYSTEMID")
        ),
        ConditionalField(
            XByteField("Wireless-Mode",None),
            lambda pkt:pkt.type == get_UBNT_type("WIRELESSMODE")
        ),
        ConditionalField(
        	StrLenField("value", "", length_from=lambda pkt: pkt.len),
            lambda pkt:
            	pkt.type != get_UBNT_type("MAC") and
            	pkt.type != get_UBNT_type("MAC_IP") and
            	pkt.type != get_UBNT_type("UPTIME") and
            	pkt.type != get_UBNT_type("SYSTEMID") and
            	pkt.type != get_UBNT_type("WIRELESSMODE")
        ),
    ]
    def extract_padding(self, p):
    	return "",p

class UBNT_discovery(Packet):
    fields_desc = [
        XByteField("version", 0),
        XByteField("cmd", 0),
        FieldLenField("full_len", 0, length_of="options"),
        PacketListField("options",[],UBNT_discovery_options,count_from = None,length_from=lambda pkt: pkt.full_len)
    ]

bind_layers(UDP, UBNT_discovery, sport=10001)
bind_layers(UDP, UBNT_discovery, dport=10001)

if __name__ == '__main__':
	pcap=rdpcap("discovery.pcap")
	for pkt in pcap:
		pkt.show()