package peafowl

/*
#cgo LDFLAGS: ${SRCDIR}/wrapper/libdpi.a

#include <net/ethernet.h>
#include <pcap.h>
#include <time.h>
#include "wrapper/api.h"

#ifdef WIN32
#define dpi_time_secs_t long
#define dpi_time_usecs_t long
#elif __APPLE__
#define dpi_time_secs_t __darwin_time_t
#define dpi_time_usecs_t __darwin_suseconds_t
#elif __ANDROID__
#define dpi_time_secs_t __kernel_time_t
#define dpi_time_usecs_t __kernel_suseconds_t
#elif __GLIBC__
#define dpi_time_secs_t __time_t
#define dpi_time_usecs_t __suseconds_t
#else  // Some form of linux/bsd/etc...
#include <sys/param.h>
#ifdef __OpenBSD__
#define dpi_time_secs_t u_int32_t
#define dpi_time_usecs_t u_int32_t
#else
#define dpi_time_secs_t time_t
#define dpi_time_usecs_t suseconds_t
#endif
#endif

#define SIZE_IPv4_FLOW_TABLE 32767
#define SIZE_IPv6_FLOW_TABLE 32767
#define MAX_IPv4_ACTIVE_FLOWS 500000
#define MAX_IPv6_ACTIVE_FLOWS 500000

dpi_library_state_t* state; // the state
struct pcap_pkthdr* header;
const u_char* packet;

uint ip_offset=0;
u_int32_t unknown_matches=0;
u_int32_t http_matches=0;
u_int32_t dns_matches=0;
u_int32_t bgp_matches=0;
u_int32_t smtp_matches=0;
u_int32_t pop3_matches=0;
u_int32_t mdns_matches=0;
u_int32_t ntp_matches=0;
u_int32_t dhcp_matches=0;
u_int32_t dhcpv6_matches=0;
u_int32_t rtp_matches=0;
u_int32_t sip_matches=0;
u_int32_t skype_matches=0;
u_int32_t ssl_matches=0;


// init state
int init()
{
	state = dpi_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS);
	ip_offset=sizeof(struct ether_header);

	if(state == NULL) {
	  return -1;
	}

	return 0;
  }

  // identify protocols l7
  int get_protocol(const u_char* packet, struct pcap_pkthdr *header)
  {
	dpi_identification_result_t r;
	int ID_protocol = -1;

	r = dpi_stateful_identify_application_protocol(state, packet+ip_offset, header->caplen-ip_offset, time(NULL));

	if(r.protocol.l4prot==IPPROTO_TCP){
		switch(r.protocol.l7prot){
			case DPI_PROTOCOL_TCP_BGP:
				++bgp_matches;
				break;
			case DPI_PROTOCOL_TCP_HTTP:
				++http_matches;
				break;
			case DPI_PROTOCOL_TCP_POP3:
				++pop3_matches;
				break;
			case DPI_PROTOCOL_TCP_SMTP:
				++smtp_matches;
				break;
			case DPI_PROTOCOL_TCP_SSL:
				++ssl_matches;
				break;
			default:
				++unknown_matches;
				break;
		}
	}else if(r.protocol.l4prot==IPPROTO_UDP){
		switch(r.protocol.l7prot){
			case DPI_PROTOCOL_UDP_DHCP:
				++dhcp_matches;
				break;
			case DPI_PROTOCOL_UDP_DHCPv6:
				++dhcpv6_matches;
				break;
			case DPI_PROTOCOL_UDP_DNS:
				++dns_matches;
				break;
			case DPI_PROTOCOL_UDP_MDNS:
				++mdns_matches;
				break;
			case DPI_PROTOCOL_UDP_NTP:
				++ntp_matches;
				break;
			case DPI_PROTOCOL_UDP_RTP:
				++rtp_matches;
				break;
			case DPI_PROTOCOL_UDP_SIP:
				++sip_matches;
				break;
			case DPI_PROTOCOL_UDP_SKYPE:
				++skype_matches;
				break;
			default:
				++unknown_matches;
				break;
		}
	}else{
		++unknown_matches;
	}

	if(r.protocol.l4prot == IPPROTO_UDP){
	  if(r.protocol.l7prot < DPI_NUM_UDP_PROTOCOLS){
		return r.protocol.l7prot;
	  }
	} else if(r.protocol.l4prot == IPPROTO_TCP){
	  if(r.protocol.l7prot < DPI_NUM_TCP_PROTOCOLS){
		return DPI_NUM_UDP_PROTOCOLS + r.protocol.l7prot;
	  }
	}
	return ID_protocol;
  }

  // identify protocols pairs [l7,l4]
  char * get_protocol_pair(const u_char* packet, struct pcap_pkthdr *header)
  {
	dpi_identification_result_t r;
	char * res;
	res = malloc(2 * sizeof(char));
	memset(res,-1,2);

	r = dpi_stateful_identify_application_protocol(state, packet+ip_offset, header->caplen-ip_offset, time(NULL));

	if(r.protocol.l4prot == IPPROTO_UDP){
	  res[0] = IPPROTO_UDP;
	  if(r.protocol.l7prot < DPI_NUM_UDP_PROTOCOLS){
		res[1] = r.protocol.l7prot;
		return res;
	  }
	} else if(r.protocol.l4prot == IPPROTO_TCP){
	  res[0] = IPPROTO_TCP;
	  if(r.protocol.l7prot < DPI_NUM_TCP_PROTOCOLS){
		res[1] = DPI_NUM_UDP_PROTOCOLS + r.protocol.l7prot;
		return res;
	  }
	}
	return res;
  }

  // terminate
  void terminate()
  {
	dpi_terminate(state);
  }
*/
import "C"
import (
	"fmt"
	"strings"
	"time"
	"unsafe"
)

type DPI struct {
	Stats Counter
}

// Counter contains statistics on how many packets were detected.
type Counter struct {
	//TODO add stats typesu_int32_t unknown_matches=0;
	HTTP    uint32
	DNS     uint32
	BGP     uint32
	SMTP    uint32
	POP3    uint32
	MDNS    uint32
	NTP     uint32
	DHCP4   uint32
	DHCP6   uint32
	RTP     uint32
	SIP     uint32
	Skype   uint32
	SSL     uint32
	Unknown uint32
}

func NewDPI() (*DPI, error) {
	e := C.init()
	if e == -1 {
		return nil, fmt.Errorf("dpi_init_stateful failed")
	}

	return &DPI{}, nil
}

func (d *DPI) GetProtocol(data []byte, offset int, t time.Time, ciLen, dataLen int) (proto int) {
	var hdr C.struct_pcap_pkthdr
	hdr.ts.tv_sec = C.dpi_time_secs_t(t.Unix())
	hdr.ts.tv_usec = C.dpi_time_usecs_t(t.Nanosecond() / 1000)
	hdr.caplen = C.bpf_u_int32(dataLen) // Trust actual length over ci.Length.
	hdr.len = C.bpf_u_int32(ciLen)

	proto = int(C.get_protocol(
		(*C.u_char)(unsafe.Pointer(&data[offset])),
		&hdr,
	))
	return proto
}

func (d *DPI) GetProtocolPair(data []byte, offset int, t time.Time, ciLen, dataLen int) (res string) {
	var hdr C.struct_pcap_pkthdr
	hdr.ts.tv_sec = C.dpi_time_secs_t(t.Unix())
	hdr.ts.tv_usec = C.dpi_time_usecs_t(t.Nanosecond() / 1000)
	hdr.caplen = C.bpf_u_int32(dataLen) // Trust actual length over ci.Length.
	hdr.len = C.bpf_u_int32(ciLen)

	res = C.GoString(C.get_protocol_pair(
		(*C.u_char)(unsafe.Pointer(&data[offset])),
		&hdr,
	))
	return res
}

func (d *DPI) ReceiveStats() {
	d.Stats.Unknown = uint32(C.unknown_matches)
	d.Stats.HTTP = uint32(C.http_matches)
	d.Stats.BGP = uint32(C.bgp_matches)
	d.Stats.POP3 = uint32(C.pop3_matches)
	d.Stats.SMTP = uint32(C.smtp_matches)
	d.Stats.NTP = uint32(C.ntp_matches)
	d.Stats.DNS = uint32(C.dns_matches)
	d.Stats.MDNS = uint32(C.mdns_matches)
	d.Stats.DHCP4 = uint32(C.dhcp_matches)
	d.Stats.DHCP6 = uint32(C.dhcpv6_matches)
	d.Stats.RTP = uint32(C.rtp_matches)
	d.Stats.SIP = uint32(C.sip_matches)
	d.Stats.Skype = uint32(C.skype_matches)
	d.Stats.SSL = uint32(C.ssl_matches)
}

func (d *DPI) ShowStats() string {
	d.ReceiveStats()
	s := strings.Join([]string{`DPI Stats {`,
		`Unknown:` + fmt.Sprintf("%v", d.Stats.Unknown) + `,`,
		`HTTP:` + fmt.Sprintf("%v", d.Stats.HTTP) + `,`,
		`BGP:` + fmt.Sprintf("%v", d.Stats.BGP) + `,`,
		`POP3:` + fmt.Sprintf("%v", d.Stats.POP3) + `,`,
		`SMTP:` + fmt.Sprintf("%v", d.Stats.SMTP) + `,`,
		`NTP:` + fmt.Sprintf("%v", d.Stats.NTP) + `,`,
		`DNS:` + fmt.Sprintf("%v", d.Stats.DNS) + `,`,
		`MDNS:` + fmt.Sprintf("%v", d.Stats.MDNS) + `,`,
		`DHCP4:` + fmt.Sprintf("%v", d.Stats.DHCP4) + `,`,
		`DHCP6:` + fmt.Sprintf("%v", d.Stats.DHCP6) + `,`,
		`RTP:` + fmt.Sprintf("%v", d.Stats.RTP) + `,`,
		`SIP:` + fmt.Sprintf("%v", d.Stats.SIP) + `,`,
		`Skype:` + fmt.Sprintf("%v", d.Stats.Skype) + `,`,
		`SSL:` + fmt.Sprintf("%v", d.Stats.SSL),
		`}`,
	}, "")
	return s
}

func (d *DPI) Close() {
	C.terminate()
}
