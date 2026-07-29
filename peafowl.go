package peafowl

/*
#cgo LDFLAGS: -L${SRCDIR}/peafowl -lpeafowl

#include <net/ethernet.h>
#include <pcap.h>
#include <time.h>
#include "peafowl/peafowl.h"


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

static pfwl_state_t* state;
static pfwl_dissection_info_t dissection_info;
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
int b_init()
{
  // C function from Peafowl lib
  state = pfwl_init();
  if(state == NULL) {
      fprintf(stderr, "peafowl init ERROR\n");
      return -1; // ERROR
  }
  return 0;
}


// Converts a pcap datalink type to a pfwl_datalink_type_t
pfwl_protocol_l2_t _convert_pcap_dlt(int link_type)
{
    return pfwl_convert_pcap_dlt(link_type);
}


// parse packet from L2
pfwl_status_t _dissect_from_L2(char* packet, uint32_t length,
                               uint32_t timestamp, pfwl_protocol_l2_t datalink_type)
{
    return pfwl_dissect_from_L2(state, (const u_char*) packet,
                                length, time(NULL),
                                datalink_type, &dissection_info);
}


// parse packet from L3
pfwl_status_t _dissect_from_L3(char* packet_fromL3, uint32_t length_fromL3,
                               uint32_t timestamp)
{
    return pfwl_dissect_from_L3(state, (const u_char*) packet_fromL3,
                                length_fromL3, time(NULL), &dissection_info);
}


// parse packet from L4
pfwl_status_t _dissect_from_L4(char* packet_fromL4, uint32_t length_fromL4,
                               uint32_t timestamp)
{
    return pfwl_dissect_from_L3(state, (const u_char*) packet_fromL4,
                                length_fromL4, time(NULL), &dissection_info);
}


// enables an L7 protocol dissector
uint8_t _protocol_L7_enable(pfwl_protocol_l7_t protocol)
{
    return pfwl_protocol_l7_enable(state, protocol);
}


// disables an L7 protocol dissector
uint8_t _protocol_L7_disable(pfwl_protocol_l7_t protocol)
{
    return pfwl_protocol_l7_disable(state, protocol);
}


// guesses the protocol looking only at source/destination ports
pfwl_protocol_l7_t _guess_protocol()
{
    return pfwl_guess_protocol(dissection_info);
}


// returns the string represetation of a protocol
char* _get_L7_protocol_name(pfwl_protocol_l7_t protocol)
{
    return pfwl_get_L7_protocol_name(protocol);
}


// returns the protocol id corresponding to a protocol string
pfwl_protocol_l7_t _get_L7_protocol_id(char* string)
{
    return pfwl_get_L7_protocol_id(string);
}


// dissect pachet from L2 and return the L7 protocol name
char* _get_L7_from_L2(char* packet, struct pcap_pkthdr* header, int link_type)
{
    char* name = NULL;
    // convert L2 type in L2 peafowl type
    pfwl_protocol_l2_t dlt = pfwl_convert_pcap_dlt(link_type);
    // call dissection from L2
    pfwl_status_t status = pfwl_dissect_from_L2(state, (const u_char*) packet,
                                                header->caplen, time(NULL), dlt, &dissection_info);

    if(status >= PFWL_STATUS_OK) {
        name = pfwl_get_L7_protocol_name(dissection_info.l7.protocol);
        return name;
    }
    else return "ERROR";
}


// enables the extraction of a specific L7 field for a given protocol
uint8_t _field_add_L7(char* field)
{
    pfwl_field_id_t f = pfwl_get_L7_field_id(field);
    return pfwl_field_add_L7(state, f);
}


// disables the extraction of a specific L7 field for a given protocol
uint8_t _field_remove_L7(char* field)
{
    pfwl_field_id_t f = pfwl_get_L7_field_id(field);
    return pfwl_field_remove_L7(state, f);
}


// set the accuracy level of dissection
uint8_t _set_protocol_accuracy_L7(pfwl_protocol_l7_t protocol,
                                  pfwl_dissector_accuracy_t accuracy)
{
    return pfwl_set_protocol_accuracy_L7(state, protocol, accuracy);
}


// check if the field is present or not
int _field_present(char* field)
{
    pfwl_field_id_t f = pfwl_get_L7_field_id(field);
    return dissection_info.l7.protocol_fields[f].present;
}


// extracts a specific string field from a list of fields (ret = 0 string set)
char* _field_string_get(char* field)
{
    pfwl_string_t string;
    pfwl_field_id_t f = pfwl_get_L7_field_id(field);
    pfwl_field_string_get(dissection_info.l7.protocol_fields, f, &string);
    return string.value;
}


// extracts a specific numeric field from a list of fields (ret = 0 number set)
int _field_number_get(char* field)
{
    int64_t num;
    pfwl_field_id_t f = pfwl_get_L7_field_id(field);
    pfwl_field_number_get(dissection_info.l7.protocol_fields, f, &num);
    return num;
}


// terminate
void _terminate()
{
	pfwl_terminate(state);
}


*/
import "C"
import (
	"fmt"
	"strings"
	"time"
)

type DPI struct {
	Stats Counter
}

// Counter contains statistics on how many packets were detected.
type Counter struct {
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
	e := C.b_init()
	if e == -1 {
		return nil, fmt.Errorf("dpi_init_stateful failed")
	}
	return &DPI{}, nil
}

func (d *DPI) GetProtocol(data []byte, offset int, t time.Time, ciLen, dataLen int) (l7 int) {
	var hdr C.struct_pcap_pkthdr
	hdr.ts.tv_sec = C.dpi_time_secs_t(t.Unix())
	hdr.ts.tv_usec = C.dpi_time_usecs_t(t.Nanosecond() / 1000)
	hdr.caplen = C.bpf_u_int32(dataLen) // Trust actual length over ci.Length.
	hdr.len = C.bpf_u_int32(ciLen)

	/* 	l7 = int(C.get_protocol(
		(*C.u_char)(unsafe.Pointer(&data[offset])),
		&hdr,
	)) */

	return l7
}

func (d *DPI) GetProtocolPair(data []byte, offset int, t time.Time, ciLen, dataLen int) (l4, l7 int) {
	var hdr C.struct_pcap_pkthdr
	hdr.ts.tv_sec = C.dpi_time_secs_t(t.Unix())
	hdr.ts.tv_usec = C.dpi_time_usecs_t(t.Nanosecond() / 1000)
	hdr.caplen = C.bpf_u_int32(dataLen) // Trust actual length over ci.Length.
	hdr.len = C.bpf_u_int32(ciLen)

	/* 	res := C.GoString(C.get_protocol_pair(
		(*C.u_char)(unsafe.Pointer(&data[offset])),
		&hdr,
	)) */

	/* 	if len(res) == 2 {
		l4 = int(res[0])
		l7 = int(res[1])

	} */
	return l4, l7
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
	C._terminate()
}
