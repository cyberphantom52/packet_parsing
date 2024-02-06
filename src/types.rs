use std::mem::size_of;

pub const MIN_TCP4: usize = size_of::<IPV4Header>() + size_of::<TCPHeader>();
pub const MIN_TCP6: usize = size_of::<IPV6Header>() + size_of::<TCPHeader>();

pub const IPV4_HDR_LEN: usize = size_of::<IPV4Header>();
pub const IPV6_HDR_LEN: usize = size_of::<IPV6Header>();
pub const TCP_HDR_LEN: usize = size_of::<TCPHeader>();

#[derive(Debug)]
#[repr(C, packed)]
pub struct IPV4Header {
    pub ver_hlen: u8,     // IP version (4), IP hdr len in dwords (4)
    pub tos_ecn: u8,      // ToS field (6), ECN flags (2)
    pub tot_len: u16,     // Total packet length, in bytes
    pub id: u16,          // IP ID
    pub flags_off: u16,   // Flags (3), fragment offset (13)
    pub ttl: u8,          // Time to live
    pub proto: u8,        // Next protocol
    pub cksum: u16,       // Header checksum
    pub src: [u8; 4],     // Source IP
    pub dst: [u8; 4],     // Destination IP
}

#[derive(Debug)]
#[repr(C, packed)]
pub struct IPV6Header {
    pub ver_tos: u32,        // Version (4), ToS (6), ECN (2), flow (20)
    pub pay_len: u16,        // Total payload length, in bytes
    pub proto: u8,           // Next protocol
    pub ttl: u8,             // Time to live
    pub src: [u8; 16],       // Source IP
    pub dst: [u8; 16],       // Destination IP
}

pub const IP4_MBZ: u16 = 0x8000;  // "Must be zero"
pub const IP4_DF: u16 = 0x4000;   // Don't fragment (usually PMTUD)
pub const IP4_MF: u16 = 0x2000;   // More fragments coming

#[repr(packed)]
pub struct TCPHeader {
  source_port: u16,
  destination_port: u16,
  sequence_number: u32,
  acknowledgment_number: u32,
  /// 4 MSBs data offset and rest 4 bits reserved
  data_offset_reserved: u8,
  flags: u8,
  window_size: u16,
  checksum: u16,
  urgent_pointer: u16,
}