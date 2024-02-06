mod types;

use pcap::{Device, Linktype};
use types::{IP4_DF, IP4_MBZ, IPV4_HDR_LEN, MIN_TCP4, MIN_TCP6, TCP_HDR_LEN};

fn find_offset (data: &[u8], len: &usize, link_type: Linktype) -> usize {
    let mut len = len.clone();
    let mut i = 0;
    

    match link_type {
        Linktype::RAW => return 0,
        Linktype::NULL |
            Linktype::PPP => return 4,
        Linktype::LOOP |
            Linktype::PPP_HDLC |
            Linktype::PPP_ETHER => return 8,
        Linktype::ETHERNET => return 14,
        Linktype::LINUX_SLL => return 16,
        Linktype::PFLOG => return 28,
        Linktype::IEEE802_11 => return 32,
        _ => {}
    }


    loop {
        if i >= 40 {
            break;
        }
        
        if len < types::MIN_TCP4 { break };
        
        if len >= types::MIN_TCP6 && (data[i] >> 4) == 6 {
            println!("offset: {}", i);
            let ipv6_header: *const types::IPV6Header;
            unsafe {
                ipv6_header = data.as_ptr().byte_add(i).cast();
            }
            let header = unsafe { &*ipv6_header };
            println!("{:#?}", header);
            if header.proto == 6 {
                return i;
            }
        }

        if (data[i] >> 4) == 4 {
            println!("offset: {}", i);
            let ipv4_header: *const types::IPV4Header;
            unsafe {
                ipv4_header = data.as_ptr().byte_add(i).cast();
            }
            let header = unsafe { &*ipv4_header };
            println!("{:#?}", header);
            if header.proto == 4 {
                return i;
            }   
        }

        i += 2;
        len -= 2;
    }

    0
}

fn main() {
    let mut cap = Device::lookup()
                        .unwrap()
                        .unwrap()
                        .open()
                        .unwrap();
    let link_type = cap.get_datalink();

    let packet = cap
                    .next_packet()
                    .unwrap();
    
    let mut data = packet.data;
    let mut data_size = u32::min(packet.header.len, packet.header.caplen) as usize;

    let offset = find_offset(data, &data_size, link_type);

    data = &data[offset..];

    if (data[0] >> 4) == 4 {
        let hdr_ptr: *const types::IPV4Header = unsafe { 
            data.as_ptr().byte_add(offset).cast()
        };
        let header = unsafe { &*hdr_ptr };
        let hdr_len = (header.ver_hlen & 0x0F) as usize * 4;
        let flags_off = u16::from_be(header.flags_off);
        let tot_len = u16::from_be(header.tot_len);

        data_size = usize::min(data_size, tot_len as usize);

        if data_size < MIN_TCP4 {
            println!("Invalid header length");
            return;
        }

        if hdr_len <  IPV4_HDR_LEN {
            println!("Invalid header length");
            return;
        }

        if tot_len > data_size as u16 {
            println!("Invalid header length");
            return;
        }

        if hdr_len + TCP_HDR_LEN > data_size {
            println!("Invalid header length");
            return;
        }

        if header.proto != 6 {
            println!("Non TCP packet");
            return;
        }

        if (flags_off & !(IP4_DF | IP4_MBZ)) != 0 {
            println!("Fragmented packet");
            return;
        }
    }
}