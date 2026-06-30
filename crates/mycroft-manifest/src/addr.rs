use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[must_use]
pub const fn ip_is_disallowed(ip: IpAddr) -> bool {
  match ip {
    IpAddr::V4(v4) => ipv4_is_disallowed(v4),
    IpAddr::V6(v6) => ipv6_is_disallowed(v6),
  }
}

const fn ipv4_is_disallowed(ip: Ipv4Addr) -> bool {
  ip.is_loopback()
    || ip.is_private()
    || ip.is_link_local()
    || ip.is_broadcast()
    || ip.is_documentation()
    || ip.is_unspecified()
    || ip.is_multicast()
    || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 0x40)
    || (ip.octets()[0] == 198 && (ip.octets()[1] & 0xFE) == 0x12)
}

const fn ipv6_is_disallowed(ip: Ipv6Addr) -> bool {
  if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
    return true;
  }
  let segs = ip.segments();
  if (segs[0] & 0xFE00) == 0xFC00 {
    return true;
  }
  if (segs[0] & 0xFFC0) == 0xFE80 {
    return true;
  }
  if let Some(v4) = ip.to_ipv4_mapped() {
    return ipv4_is_disallowed(v4);
  }
  false
}

#[must_use]
pub fn host_literal_is_disallowed(host: &str) -> bool {
  let trimmed = host.trim_start_matches('[').trim_end_matches(']');
  if trimmed.eq_ignore_ascii_case("localhost") {
    return true;
  }
  trimmed.parse::<IpAddr>().is_ok_and(ip_is_disallowed)
}

#[cfg(test)]
mod tests {
  use crate::addr::{host_literal_is_disallowed, ip_is_disallowed};

  #[test]
  fn loopback_and_private_are_disallowed() {
    assert!(ip_is_disallowed("127.0.0.1".parse().unwrap()));
    assert!(ip_is_disallowed("10.0.0.5".parse().unwrap()));
    assert!(ip_is_disallowed("192.168.1.1".parse().unwrap()));
    assert!(ip_is_disallowed("169.254.169.254".parse().unwrap()));
    assert!(ip_is_disallowed("::1".parse().unwrap()));
    assert!(ip_is_disallowed("fd00::1".parse().unwrap()));
  }

  #[test]
  fn public_addresses_are_allowed() {
    assert!(!ip_is_disallowed("1.1.1.1".parse().unwrap()));
    assert!(!ip_is_disallowed("8.8.8.8".parse().unwrap()));
    assert!(!ip_is_disallowed("2606:4700:4700::1111".parse().unwrap()));
  }

  #[test]
  fn localhost_name_is_disallowed() {
    assert!(host_literal_is_disallowed("localhost"));
    assert!(!host_literal_is_disallowed("example.com"));
  }
}
