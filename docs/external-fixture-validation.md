# External fixture validation

The following files were fetched temporarily into `/tmp`, parsed, and then
removed from the project. No third-party capture is vendored and no packet
contents are included in this report. SHA-256 values are recorded so the check
can be repeated against the pinned upstream commits.

| Source file | Upstream commit | SHA-256 | Expected | Actual | Status | License / redistribution |
| --- | --- | --- | --- | --- | --- | --- |
| [tcpdump `tests/LINKTYPE_IPV4.pcap`](https://github.com/the-tcpdump-group/tcpdump/blob/3a2f6acd865e5b845d9f63caf5f2c23cb73a2bc9/tests/LINKTYPE_IPV4.pcap) | `3a2f6acd865e5b845d9f63caf5f2c23cb73a2bc9` | `60f58aff090449e3a7cec137ff32c9d168dbfbed866edc6f3cf8f2ce764ee9ec` | classic PCAP, one packet | imported as PCAP, 1 packet | **PASS** | BSD; not redistributed |
| [tcpdump `tests/LINKTYPE_IPV6.pcap`](https://github.com/the-tcpdump-group/tcpdump/blob/3a2f6acd865e5b845d9f63caf5f2c23cb73a2bc9/tests/LINKTYPE_IPV6.pcap) | same | `522ec0aca58bb965d0294cb3e758f2edeb7524075999e06fb9abb3e913ddf471` | classic PCAP, one packet | imported as PCAP, 1 packet | **PASS** | BSD; not redistributed |
| [PcapPlusPlus `DNS_NXDomain.pcap`](https://github.com/seladb/PcapPlusPlus/blob/43e9eeeb3fabd7f268b2fdefd57b4cad791ca859/Tests/Packet%2B%2BTest/PacketExamples/DNS_NXDomain.pcap) | `43e9eeeb3fabd7f268b2fdefd57b4cad791ca859` | `e98ff9261235911575bc636a048a4018269b2a0edef14a9d3580f0b84b91abd4` | classic PCAP, DNS packet | imported as PCAP, 1 packet | **PASS** | public-domain notice in repository; not redistributed |
| [Wireshark `test/captures/http.pcap`](https://github.com/wireshark/wireshark/blob/4cb82f7abf507f86b9dcb93b41517ecca0eb84b1/test/captures/http.pcap) | `4cb82f7abf507f86b9dcb93b41517ecca0eb84b1` | `69e489a26a59208a1dd56fbea4c606b1e59e8ac32d3d4789ca6cc81e71bad3f2` | classic PCAP, HTTP/TCP packet | imported as PCAP, 1 packet | **PASS** | repository GPL-2.0-or-later; not redistributed |
| [Kaitai `network/rtp_packet/pcma-marker.bin`](https://github.com/kaitai-io/kaitai_struct_samples/blob/11ccc86d7697d1b4dcc58ee4b0c5bf8994307e76/network/rtp_packet/pcma-marker.bin) | `11ccc86d7697d1b4dcc58ee4b0c5bf8994307e76` | `f29811921afaa4a347d0d00c02608ca0c206781a321e7a972407686abf2a19` | raw binary RTP sample | imported as BIN, 1 packet | **PASS** | file license says GPL-2.0-or-later; not redistributed |

This is importer validation only. A successful import does not mean PacketScope
successfully reverse-engineered the application protocol, and a one-packet
fixture is intentionally not treated as sufficient inference evidence.

The validation command used the standard-library importer with default limits;
it was an online, non-mandatory check. Mandatory unit and integration tests
remain fully offline.
