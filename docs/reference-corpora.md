# Independent reference corpora audit

This audit was performed on 2026-10-15. The files below were checked for
existence through the upstream repository APIs, downloaded only to a temporary
directory, and hashed with `sha256sum`. They are **not** copied into this
repository and are not required by offline tests.

| Source file | Existence / size | Upstream license reference | SHA-256 |
| --- | ---: | --- | --- |
| [tcpdump `tests/LINKTYPE_IPV4.pcap`](https://github.com/the-tcpdump-group/tcpdump/blob/master/tests/LINKTYPE_IPV4.pcap) | PASS / 97 bytes | [tcpdump LICENSE](https://raw.githubusercontent.com/the-tcpdump-group/tcpdump/master/LICENSE), BSD-style | `60f58aff090449e3a7cec137ff32c9d168dbfbed866edc6f3cf8f2ce764ee9ec` |
| [PcapPlusPlus `Tests/Packet++Test/PacketExamples/ArpRequestPacket.pcap`](https://github.com/seladb/PcapPlusPlus/blob/master/Tests/Packet%2B%2BTest/PacketExamples/ArpRequestPacket.pcap) | PASS / 82 bytes | [PcapPlusPlus LICENSE](https://github.com/seladb/PcapPlusPlus/blob/master/LICENSE), public-domain dedication | `ec95793099f416942337763d4983cc895fa1cb73eb570cf9fade896afc6de957` |
| [Wireshark `test/captures/mysql/mysql57.pcapng.gz`](https://gitlab.com/wireshark/wireshark/-/blob/master/test/captures/mysql/mysql57.pcapng.gz) | PASS / 1,738 bytes | [Wireshark COPYING](https://gitlab.com/wireshark/wireshark/-/raw/master/COPYING), GPLv2 | `c3e95690dfca73b75ef8e604e36909df62d53a76a7d47cf0db228dd6d34b99a0` |

The upstream project license is not automatically proof that every capture
has unrestricted redistribution rights. Before vendoring any capture, record
the exact file, commit/ref, hash, and capture-specific rights. For this phase,
synthetic fixtures remain the safer deterministic test corpus.

Audit commands (run outside the repository's mandatory test path):

```text
curl --fail --location <upstream-file-url> -o /tmp/<file>
sha256sum /tmp/<file>
stat -c '%n %s bytes' /tmp/<file>
```
