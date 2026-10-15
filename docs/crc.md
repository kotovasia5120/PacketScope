# Checksum and CRC discovery

PacketScope searches a deliberately bounded set of layouts. It does not brute-force arbitrary CRC parameters. The supported catalogue is:

| Name | Width | Poly | Init | RefIn/RefOut | XorOut | Check (`123456789`) |
| --- | ---: | ---: | ---: | --- | ---: | ---: |
| CRC-8 | 8 | `0x07` | `0x00` | false/false | `0x00` | `0xF4` |
| CRC-16/CCITT-FALSE | 16 | `0x1021` | `0xFFFF` | false/false | `0x0000` | `0x29B1` |
| CRC-16/MODBUS | 16 | `0x8005` | `0xFFFF` | true/true | `0x0000` | `0x4B37` |
| CRC-32/ISO-HDLC | 32 | `0x04C11DB7` | `0xFFFFFFFF` | true/true | `0xFFFFFFFF` | `0xCBF43926` |

XOR-8, additive-8, and additive-16 are also checked. `CRCParams` retains `width`, `poly`, `init`, `refin`, `refout`, `xorout`, `check`, and `residue`; the catalogue includes standard check and residue values where they are defined by the reference profile.

Discovery requires at least three bounded samples. It checks fixed offsets and a field immediately before the end of each message, in both wire byte orders. Results include the location mode, covered ranges, mismatch list, match/sample counts, algorithm parameters, and an explicit hypothesis status. It can return `INSUFFICIENT_EVIDENCE`, `SEARCH_LIMIT_REACHED`, or `TIME_LIMIT_EXCEEDED`. A match is never automatically promoted to `CONFIRMED`.

The implementation and independent vectors are in `packetscope/analysis/crc.py` and `tests/test_crc.py`; synthetic protocol corpora are in `tests/fixtures/phase3_corpus.py`.
