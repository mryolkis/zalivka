# Partial firmware-updater retry

The adjacent plist projects the Ace3 requests from a supplied Zalivka 0.2.3
restore transcript for a Mac15,6 (SoC CPID 6030, BDID 04). ECIDs, nonces,
digests, ticket bytes, server metadata and volume paths have been replaced with
synthetic values. Public hardware identifiers, protocol fields and request
structure are retained. The fixture contains no usable signing response.

| Updater round | Listed ResponseTags | Active ticket flags in DeviceGeneratedRequest | TSS response tickets |
| --- | --- | --- | --- |
| 0 | Controllers 1–4 | Controllers 1–4 | Controllers 1–4 |
| 1 | Controllers 1–4 | Controllers 2–4 | Controllers 2–4 |

Both original TSS responses reported STATUS=0 / SUCCESS. In the second round,
the host incorrectly required USBPortController1,Ticket even though its flag
was absent from that round's DeviceGeneratedRequest. MessageArgInfo.TicketName
also still named controller 1; it did not describe the current requested set.

The regression test replays both rounds through request preparation, response
validation and in-memory plist framing. It confirms that the second response is
forwarded unchanged, without restoring a ticket from the first round. Separate
tests still reject absent, empty or malformed active tickets and invalid
response envelopes. No test contacts TSS or writes to physical USB.
