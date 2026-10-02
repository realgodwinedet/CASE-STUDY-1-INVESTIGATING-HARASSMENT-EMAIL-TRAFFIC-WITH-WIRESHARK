# SBT-DF204 — COMPUTER FORENSICS CASE STUDIES

## CASE STUDY 1: INVESTIGATING HARASSMENT EMAIL TRAFFIC WITH WIRESHARK

**Individual Forensic Investigation Report**

| Metadata Field | Recorded Details |
| --- | --- |
| **Student Name** | Godwin Edet Ikpi |
| **Registration Number** | 2025/FWSD/11267 |
| **Course** | SBT-DF204 — Computer Forensics Case Studies |
| **Case Title** | Investigating Harassment Email Traffic With Wireshark |
| **Evidence Examined** | `nitroba.pcap` |

---

## 1. Executive Conclusion

The available network result supports a strong attribution link between the harassment activity and a single client on the Nitroba dormitory network. The relevant traffic originated from private IP address `192.168.15.4` and was associated with MAC address `00:17:f2:e2:c0:ce`. Two HTTP transactions identified in the capture correspond to anonymous-mail activity directed at Lily Tuckrige: frame 80614 at `2008-07-22 06:02:57 UTC` and frame 83601 at `2008-07-22 06:04:24 UTC`. The latter is the `willselfdestruct.com` transaction described in the case.

The same IP/MAC combination is also associated with browser traffic containing the Gmail identity `jcoachj@gmail.com` and a matching Internet Explorer 6 / Windows XP user-agent. The supplied Chemistry 109 roster contains the student Johnny Coach, providing the final roster correlation. On the available evidence, the attribution to Johnny Coach is supported with high confidence for this training scenario, but it should not be described as mathematically or absolutely conclusive because the dormitory network used an open, shared wireless router. The evidence establishes a device and a correlated account; it does not independently prove who was physically sitting at the keyboard at every moment.

---

## 2. Evidence Acquisition and Integrity

The scenario shows `nitroba.pcap` as the network capture collected from the Ethernet tap serving the shared Nitroba student residence. The Digital Corpora scenario page publishes cryptographic hashes for the evidence file. The published SHA-256 value is reproduced below for comparison with the examiner's locally calculated hash.

| Acquisition Field | Recorded Value |
| --- | --- |
| **Original Filename** | `nitroba.pcap` |
| **Source** | Digital Corpora — 2008 Nitroba University Harassment Scenario |
| **Source File Size** | Approximately 60 MB; a published analysis records 54,865 KB |
| **Published MD5** | `9981827f11968773ff815e39f5458ec8` |
| **Published SHA-1** | `65656392412add15f93f8585197a8998aaeb50a1` |
| **Published SHA-256** | `2b77a9eaefc1d6af163d1ba793c96dbccacb04e6befdf1a0b01f8c67553ec2fb` |
| **Local Calculated SHA-256** | `2b77a9eaefc1d6af163d1ba793c96dbccacb04e6befdf1a0b01f8c67553ec2fb` |
| **Download Date** | 2026-09-30 11:29 WAT |
| **Working Copy** | Created from the downloaded evidence file; original source retained unchanged |

---

## 3. Method

The investigation followed a targeted Wireshark workflow. First, the public IP address from the earlier email header, `140.247.62.34`, was used to identify the relevant internal client. The capture was then searched for the victim's name/address and for the anonymous-mail service. HTTP POST requests and TCP streams were inspected to correlate the message content with the reported harassment. Ethernet-layer details were then examined to show the client MAC address. Finally, HTTP cookie/browser evidence was correlated with the same IP/MAC pair and compared with the Chemistry 109 roster.

| Purpose | Wireshark Display Filter / Search |
| --- | --- |
| **Locate the dorm/public address** | `ip.addr == 140.247.62.34` |
| **Locate victim/message references** | `frame contains "tuckrige"` |
| **Locate anonymous-mail submissions** | `http.request.method == "POST"` |
| **Narrow the relevant client exchange** | `ip.src == 192.168.15.4 && http.request.method == "POST"` |
| **Trace the device** | `eth.addr == 00:17:f2:e2:c0:ce` |
| **Find browser/account evidence** | `ip.addr == 192.168.15.4 && frame contains "jcoach"` |
| **Correlate Gmail/browser traffic** | `ip.addr == 192.168.15.4 && http.cookie contains "@"` |

---

## 4. Findings

### 4.1 What file was acquired and how was integrity preserved?

The result item is `nitroba.pcap`. The Digital Corpora scenario publishes SHA-256 `2b77a9eaefc1d6af163d1ba793c96dbccacb04e6befdf1a0b01f8c67553ec2fb`. The capture contains 94,410 packets and spans approximately 4 hours 22 minutes. Calculating the local SHA-256 verified a complete match, confirming that the working copy corresponds to the published evidence object.

* **Evidence Log Reference:** E01
* **Supporting Appendix:** Appendix A1

### 4.2 Which client system contacted the web service?

Filtering the public address identifies `192.168.15.4` as the relevant internal source. The anonymous mail transactions use `192.168.15.4` as the source. For the `willselfdestruct.com` transaction, the destination service address is `69.25.94.22` (frame 83601). The earlier anonymous-mail transaction in frame 80614 goes to `69.80.225.91`.

* **Evidence Log Reference:** E02
* **Supporting Appendix:** Appendix A2

### 4.3 What evidence links the client to the harassment message?

Frame 80614 contains an anonymous-mail submission with the subject *"Your class stinks"* and message *"Why do you persist in teaching a boring class? We do not like you."* Frame 83601 contains the later `willselfdestruct.com` submission with the subject *"You can't find us"* and message *"And you can't hide from us. Stop teaching. Start running."* Both originate from `192.168.15.4`. The second transaction directly correlates with the `willselfdestruct.com` message described in the case materials.

* **Evidence Log Reference:** E03
* **Supporting Appendix:** Appendix A3

### 4.4 Which device made the relevant request?

The Ethernet layer associated with the relevant client traffic identifies MAC address `00:17:f2:e2:c0:ce`. Public analyses identify this as an Apple-registered MAC address. The MAC serves as a physical device-level identifier on this local network segment; it is significantly stronger than relying on the shared IP alone, but it still does not independently identify a human operator.

* **Evidence Log Reference:** E04
* **Supporting Appendix:** Appendix A4

### 4.5 Who is associated with the device?

HTTP/browser traffic from the same `192.168.15.4` / `00:17:f2:e2:c0:ce` combination contains Gmail identity evidence for `jcoachj@gmail.com`. Frame 77528 (at `06:00:44 UTC`) reveals active Google session cookies alongside a matching user-agent string (`Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)`). Frame 78990 further documents a GET `/mail/` transaction from this same environment.

* **Evidence Log Reference:** E05
* **Supporting Appendix:** Appendix A5

### 4.6 Is that person on the Chem 109 roster?

Yes. The supplied Chemistry 109 roster includes **Johnny Coach**. The account identifier `jcoachj` is therefore directly consistent with a roster member. This represents an account-to-roster correlation rather than an independent identity document: network captures alone do not contain physical identification proving the identity of the person sitting at the physical keyboard.

* **Evidence Log Reference:** E06
* **Supporting Appendix:** Appendix A6

### 4.7 When did the activity occur?

The PCAP timestamps are recorded in UTC. The activity forms a clear chronological sequence:

1. `05:57:38 UTC` — Google search: `how to annoy people` (frame 72597)
2. `05:58:01 UTC` — Google search: `sending anonymous mail` (frame 74059)
3. `05:58:07 UTC` — Google search: `I want to harass my teacher` (frame 74334)
4. `06:00:44 UTC` — `jcoachj@gmail.com` browser/account session evidence (frame 77528)
5. `06:02:57 UTC` — Anonymous-mail submission: `Your class stinks` (frame 80614)
6. `06:04:24 UTC` — `willselfdestruct.com` harassment submission (frame 83601)
7. `06:04:43 UTC` — Google search: `where do the cool kids go to play` (frame 83805)

* **Evidence Log Reference:** E07
* **Supporting Appendix:** Appendix A7

### 4.8 What conclusion can be defended?

The evidence supports firmly the proposition that the device using `192.168.15.4` and MAC `00:17:f2:e2:c0:ce` submitted the harassment messages and that the same device/browser environment was associated with `jcoachj@gmail.com`. Because Johnny Coach appears on the Chemistry 109 roster, the evidence supports attribution to Johnny Coach within the scenario. Confidence is **HIGH** for device/account correlation and **MODERATE-TO-HIGH** for human attribution due to the open, shared nature of the network.

* **Evidence Log Reference:** E08
* **Supporting Appendix:** Appendix A8

---

## 5. Timeline

| Time (UTC) | Frame | Activity | Significance |
| --- | --- | --- | --- |
| **05:57:38** | 72597 | Google search: `how to annoy people` | Pre-activity search |
| **05:58:01** | 74059 | Google search: `sending anonymous mail` | Relevant preparatory search |
| **05:58:07** | 74334 | Google search: `I want to harass my teacher` | Highly relevant preparatory search |
| **06:00:44** | 77528 | `jcoachj@gmail.com` browser/account evidence | Links account to matching browser |
| **06:02:57** | 80614 | Anonymous-mail submission: *"Your class stinks"* | Harassment message correlation |
| **06:04:24** | 83601 | `willselfdestruct.com` submission: *"You can't find us"* | Case's reported second harassment event |
| **06:04:43** | 83805 | Google search: `where do the cool kids go to play` | Post-event browsing |

*Time-zone note: Wireshark/PCAP timestamps used for this report are UTC. If local Nigerian time (WAT) is required for assessment, UTC+1 converts these timestamps to 06:57:38 through 07:04:43 WAT.*

---

## 6. Attribution Assessment

| Evidence Category | Observation | Interpretation / Limitation |
| --- | --- | --- |
| **Network Location** | `192.168.15.4` generated the relevant anonymous-mail traffic. | Identifies a client on the captured network, not a person. |
| **Device** | MAC `00:17:f2:e2:c0:ce` appears with the relevant client. | Links activity to a captured device interface; MAC alone does not identify the operator. |
| **Application Identity** | `jcoachj@gmail.com` appears in HTTP/browser evidence from the same IP/MAC environment. | Strong account/device correlation, but capture does not prove physical operator identity. |
| **Roster** | Johnny Coach appears in Chem 109 roster. | Supports identity correlation between account name and class membership. |
| **Behavioral Sequence** | Searches for anonymous mail/harassing teacher precede the submissions. | Corroborating circumstantial evidence; intent should be stated cautiously. |
| **Shared Wi-Fi** | Scenario states the router was open and used by multiple people. | Creates an alternative-access explanation and prevents public IP alone from proving identity. |

**Overall Assessment:** **HIGH** confidence that the harassment submissions originated from the identified client/device and were associated with the `jcoachj` Gmail identity. **MODERATE-TO-HIGH** confidence that the identity corresponds to Johnny Coach based on roster correlation and surrounding browser activity. The conclusion remains subject to shared-network limitations and represents an evidence-based attribution rather than absolute physical proof.

---

## 7. Evidence Log

| Evidence ID | Packet / Item | Finding | Why It Matters | Screenshot / Appendix |
| --- | --- | --- | --- | --- |
| **E01** | `nitroba.pcap` / Properties | 94,410-packet capture; SHA-256 verified | Establishes evidence identity and integrity | Appendix A1 |
| **E02** | Frames 80614, 83601 | `192.168.15.4` communicates with anonymous-mail services | Identifies client involved in harassment traffic | Appendix A2 |
| **E03** | Frames 80614, 83601 | HTTP content correlates with reported harassment | Connects network traffic to complaint | Appendix A3 |
| **E04** | Ethernet II details | MAC `00:17:f2:e2:c0:ce` | Links relevant traffic to same captured device interface | Appendix A4 |
| **E05** | Frame 78990 / related Gmail traffic | `jcoachj@gmail.com` and matching browser evidence | Links device to application identity | Appendix A5 |
| **E06** | Chem 109 Roster | Johnny Coach appears on roster | Provides scenario's identity correlation | Appendix A6 |
| **E07** | Frames 72597–83805 | Chronological activity before and after submissions | Supports temporal correlation | Appendix A7 |
| **E08** | Attribution Matrix | Device, account, and roster evidence considered together | Documents final cautious attribution | Appendix A8 |

---

## 8. Conclusion

The technical analysis of `nitroba.pcap` establishes a continuous, timestamped chain of network activity originating from the client host assigned local IP address `192.168.15.4` and hardware MAC address `00:17:f2:e2:c0:ce`. Between 01:57:38 EDT and 02:04:43 EDT on July 22, 2008, this endpoint executed web searches demonstrating clear intent (*how to annoy people*, *sending anonymous mail*, *i want to harass my teacher*), attempted transmission via an anonymous mailing service, and successfully submitted an HTTP POST request to `willselfdestruct.com` containing the harassing message directed to instructor Lily Tuckrige.

While an IP address alone cannot prove human identity on a shared open wireless network, active session cookies captured in Frame 77528 directly link the physical endpoint (`00:17:f2:e2:c0:ce`) to the authenticated Google account `jcoachj@gmail.com`. Cross-referencing this account identifier with the Chemistry 109 class roster correlates the network activity to student **Johnny Coach**.

### Defensive Summary & Limitations

* **Supported Finding:** High-confidence technical attribution connects the hardware device (MAC `00:17:f2:e2:c0:ce`) and the user account `jcoachj@gmail.com` to the transmission of the harassing message.
* **Investigative Limitations:** Network traffic analysis alone cannot definitively confirm physical keyboard interaction or account for potential unauthorized physical access to an unlocked host, endpoint malware/session hijacking, or shared device usage on an open wireless segment. Forensic analysis of the host workstation disk image would be required to rule out local unauthorized access.

---

## 9. Appendices — Screenshot Checklist

* **Appendix A1 — Capture File Properties / packet count / timestamps / hash verification:** Capture file properties, packet count (94,410), timestamps, and terminal verification of local SHA-256 hash match (`2b77a9eaefc1d6af163d1ba793c96dbccacb04e6befdf1a0b01f8c67553ec2fb`).
* **Appendix A2 — Filter showing frames 80614 and 83601 and source/destination IP addresses:** Display filter showing frames 80614 and 83601 with client source IP `192.168.15.4` and service destination addresses.
* **Appendix A3 — Frame 83601 HTTP POST or Follow TCP Stream showing willselfdestruct.com transaction:** HTTP POST packet details / Follow TCP Stream for Frame 83601 showing the `willselfdestruct.com` submission payload.
* **Appendix A4 — Ethernet II details showing MAC 00:17:f2:e2:c0:ce:** Ethernet II packet header details displaying client source MAC address `00:17:f2:e2:c0:ce`.
* **Appendix A5 — Frame 78990 or equivalent Gmail HTTP request showing jcoachj@gmail.com cookie/account evidence:** HTTP request headers and cookie structure showing active session cookie/account evidence and browser user-agent string.
* **Appendix A6 — Chem 109 roster showing Johnny Coach:** Chemistry 109 class roster output confirming enrollment of Johnny Coach (`jcoachj@gmail.com`) under instructor Lily Tuckrige.
* **Appendix A7 — Timeline filters/results for relevant frames and timestamps:** Sequential packet output covering frames 72597 through 83805 mapping pre-incident searches, identity verification, harassment submissions, and post-incident searches.
* **Appendix A8 — Final evidence correlation summary:** Final attribution matrix and evidence log correlating frame numbers, timestamps, MAC/IP addresses, target hosts, and activity descriptions.

---

## 10. References

* Digital Corpora. *2008 Nitroba University Harassment Scenario*. Scenario page and published evidence hashes.
* Digital Corpora. `nitroba.pcap` — Network packet capture for the Nitroba harassment scenario.
* Public corroborating analysis consulted for packet/frame cross-checking: *PCAP Analysis Report — Nitroba University* (2023); *Wise Forensics — 2008 Nitroba University Harassment* (2024); *Forensicxs — Computer Forensics: Network Case using Wireshark and NetworkMiner* (2020).
