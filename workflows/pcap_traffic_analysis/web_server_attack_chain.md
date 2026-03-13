# Web Server Attack Chain

This workflow is a simple method I use when studying web server compromises in practice, from the attacker’s first contact with the host through data theft.


A common chain looks like this:

**reconnaissance → enumeration → exploitation → post-exploitation → data exfiltration**

## Identify the Attacker IP Through Port Scanning

The first priority is finding the source that kicked off the activity.

In web intrusion cases, that often starts with port scanning to identify exposed services worth revisiting.

In Wireshark:

`Statistics → Conversations → TCP`

Sort by **Packets A → B** in descending order. The scanning source will usually show a high volume of packets sent across multiple ports, with far fewer responses coming back.

Once identified, that IP becomes the main pivot point for the rest of the investigation.

## Recon Phase

### Count the Initial Probes

After isolating the source, the next step is measuring how broad the scan was.

Focus on TCP packets that begin a connection attempt: SYN packets without the ACK flag set.

Use this display filter:

    tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.src == <attacker IP>

The `Displayed` count gives a quick total of the matching packets. That helps size up the recon activity and shows how many connection attempts were made during the scan.

### Find the Ports That Responded

A listening service will answer a SYN with a SYN-ACK. Those responses show which ports were reachable from the attacker’s perspective.

Use this filter:

    tcp.flags.syn == 1 and tcp.flags.ack == 1 and ip.src == <web server IP>

With that traffic isolated, review `Statistics → Conversations → TCP` and check the associated port values. Those ports represent the services the attacker identified.

### Measure the Scan Window

It also helps to place the scan in time.

To isolate the probing traffic again, use:

    ip.src == <attacker IP> and tcp.flags.syn == 1 and tcp.flags.ack == 0

`Statistics → I/O Graphs` in Wireshark with a **1 second** interval will graphically reveal any spikes/bursts in network activity and there duration.

From there, return to the packet list and note the first and last SYN packets within that burst. The gap between those timestamps gives a reasonable estimate of the scan duration.

## Enumeration

Once live web services are exposed, the next step is usually mapping the application.

That often shows up as repeated requests for common directories, backup files, admin panels, upload paths, or other predictable locations.

To review that activity, filter for HTTP `GET` requests from the attacker:

    http.request.method == GET && ip.src == <attacker IP>

Focus on the requested paths and the `User-Agent` header. The URIs can show what the attacker was trying to enumerate, while the header may help separate scripted activity from normal browser traffic.

## Post-Exploitation

### Identify Web Shell Activity

Web shell HTTP traffic usually shows up as requests to unusual server-side files with parameters that look tied to command execution.

Useful filters:

    http.request.uri contains ".php?"
    http.request.uri contains "cmd"
    http.request.uri contains "exec"

When reviewing those requests, I’m looking at two things:

- where the file lives on the server
- whether the parameters suggest command execution

The URI often gives away both. A suspicious path can point to the upload location, and parameter names can help confirm that the file is being used as a control point rather than a normal page.

### Look for Tool Staging or Second-Stage Payloads

Once command execution is established, the next question is whether the attacker used that access to pull in something else.

PowerShell is a common next step on Windows systems, especially for staging tools, downloading follow-on payloads, or executing other binaries (LOTL).

Search with:

    http.request.uri contains "powershell"

## C2 Communication

Once the attacker has code running on the host, the next question is whether that access turns into sustained communication.

To look for outbound HTTP traffic from the compromised system, use:

    http && ip.src == <victim IP>

Review the outbound requests and look closely at the request structure and data being sent. Traffic tied to C2 often stands out through repeated callbacks, unusual destinations, encoded values, or identifiers used to track the infected host.

If a beacon ID or similar marker is present, it becomes a useful pivot for understanding how the malware checks in and for spotting related traffic elsewhere.

## Data Exfiltration

> [!NOTE]
> Large HTTP POST requests are worth inspecting, but size alone isn’t enough. The destination, timing, and request body help determine whether the traffic reflects normal application behavior or exfiltration.

If the attack reaches this stage, the focus shifts to what left the host and how it was sent.

HTTP `POST` requests are worth reviewing here since they can carry large amounts of data while blending in with normal application traffic.

Use this filter:

    http.request.method == "POST" && ip.src == <victim IP>

Review the destination URI and the `Content-Length` values for each request. Large payloads, repeated uploads, or unusual endpoints can point to exfiltration rather than routine web traffic.

To inspect the transferred data, right-click a `POST` request and choose `Follow → TCP Stream`. That view can help confirm what was sent and whether the traffic reflects file transfer, staged output, or stolen application data.
