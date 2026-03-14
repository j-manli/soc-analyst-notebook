# Cobalt Strike Traffic Analysis

This workflow is a condensed reference for reviewing suspected Cobalt Strike traffic in Wireshark. 
The main things I want to keep straight are the beacon’s callback rhythm, the layered encryption in the traffic, and what needs to be recovered before decryption is possible.

## Beacon Pattern and Encryption

Cobalt Strike traffic usually follows a simple rhythm:

**check-in → tasking → response → sleep → repeat**

Changes in callback timing, payload size, or frequency can suggest a shift from routine beaconing to interactive operator use.

I also want to keep the layered encryption in mind:

**TLS → hides the transport**  
**AES → protects the beacon payload**  
**HMAC → validates payload integrity**  
**RSA → protects key exchange**

## Decrypt the TLS Layer

In Wireshark, load the PCAP, then go to:

`Edit → Preferences → Protocols → TLS`

In the **(Pre)-Master-Secret log filename** field, load the TLS key and apply the change.

Once that’s in place, packets that previously showed up as generic TLS application data should start resolving into HTTP.

## Extract Beacon Metadata from the HTTP Layer

Once the TLS is decrypted, start looking for the metadata tied to the beacon session.

A good place to start is the `Cookie` header in the beacon’s HTTP requests. Long, encoded-looking values are worth investigating and may appear across callbacks.

To review that traffic in Wireshark:

    http.request

From there, expand the HTTP headers and inspect the `Cookie` value of the packet tied to the suspected beacon traffic.

## Decrypt the Metadata

### Normalize the Cookie Value

Before passing the cookie to a tool like `cs-decrypt-metadata.py`, I need to decode the value from base64URL into standard Base64 format.

There are many online encoders and decoders, but I used this quick Python snippet to clean it up:

```python
b64url = input("\nEnter base64url string: ").strip()
b64 = b64url + '=' * (-len(b64url) % 4)
b64 = b64.replace('-', '+').replace('_', '/')
print(f"\nOutput: {b64}")
```

After normalizing the encoded value, [Didier Stevens' `cs-decrypt-metadata.py`](https://github.com/DidierStevens/DidierStevensSuite/blob/master/cs-decrypt-metadata.py) can be used to decrypt the metadata.

> [!NOTE]
> Beacon keys are not something I should expect to have by default.
>
> In practice, they usually come from deeper access to the attacker’s infrastructure e.g. seized or otherwise recovered teamserver material.

Command:
```python
    cs-decrypt-metadata.py -f <path to beacon keys file> "<standardized base64 string>"
```

This script takes the encoded metadata, decrypts it with the beacon private key, and recovers the session-specific `AES` and `HMAC` values from it.

## Use the Metadata as a Pivot

Recovered metadata can help tie the network activity back to the host with field values for `hostname`, `user account`, and `process name`.

But one of the more useful values from the output is the process ID, `PID`. 
Use this value to investigate: 
- logs
- process creation
- process trees
- EDR telemetry

## Decrypt Beacon Payloads

In Wireshark, look for HTTP traffic carrying beacon tasking or output.  
For example:

- HTTP responses sent back to the compromised host
- HTTP `POST` requests sent from the compromised host

Queries:

    http && ip.dst == <compromised_host_IP>

or

    http.request.method == "POST" && ip.src == <compromised_host_IP>

After isolating a packet, inspect the HTTP message body and copy the encrypted payload, `right-click → Copy → Value → Printable Text`.

Copy and paste that value into a txt file e.g.:

    cs_data.txt

For payload parsing: [Didier Stevens' `cs-parse-traffic.py`](https://github.com/DidierStevens/DidierStevensSuite/blob/master/cs-parse-traffic.py)

This tool will need the session-specific `AES` and `HMAC` values retrieved from the `cs-decrypt-metadata.py` script in order to decrypt the payload.

> [!NOTE]
> This has to be repeated per payload (packet). Once decrypted, the tasking becomes much clearer, including commands to the beacon and command output visible to the attacker.
>
> Also look for `PowerShell` to see if it was used for follow-on collection, compression, staging, or exfiltration.
