# The RLPx Transport Protocol

* RLPx transport protocol
  * := TCP-based transport protocol / 
    * carries encrypted messages / negotiated | connection establishment
  * uses
    * Ethereum node1 can communicate -- with -- Ethereum node1
  * history
    * RLP
      * original name
        * NOT acronym
    * RLPx
      * named after [RLP serialization format](https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp)
  * CURRENT version
    * 5

## Notation

* `X || Y`
  * == concatenate X & Y
  * _Example:_  X = "hello", Y = "world" -> X || Y = "helloworld"
* `X ^ Y`
  * byte-wise XOR of X & Y
  * _Examples:_
    * 0 ^ 0 = 0
    * 0 ^ 1 = 1
    * 1 ^ 0 = 1
    * 1 ^ 1 = 0
* `X[:N]`
  * N-byte prefix -- of -- X
    * == take FIRST N-byte prefix -- of -- X 
  * _Example:_ X = [0x12, 0x34, 0x56, 0x78, 0xAB, 0xCD]
    * X[:2] = [0x12, 0x34]        
    * X[:4] = [0x12, 0x34, 0x56, 0x78]  
* `[X, Y, Z, ...]`
  * recursive encoding -- as an -- RLP list
  * _Example:_ auth-body = [signature_bytes, pubkey_bytes, nonce_bytes, 4]
    * signature_bytes → RLP encoding → encoded_sig
    * pubkey_bytes → RLP encoding → encoded_pubkey
    * nonce_bytes → RLP encoding → encoded_nonce
    * 4 → RLP encoding → encoded_version
* `keccak256(MESSAGE)`
  * Keccak256 hash function -- as used by -- Ethereum
* `ecies.encrypt(PUBKEY, MESSAGE, AUTHDATA)`
  * asymmetric authenticated encryption function -- as used by -- RLPx
    * ECIES == Elliptic Curve Integrated Encryption Scheme
  * AUTHDATA 
    * == authenticated data / 
      * ❌NOT included | ciphertext❌
      * BEFORE generating the message tag, written -- to -- HMAC-256 
* `ecdh.agree(PRIVKEY, PUBKEY)`
  * elliptic curve Diffie-Hellman

## ECIES Encryption

* TODO: 
ECIES (Elliptic Curve Integrated Encryption Scheme) is an asymmetric encryption method
used in the RLPx handshake. The cryptosystem used by RLPx is

- The elliptic curve secp256k1 with generator `G`.
- `KDF(k, len)`: the NIST SP 800-56 Concatenation Key Derivation Function
- `MAC(k, m)`: HMAC using the SHA-256 hash function.
- `AES(k, iv, m)`: the AES-128 encryption function in CTR mode.

Alice wants to send an encrypted message that can be decrypted by Bobs static private key
<code>k<sub>B</sub></code>. Alice knows about Bobs static public key
<code>K<sub>B</sub></code>.

To encrypt the message `m`, Alice generates a random number `r` and corresponding elliptic
curve public key `R = r * G` and computes the shared secret <code>S = P<sub>x</sub></code>
where <code>(P<sub>x</sub>, P<sub>y</sub>) = r * K<sub>B</sub></code>. She derives key
material for encryption and authentication as
<code>k<sub>E</sub> || k<sub>M</sub> = KDF(S, 32)</code> as well as a random
initialization vector `iv`. Alice sends the encrypted message `R || iv || c || d` where
<code>c = AES(k<sub>E</sub>, iv , m)</code> and
<code>d = MAC(sha256(k<sub>M</sub>), iv || c)</code> to Bob.

For Bob to decrypt the message `R || iv || c || d`, he derives the shared secret
<code>S = P<sub>x</sub></code> where
<code>(P<sub>x</sub>, P<sub>y</sub>) = k<sub>B</sub> * R</code> as well as the encryption and
authentication keys <code>k<sub>E</sub> || k<sub>M</sub> = KDF(S, 32)</code>. Bob verifies
the authenticity of the message by checking whether
<code>d == MAC(sha256(k<sub>M</sub>), iv || c)</code> then obtains the plaintext as
<code>m = AES(k<sub>E</sub>, iv || c)</code>.

## Node Identity

* cryptographic operations
  * 👀are -- based on the -- `secp256k1` elliptic curve👀

* EACH node
  * 💡should maintain a static `secp256k1` private key💡 /
    * saved
    * 👀restored BETWEEN sessions👀
    * recommendation
      * only reset MANUALLY
        * _Example:_ | delete a file or database entry

## Initial Handshake

* RLPx connection
  * established -- by creating a -- TCP connection
  * agreeing | ephemeral key material -- for -- further encrypted & authenticated communication

* 'initiator'
  * := node / opened the TCP connection 
* 'recipient'
  * := node / accepted the TCP connection

* 'handshake'
  * == process of creating those session keys /
    * carried out BETWEEN 'initiator' -- & -- 'recipient'
  * steps
    1. initiator 
       1. connects -- to -- recipient
       2. sends its `auth` message
    2. recipient
       1. accepts, decrypts & verifies `auth` (recovery of signature == `keccak256(ephemeral-pubk)`)
       2. generates `auth-ack` message -- from -- `remote-ephemeral-pubk` & `nonce`
       3. derives secrets & sends the first encrypted frame message (== [Hello](#hello-0x00)) 
    3. initiator
       1. receives `auth-ack` & derives secrets
       2. sends its first encrypted frame message (== [Hello](#hello-0x00))
    4. recipient
       1. receives & authenticates first encrypted frame
    5. initiator
       1. receives & authenticates first encrypted frame
    6. if MAC of first encrypted frame is valid | BOTH sides -> cryptographic handshake is complete 

* if authentication of the first framed packet fails -> either side may disconnect 

* handshake messages

    auth = auth-size || enc-auth-body
    auth-size = size of enc-auth-body, encoded as a big-endian 16-bit integer
    auth-vsn = 4
    auth-body = [sig, initiator-pubk, initiator-nonce, auth-vsn, ...]
    enc-auth-body = ecies.encrypt(recipient-pubk, auth-body || auth-padding, auth-size)
    auth-padding = arbitrary data

    ack = ack-size || enc-ack-body
    ack-size = size of enc-ack-body, encoded as a big-endian 16-bit integer
    ack-vsn = 4
    ack-body = [recipient-ephemeral-pubk, recipient-nonce, ack-vsn, ...]
    enc-ack-body = ecies.encrypt(initiator-pubk, ack-body || ack-padding, ack-size)
    ack-padding = arbitrary data

* implementations must ignore any
  * mismatches | `auth-vsn` & `ack-vsn`
  * additional list elements | `auth-body` & `ack-body`

* secrets / generated -- following the -- exchange of handshake messages

    static-shared-secret = ecdh.agree(privkey, remote-pubk)
    ephemeral-key = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
    shared-secret = keccak256(ephemeral-key || keccak256(nonce || initiator-nonce))
    aes-secret = keccak256(ephemeral-key || shared-secret)
    mac-secret = keccak256(ephemeral-key || aes-secret)

## Framing

All messages following the initial handshake are framed. A frame carries a single
encrypted message belonging to a capability.

The purpose of framing is multiplexing multiple capabilities over a single connection.
Secondarily, as framed messages yield reasonable demarcation points for message
authentication codes, supporting an encrypted and authenticated stream becomes
straight-forward. Frames are encrypted and authenticated via key material generated during
the handshake.

The frame header provides information about the size of the message and the message's
source capability. Padding is used to prevent buffer starvation, such that frame
components are byte-aligned to block size of cipher.

    frame = header-ciphertext || header-mac || frame-ciphertext || frame-mac
    header-ciphertext = aes(aes-secret, header)
    header = frame-size || header-data || header-padding
    header-data = [capability-id, context-id]
    capability-id = integer, always zero
    context-id = integer, always zero
    header-padding = zero-fill header to 16-byte boundary
    frame-ciphertext = aes(aes-secret, frame-data || frame-padding)
    frame-padding = zero-fill frame-data to 16-byte boundary

See the [Capability Messaging] section for definitions of `frame-data` and `frame-size.`

### MAC

Message authentication in RLPx uses two keccak256 states, one for each direction of
communication. The `egress-mac` and `ingress-mac` keccak states are continuously updated
with the ciphertext of bytes sent (egress) or received (ingress). Following the initial
handshake, the MAC states are initialized as follows:

Initiator:

    egress-mac = keccak256.init((mac-secret ^ recipient-nonce) || auth)
    ingress-mac = keccak256.init((mac-secret ^ initiator-nonce) || ack)

Recipient:

    egress-mac = keccak256.init((mac-secret ^ initiator-nonce) || ack)
    ingress-mac = keccak256.init((mac-secret ^ recipient-nonce) || auth)

When a frame is sent, the corresponding MAC values are computed by updating the
`egress-mac` state with the data to be sent. The update is performed by XORing the header
with the encrypted output of its corresponding MAC. This is done to ensure uniform
operations are performed for both plaintext MAC and ciphertext. All MACs are sent
cleartext.

    header-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16]) ^ header-ciphertext
    egress-mac = keccak256.update(egress-mac, header-mac-seed)
    header-mac = keccak256.digest(egress-mac)[:16]

Computing `frame-mac`:

    egress-mac = keccak256.update(egress-mac, frame-ciphertext)
    frame-mac-seed = aes(mac-secret, keccak256.digest(egress-mac)[:16]) ^ keccak256.digest(egress-mac)[:16]
    egress-mac = keccak256.update(egress-mac, frame-mac-seed)
    frame-mac = keccak256.digest(egress-mac)[:16]

Verifying the MAC on ingress frames is done by updating the `ingress-mac` state in the
same way as `egress-mac` and comparing to the values of `header-mac` and `frame-mac` in
the ingress frame. This should be done before decrypting `header-ciphertext` and
`frame-ciphertext`.

# Capability Messaging

All messages following the initial handshake are associated with a 'capability'. Any
number of capabilities can be used concurrently on a single RLPx connection.

A capability is identified by a short ASCII name (max eight characters) and version number. The capabilities
supported on either side of the connection are exchanged in the [Hello] message belonging
to the 'p2p' capability which is required to be available on all connections.

## Message Encoding

The initial [Hello] message is encoded as follows:

    frame-data = msg-id || msg-data
    frame-size = length of frame-data, encoded as a 24bit big-endian integer

where `msg-id` is an RLP-encoded integer identifying the message and `msg-data` is an RLP
list containing the message data.

All messages following Hello are compressed using the Snappy algorithm.

    frame-data = msg-id || snappyCompress(msg-data)
    frame-size = length of frame-data encoded as a 24bit big-endian integer

Note that the `frame-size` of compressed messages refers to the compressed size of
`msg-data`. Since compressed messages may inflate to a very large size after
decompression, implementations should check for the uncompressed size of the data before
decoding the message. This is possible because the [snappy format] contains a length
header. Messages carrying uncompressed data larger than 16 MiB should be rejected by
closing the connection.

## Message ID-based Multiplexing

While the framing layer supports a `capability-id`, the current version of RLPx doesn't
use that field for multiplexing between different capabilities. Instead, multiplexing
relies purely on the message ID.

Each capability is given as much of the message-ID space as it needs. All such
capabilities must statically specify how many message IDs they require. On connection and
reception of the [Hello] message, both peers have equivalent information about what
capabilities they share (including versions) and are able to form consensus over the
composition of message ID space.

Message IDs are assumed to be compact from ID 0x10 onwards (0x00-0x0f is reserved for the
"p2p" capability) and given to each shared (equal-version, equal-name) capability in
alphabetic order. Capability names are case-sensitive. Capabilities which are not shared
are ignored. If multiple versions are shared of the same (equal name) capability, the
numerically highest wins, others are ignored.

## "p2p" Capability

* "p2p" capability
  * 👀is present | ALL connections👀

* AFTER initial handshake,
  * initiator & recipient must send 
    * [Hello](#hello-0x00) message OR
    * [Disconnect](#disconnect-0x01) message

* | receive the [Hello](#hello-0x00) message,
  * 💡session is active💡
  * any other message -- may be -- sent

* implementations MUST ignore differences in protocol version
  * Reason:🧠forward-compatibility reasons🧠
  * if communicate / peer of lower version -> implementations should try to mimic that version

* AFTER protocol negotiation
  * [Disconnect](#disconnect-0x01) message -- may be -- sent

### Hello (0x00)

* `[protocolVersion: P, clientId: B, capabilities, listenPort: P, nodeKey: B_64, ...]`
  * `protocolVersion`
    * == "p2p" capability version
    * == 5
  * `clientId`
    * == client software identity / human-readable string
      * _Example:_ "Ethereum(++)/1.0.0"
  * `capabilities`
    * == list of SUPPORTED capabilities + their versions
    * == `[[cap1, capVersion1], [cap2, capVersion2], ...]`
  * `listenPort`
    * ⚠️legacy⚠️
      * == NOT use it
    * == port | client is listening on
      * == interface / present connection traverses
    * ❌if 0 -> client is NOT listening❌ 
  * `nodeId`
    * == `secp256k1` public key / 
      * correspond -- to the -- node's private key
  * recommendations
    * ❌NOT add ADDITIONAL elements❌
      * Reason:🧠they may be used | future versions🧠

* := FIRST packet 
  * / sent
    * -- over the -- connection
    * 1! -- by -- both sides
  * == ⚠️UNTIL it's received -> NO OTHER messages may be sent ⚠️

### Disconnect (0x01)

* `[reason: P]`
  * OPTIONAL
  * integer

* goal
  * send -- to the -- peer / disconnection is imminent
    * if it's received -> a peer should disconnect IMMEDIATELY
    * well-behaved hosts give their peers a chance (2 seconds) -- to -- disconnect themselves

| Reason -- to -- disconnect | Meaning                                                      |
|----------------------------|:-------------------------------------------------------------|
| `0x00`                     | Disconnect requested                                         |
| `0x01`                     | TCP sub-system error                                         |
| `0x02`                     | Breach of protocol, e.g. a malformed message, bad RLP, ...   |
| `0x03`                     | Useless peer                                                 |
| `0x04`                     | Too many peers                                               |
| `0x05`                     | Already connected                                            |
| `0x06`                     | Incompatible P2P protocol version                            |
| `0x07`                     | Null node identity received - this is automatically invalid  |
| `0x08`                     | Client quitting                                              |
| `0x09`                     | Unexpected identity in handshake                             |
| `0x0a`                     | Identity is the same as this node (i.e. connected to itself) |
| `0x0b`                     | Ping timeout                                                 |
| `0x10`                     | Some other reason specific to a subprotocol                  |

### Ping (0x02)

`[]`

Requests an immediate reply of [Pong] from the peer.

### Pong (0x03)

`[]`

Reply to the peer's [Ping] packet.

# Change Log

### Known Issues in the current version

- The frame encryption/MAC scheme is considered 'broken' because `aes-secret` and
  `mac-secret` are reused for both reading and writing. The two sides of a RLPx connection
  generate two CTR streams from the same key, nonce and IV. If an attacker knows one
  plaintext, they can decrypt unknown plaintexts of the reused keystream.
- General feedback from reviewers has been that the use of a keccak256 state as a MAC
  accumulator and the use of AES in the MAC algorithm is an uncommon and overly complex
  way to perform message authentication but can be considered safe.
- The frame encoding provides `capability-id` and `context-id` fields for multiplexing
  purposes, but these fields are unused.

### Version 5 (EIP-706, September 2017)

[EIP-706] added Snappy message compression.

### Version 4 (EIP-8, December 2015)

[EIP-8] changed the encoding of `auth-body` and `ack-body` in the initial handshake to
RLP, added a version number to the handshake and mandated that implementations should
ignore additional list elements in handshake messages and [Hello].

# References

- Elaine Barker, Don Johnson, and Miles Smid. NIST Special Publication 800-56A Section 5.8.1,
  Concatenation Key Derivation Function. 2017.\
  URL <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-56ar.pdf>

- Victor Shoup. A proposal for an ISO standard for public key encryption, Version 2.1. 2001.\
  URL <http://www.shoup.net/papers/iso-2_1.pdf>

- Mike Belshe and Roberto Peon. SPDY Protocol - Draft 3. 2014.\
  URL <http://www.chromium.org/spdy/spdy-protocol/spdy-protocol-draft3>

- Snappy compressed format description. 2011.\
  URL <https://github.com/google/snappy/blob/master/format_description.txt>

Copyright &copy; 2014 Alex Leverington.
<a rel="license" href="http://creativecommons.org/licenses/by-nc-sa/4.0/">
This work is licensed under a
Creative Commons Attribution-NonCommercial-ShareAlike
4.0 International License</a>.

[Hello]: #hello-0x00
[Disconnect]: #disconnect-0x01
[Ping]: #ping-0x02
[Pong]: #pong-0x03
[Capability Messaging]: #capability-messaging
[EIP-8]: https://eips.ethereum.org/EIPS/eip-8
[EIP-706]: https://eips.ethereum.org/EIPS/eip-706
[RLP]: 
[snappy format]: https://github.com/google/snappy/blob/master/format_description.txt
