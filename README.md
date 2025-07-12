<p align="center"><img src="etherdog.png"></p>

* goal
  * Ethereum P2P networking protocols specifications
    * low-level protocols
      - [Ethereum Node Records](./enr.md)
      - [DNS Node Lists](./dnsdisc.md)
      - [Node Discovery Protocol v4](./discv4.md)
      - [Node Discovery Protocol v5](./discv5/discv5.md)
      - [RLPx protocol](./rlpx.md)
    * RLPx-based application-level protocols
      - [Ethereum Wire Protocol](./caps/eth.md)
        - eth/68
      - [Ethereum Snapshot Protocol](./caps/snap.md)
        - snap/1
      - [Light Ethereum Subprotocol](./caps/les.md)
        - les/4
      - [Parity Light Protocol](./caps/pip.md)
        - pip/1
      - [Ethereum Witness Protocol](./caps/wit.md)
        - wit/0

### The Mission

* TODO: devp2p is a set of network protocols which form the Ethereum peer-to-peer network.
'Ethereum network' is meant in a broad sense, i.e. devp2p isn't specific to a particular
blockchain, but should serve the needs of any networked application associated with the
Ethereum umbrella.

We aim for an integrated system of orthogonal parts, implemented in multiple programming
environments. The system provides discovery of other participants throughout the Internet
as well as secure communication with those participants.

The network protocols in devp2p should be easy to implement from scratch given only the
specification, and must work within the limits of a consumer-grade Internet connection. We
usually design protocols in a 'specification first' approach, but any specification
proposed must be accompanied by a working prototype or implementable within reasonable
time.

### Relationship with libp2p

The [libp2p] project was started at about the same time as devp2p and seeks to be a
collection of modules for assembling a peer-to-peer network from modular components.
Questions about the relationship between devp2p and libp2p come up rather often.

It's hard to compare the two projects because they have different scope and are designed
with different goals in mind. devp2p is an integrated system definition that wants to
serve Ethereum's needs well (although it may be a good fit for other applications, too)
while libp2p is a collection of programming library parts serving no single application in
particular.

That said, both projects are very similar in spirit and devp2p is slowly adopting parts of
libp2p as they mature.

### Implementations

* MOST Ethereum clients implement it
  - C#: Nethermind <https://github.com/NethermindEth/nethermind>
  - C++: Aleth <https://github.com/ethereum/aleth>
  - C: Breadwallet <https://github.com/breadwallet/breadwallet-core>
  - Elixir: Exthereum <https://github.com/exthereum/ex_wire>
  - Go: go-ethereum/geth <https://github.com/ethereum/go-ethereum>
  - Java: Tuweni RLPx library <https://github.com/apache/incubator-tuweni/tree/master/rlpx>
  - Java: Besu <https://github.com/hyperledger/besu>
  - JavaScript: EthereumJS <https://github.com/ethereumjs/ethereumjs-devp2p>
  - Kotlin: Tuweni Discovery library <https://github.com/apache/incubator-tuweni/tree/master/devp2p>
  - Nim: Nimbus nim-eth <https://github.com/status-im/nim-eth>
  - Python: Trinity <https://github.com/ethereum/trinity>
  - Ruby: Ciri <https://github.com/ciri-ethereum/ciri>
  - Ruby: ruby-devp2p <https://github.com/cryptape/ruby-devp2p>
  - Rust: rust-devp2p <https://github.com/rust-ethereum/devp2p>
  - Rust: openethereum <https://github.com/openethereum/openethereum>
  - Rust: reth <https://github.com/paradigmxyz/reth>

* [WireShark dissectors](https://github.com/ConsenSys/ethereum-dissectors)

### Issues

* report [protocol level security issues](https://bounty.ethereum.org)

[libp2p]: https://libp2p.io
