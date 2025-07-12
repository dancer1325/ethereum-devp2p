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

* devp2p
  * == set of network protocols / 
    * form the Ethereum P2P network
    * ❌NOT specific -- to a -- particular blockchain❌
    * easy to implement from scratch -- based on the -- specification
    * MUST work | consumer-grade Internet connection
    * follow 'specification first' approach + working prototype 
  * == orthogonal parts / 
    * implemented | MULTIPLE programming environments
  * provides  
    * discovery of -- , throughout Internet, -- other participants
    * secure communication -- with -- those participants
  * 's goal
    * serve Ethereum's needs
  * is adopting parts of libp2p

### Relationship with libp2p

* [libp2p project](https://libp2p.io)
  * started | SAME time -- as -- devp2p
  * == collection of modules / 
    * FROM modular components -- assemble a -- P2P network
  * vs devp2p
    * DIFFERENT 
      * scope
      * design
  * 's goal
    * NO serve 1! specific application

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
