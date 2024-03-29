# [Blockchain Commons Crypto Base](https://github.com/BlockchainCommons/bc-crypto-base)

### _by [Wolf McNally](https://www.github.com/wolfmcnally) and [Christopher Allen](https://www.github.com/ChristopherA)_

* <img src="https://github.com/BlockchainCommons/crypto-commons/blob/master/images/logos/crypto-commons-super-simple.png" width=16 valign="bottom">&nbsp;&nbsp; ***part of the [crypto commons](https://github.com/BlockchainCommons/crypto-commons/blob/master/README.md) technology family***

**Well-Reviewed and Audited Cryptographic Functions for Use in [Blockchain Commons](https://www.BlockchainCommons.com)  Software Projects**

These are selected cryptographic functions used by various [Blockchain Commons](https://www.BlockchainCommons.com) software projects that have have been vetted by the developers as having been sufficiently well-reviewed and/or cryptographically audited by other parties, but also meet our specific needs (for instance to be able to run on embedded hardware).

## Installation Instructions

```bash
$ ./configure
$ make check
$ sudo make install
```

This sequence runs the module's unit tests.

## Usage Instructions

1. Link against `libbc-crypto-base.a`.
2. Include the umbrella header in your code:

```c
#include <bc-crypto-base/bc-crypto-base.h>
```

## Notes for Maintainers

Before accepting a PR that can affect build or unit tests, make sure the following sequence of commands succeeds:

```bash
$ ./configure
$ make distcheck
$ make distclean
```

`make distcheck` builds a distribution tarball, unpacks it, then configures, builds, and runs unit tests from it, then performs an install and uninstall from a non-system directory and makes sure the uninstall leaves it clean. `make distclean` removes all known byproduct files, and unless you've added files of your own, should leave the directory in a state that could be tarballed for distribution. After a `make distclean` you'll have to run `./configure` again.

## Origin, Authors, Copyright & Licenses

Unless otherwise noted (either in this [/README.md](./README.md) or in the file's header comments) the contents of this repository are Copyright © 2020 by Blockchain Commons, LLC, and are [licensed](./LICENSE) under the [spdx:BSD-2-Clause Plus Patent License](https://spdx.org/licenses/BSD-2-Clause-Patent.html).

The table below establishes provenance (repository of origin, permalink, and commit id) for each source file in this repository. Contributors to these files are listed in the commit history for each file, first in this repo, then in the repo of their origin.

In most cases, the authors, copyright, and license for each file reside in comments in the source. When it does not we have attempted to attribute it accurately below.

| File      | From                                                         | Commit                                                       | Authors & Copyright (c)                                | License                                                     |
| --------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------ | ----------------------------------------------------------- |
| bc-crypto-hash.h | [blockchaincommons/bc-crypto-base](?) | [?](?) | 2020 Blockchain Commons, LLC  | [BSD-2-Clause-Patent](https://spdx.org/licenses/BSD-2-Clause-Patent.html)                        |
| hmac.c    | [trezor/trezor-firmware](https://github.com/trezor/trezor-firmware/blob/49fe64f84c5fc17f5680daaf03b124a2b8f26c3b/crypto/hmac.c) | [fdad317](https://github.com/trezor/trezor-firmware/commit/fdad317d8c5d11bc4734f8cf07b1d589fb475209) | 2013-2014 Tomas Dzetkulic<br />2013-2014 Pavol Rusnak  | [MIT](https://spdx.org/licenses/MIT)                        |
| hmac.h    | [trezor/trezor-firmware](https://github.com/trezor/trezor-firmware/blob/49fe64f84c5fc17f5680daaf03b124a2b8f26c3b/crypto/hmac.h) | [4e0d813](https://github.com/trezor/trezor-firmware/commit/4e0d813269a5c527b15b33c6adb6ecb476916165) | 2013-2014 Tomas Dzetkulic<br />2013-2014 Pavol Rusnak  | [MIT](https://spdx.org/licenses/MIT)                        |
| memzero.c | [trezor/trezor-firmware](https://github.com/trezor/trezor-firmware/blob/8ddf799cad4f3e5d6f13d22f21154d2d572c8519/crypto/memzero.c)<br>derived from [jedisct1/libsodium](https://github.com/jedisct1/libsodium/blob/1647f0d53ae0e370378a9195477e3df0a792408f/src/libsodium/sodium/utils.c#L102-L130) | [4e0d813](https://github.com/trezor/trezor-firmware/commit/4e0d813269a5c527b15b33c6adb6ecb476916165)<br>[32385c6](https://github.com/jedisct1/libsodium/commit/32385c6b9a00cb2a83c64cba80e8b5962841cd88) | 2013-2019 Frank Denis                                  | [ISC](https://spdx.org/licenses/ISC)                        |
| memzero.h | [trezor/trezor-firmware](https://github.com/trezor/trezor-firmware/blob/8ddf799cad4f3e5d6f13d22f21154d2d572c8519/crypto/memzero.h)<br/>derived from [jedisct1/libsodium](https://github.com/jedisct1/libsodium/blob/1647f0d53ae0e370378a9195477e3df0a792408f/src/libsodium/sodium/utils.c#L102-L130) | [4e0d813](https://github.com/trezor/trezor-firmware/commit/4e0d813269a5c527b15b33c6adb6ecb476916165)<br/>[32385c6](https://github.com/jedisct1/libsodium/commit/32385c6b9a00cb2a83c64cba80e8b5962841cd88) | 2013-2019 Frank Denis                                  | [ISC](https://spdx.org/licenses/ISC)                        |
| options.h | [trezor/trezor-firmware](https://github.com/trezor/trezor-firmware/blob/8ddf799cad4f3e5d6f13d22f21154d2d572c8519/crypto/options.h) | [4e0d813](https://github.com/trezor/trezor-firmware/commit/4e0d813269a5c527b15b33c6adb6ecb476916165) | 2013-2014 Pavol Rusnak                                 | [MIT](https://spdx.org/licenses/MIT)                        |
| pbkdf2.c  | [trezor/trezor-firmware](https://github.com/trezor/trezor-firmware/blob/49fe64f84c5fc17f5680daaf03b124a2b8f26c3b/crypto/pbkdf2.c) | [fdad317](https://github.com/trezor/trezor-firmware/commit/fdad317d8c5d11bc4734f8cf07b1d589fb475209) | 2013-2014 Tomas Dzetkulic<br />2013-2014 Pavol Rusnak  | [BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html) |
| pbkdf2.c  | [trezor/trezor-firmware](https://github.com/trezor/trezor-firmware/blob/49fe64f84c5fc17f5680daaf03b124a2b8f26c3b/crypto/pbkdf2.h) | [4e0d813](https://github.com/trezor/trezor-firmware/commit/4e0d813269a5c527b15b33c6adb6ecb476916165) | 2013-2014 Tomas Dzetkulic<br />2013-2014 Pavol Rusnak  | [BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html) |
| sha2.c    | [trezor/trezor-firmware](https://github.com/trezor/trezor-firmware/blob/49fe64f84c5fc17f5680daaf03b124a2b8f26c3b/crypto/sha2.c) | [fdad317](https://github.com/trezor/trezor-firmware/commit/fdad317d8c5d11bc4734f8cf07b1d589fb475209) | 2000-2001 Aaron D. Gifford<br />2013-2014 Pavol Rusnak | [BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html) |
| sha2.h    | [trezor/trezor-firmware](https://github.com/trezor/trezor-firmware/blob/49fe64f84c5fc17f5680daaf03b124a2b8f26c3b/crypto/sha2.h) | [4e0d813](https://github.com/trezor/trezor-firmware/commit/4e0d813269a5c527b15b33c6adb6ecb476916165) | 2000-2001 Aaron D. Gifford<br />2013-2014 Pavol Rusnak | [BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html) |
| crc32.c<br/>crc32.h | NA | NA | 2020 Wolf McNally for Blockchain Commons | [BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html) |

### Used by …

- [bc-shamir](https://github.com/BlockchainCommons/bc-shamir) — Blockchain Common's Shamir Secret Sharing Library

### Derived from…

- [trezor/trezor-firmware/crypto](https://github.com/trezor/trezor-firmware/tree/master/crypto) — Heavily optimized cryptography algorithms for embedded devices, used by both Trezor Core and the Trezor One firmware, from Satoshi Labs ([docs](https://github.com/trezor/trezor-firmware/blob/master/docs/index.md)).

### Dependencies

- autotools - Gnu Build System from Free Software Foundation ([intro](https://www.gnu.org/software/automake/manual/html_node/Autotools-Introduction.html)).

## Financial Support

*Blockchain Commons Crypto Base* is a project of [Blockchain Commons](https://www.blockchaincommons.com/). We are proudly a "not-for-profit" social benefit corporation committed to open source & open development. Our work is funded entirely by donations and collaborative partnerships with people like you. Every contribution will be spent on building open tools, technologies, and techniques that sustain and advance blockchain and internet security infrastructure and promote an open web.

To financially support further development of *Blockchain Commons Crypto Base* and other projects, please consider becoming a Patron of Blockchain Commons through ongoing monthly patronage as a [GitHub Sponsor](https://github.com/sponsors/BlockchainCommons). You can also support Blockchain Commons with bitcoins at our [BTCPay Server](https://btcpay.blockchaincommons.com/).

## Contributing

We encourage public contributions through issues and pull-requests! Please review [CONTRIBUTING.md](./CONTRIBUTING.md) for details on our development process. All contributions to this repository require a GPG signed [Contributor License Agreement](./CLA.md).

### Discussions

The best place to talk about Blockchain Commons and its projects is in our GitHub Discussions areas.

[**Gordian Developer Community**](https://github.com/BlockchainCommons/Gordian-Developer-Community/discussions). For standards and open-source developers who want to talk about interoperable wallet specifications, please use the Discussions area of the [Gordian Developer Community repo](https://github.com/BlockchainCommons/Gordian-Developer-Community/discussions). This is where you talk about Gordian specifications such as [Gordian Envelope](https://github.com/BlockchainCommons/Gordian/tree/master/Envelope#articles), [bc-shamir](https://github.com/BlockchainCommons/bc-shamir), [Sharded Secret Key Reconstruction](https://github.com/BlockchainCommons/bc-sskr), and [bc-ur](https://github.com/BlockchainCommons/bc-ur) as well as the larger [Gordian Architecture](https://github.com/BlockchainCommons/Gordian/blob/master/Docs/Overview-Architecture.md), its [Principles](https://github.com/BlockchainCommons/Gordian#gordian-principles) of independence, privacy, resilience, and openness, and its macro-architectural ideas such as functional partition (including airgapping, the original name of this community).

[**Blockchain Commons Discussions**](https://github.com/BlockchainCommons/Community/discussions). For developers, interns, and patrons of Blockchain Commons, please use the discussions area of the [Community repo](https://github.com/BlockchainCommons/Community) to talk about general Blockchain Commons issues, the intern program, or topics other than those covered by the [Gordian Developer Community](https://github.com/BlockchainCommons/Gordian-Developer-Community/discussions) or the 
[Gordian User Community](https://github.com/BlockchainCommons/Gordian/discussions).

### Other Questions & Problems

As an open-source, open-development community, Blockchain Commons does not have the resources to provide direct support of our projects. Please consider the discussions area as a locale where you might get answers to questions. Alternatively, please use this repository's [issues](./issues) feature. Unfortunately, we can not make any promises on response time.

If your company requires support to use our projects, please feel free to contact us directly about options. We may be able to offer you a contract for support from one of our contributors, or we might be able to point you to another entity who can offer the contractual support that you need.


### Credits

The following people directly contributed to this repository. You can add your name here by getting involved — the first step is to learn how to contribute from our [CONTRIBUTING.md](./CONTRIBUTING.md) documentation.

| Name              | Role                | Github                                            | Email                                 | GPG Fingerprint                                    |
| ----------------- | ------------------- | ------------------------------------------------- | ------------------------------------- | -------------------------------------------------- |
| Christopher Allen | Principal Architect | [@ChristopherA](https://github.com/ChristopherA) | \<ChristopherA@LifeWithAlacrity.com\> | FDFE 14A5 4ECB 30FC 5D22  74EF F8D3 6C91 3574 05ED |
| Wolf McNally      | Project Lead        | [@WolfMcNally](https://github.com/wolfmcnally)    | \<Wolf@WolfMcNally.com\>              | 9436 52EE 3844 1760 C3DC  3536 4B6C 2FCF 8947 80AE |

## Responsible Disclosure

We want to keep all our software safe for everyone. If you have discovered a security vulnerability, we appreciate your help in disclosing it to us in a responsible manner. We are unfortunately not able to offer bug bounties at this time.

We do ask that you offer us good faith and use best efforts not to leak information or harm any user, their data, or our developer community. Please give us a reasonable amount of time to fix the issue before you publish it. Do not defraud our users or us in the process of discovery. We promise not to bring legal action against researchers who point out a problem provided they do their best to follow the these guidelines.

### Reporting a Vulnerability

Please report suspected security vulnerabilities in private via email to ChristopherA@BlockchainCommons.com (do not use this email for support). Please do NOT create publicly viewable issues for suspected security vulnerabilities.

The following keys may be used to communicate sensitive information to developers:

| Name              | Fingerprint                                        |
| ----------------- | -------------------------------------------------- |
| Christopher Allen | FDFE 14A5 4ECB 30FC 5D22  74EF F8D3 6C91 3574 05ED |

You can import a key by running the following command with that individual’s fingerprint: `gpg --recv-keys "<fingerprint>"` Ensure that you put quotes around fingerprints that contain spaces.

## Version History

### 0.2.0, 7/1/2020

* Added functions for computing CRC-32 checksums.

### 0.1.0, 5/19/2020

* Initial release.
