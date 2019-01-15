# rieTools

rieTools is a collection of tools related to the Riecoin project. Its purpose is mainly personal, to help me do some testing or better understand some concepts. Or simply for convenience. But who knows if they could be useful to other people (not necessarily related to Riecoin), so I make them public.

## Current tools

* constellationsGen: generate prime constellations of a given type, can use wheel factorization;
* constellationCheck: simple tool to check if a number is the base prime of a prime constellation;
* keysGen: generates Riecoin addresses with the private and public keys;
* blockHeaderDecode: decodes a given Riecoin block header and tell if the numbers of its 6-tuple are primes.

## Compilation

The codes depend on GMP (with its C++ wrapper) or on LibSsl (LibCrypto), please install these dependencies.

Then compile all tools with `make`, or individially with for example `make keysGen`.

Only tested on Linux (Debian 9).

## Author and license

* [Pttn](https://github.com/Pttn), contact: dev at Pttn dot me

This work is released under the MIT license. See the [LICENSE](LICENSE) for details.

## Resources

* Some links given in the files.
