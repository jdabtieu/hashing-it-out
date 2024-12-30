# Hashing It Out: An Analysis of Cryptographic Hash Functions for Password Storage

29 Dec 2024

This repo contains benchmarking code only.<br>
View the paper at <https://jonathanw.dev/public/2024/hashingitout.pdf>

### Abstract
Cryptographic hash functions play a critical role in secured password authentication. To be both secure and practical, these functions should
exhibit a variety of mathematical guarantees, meet
certain performance requirements, and be easily deployable to software
stacks. In this paper, we present a holistic evaluation framework that
considers all mentioned criteria, examining some of the
most popular cryptographic hash functions to determine if there
exists, among these popular hash functions, one option with clear
advantages over all alternatives. We determine that, when properly
configured, scrypt and Argon2 are generally good contenders and
PBKDF2 is acceptable in memory-constrained environments.