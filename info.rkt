#lang setup/infotab
(define version "0.0.2")
(define collection 'multi)
(define deps '("base"
               "binaryio"
               "sha"
               "https://github.com/marckn0x/bech32.git"
               "asn1-lib"
               "bip32"
               "ec"
               "base58"
               "crypto-lib"))
(define build-deps '("racket-doc"
                     "rackunit-lib"
                     "scribble-lib"))
