#lang racket

(require "script-symbols.rkt"
         "io-helpers.rkt"
         bech32
         bip32
         ec
         base58
         bip32/ripemd160
         binaryio
         sha
         asn1
         (except-in crypto bytes->hex-string)
         crypto/libcrypto)

(provide (all-defined-out))

(struct op (code data) #:transparent #:mutable)
(struct scriptsig (der-signature pubkey) #:transparent #:mutable)

(define (der->rs bs)
  (match-define
    (hash-table ('r r) ('s s))
    (bytes->asn1/DER (SEQUENCE [r INTEGER] [s INTEGER]) bs))
  (bytes-append
    (integer->bytes r 32 #f #t)
    (integer->bytes s 32 #f #t)))

(define (rs->low-s-der bs)
  (define r (bytes->integer (subbytes bs 0 32) #f #t))
  (define s (bytes->integer (subbytes bs 32) #f #t))
  (define order (curve-n secp256k1))
  (define low-s
    (if (> s (quotient order 2))
        (- order s)
        s))
  (asn1->bytes/DER
    (SEQUENCE [r INTEGER] [s INTEGER])
    (hash 'r r 's low-s)))

(define (read-script)
  (define b (read-byte))
  (if (eof-object? b)
      empty
      (cons
       (cond
         [(< b OP_PUSHDATA1)
          (op b (read-bytes b))]
         [(= b OP_PUSHDATA1)
          (op (op->name b) (read-bytes (read-int 1)))]
         [(= b OP_PUSHDATA2)
          (op (op->name b) (read-bytes (read-int 2)))]
         [(= b OP_PUSHDATA4)
          (op (op->name b) (read-bytes (read-int 4)))]
         [else (op (op->name b) #f)])
       (read-script))))

(define (write-script script)
  (for ([o script])
    (match-define (op code data) o)
    (define b (if (symbol? code) (name->op code) code))
    (write-byte b)
    (cond
      [(< b OP_PUSHDATA1)
       (write-bytes data)]
      [(= b OP_PUSHDATA1)
       (write-int 1 (bytes-length data))
       (write-bytes data)]
      [(= b OP_PUSHDATA2)
       (write-int 2 (bytes-length data))
       (write-bytes data)]
      [(= b OP_PUSHDATA4)
       (write-int 4 (bytes-length data))
       (write-bytes data)])))

(define (remove-codeseparator script)
  (for/list ([op script] #:unless (eq? (op-code op) 'OP_CODESEPARATOR)) op))

(define (read-der-sig)
  (define (assert-byte byte expected-byte)
    (unless (= byte expected-byte)
      (error (format "invalid der signature: expected byte ~a but got ~a" expected-byte byte))))
  (assert-byte (read-byte) #x30)
  (read-byte)
  (assert-byte (read-byte) #x02)
  (define r (bytes->integer (read-bytes (read-byte)) #t #t))
  (assert-byte (read-byte) #x02)
  (define s (bytes->integer (read-bytes (read-byte)) #t #t))
  (list r s))

(define (encode-scriptsig the-scriptsig)
  (match-define (scriptsig signature compressed-pubkey) the-scriptsig)
  (define sig+1 (bytes-append signature #"\x01"))
  (unless (<= 66 (bytes-length sig+1) 75) (error "signature wrong length"))
  (unless (= (bytes-length compressed-pubkey) 33) (error "pubkey wrong length"))
  (define redeem-script-bytes
    (capture-output
      (write-script (derive-p2sh-redeemscript compressed-pubkey))))
  (list
    (op 'OP_0 #"")
    (op (bytes-length sig+1) sig+1)
    (op (bytes-length redeem-script-bytes) redeem-script-bytes)))

(define (decode-scriptsig script)
  (match-define (list (op _ signature) (op _ pubkey)) script)
  (scriptsig (subbytes signature 0 (sub1 (bytes-length signature))) pubkey))

(define (make-pkscript-p2pkh payload)
  (list (op 'OP_DUP #f) (op 'OP_HASH160 #f) (op 20 payload) (op 'OP_EQUALVERIFY #f) (op 'OP_CHECKSIG #f)))

(define (make-pkscript-p2sh payload)
  (list (op 'OP_HASH160 #f) (op 20 payload) (op 'OP_EQUAL #f)))

(define (make-pkscript-bech32 payload)
  (match (bytes-length payload)
    [(or 20 32) (void)]
    [_ (error "Invalid bech32 payload length")])
  (list (op 'OP_0 #"") (op (bytes-length payload) payload)))

(define (address-to-pkscript addr)
  (match (string-downcase (substring addr 0 2))
    [(or "bc" "tb") (make-pkscript-bech32 (bech32-decode addr))]
    [_
     (define v+p (base58-decode addr))
     (define version (bytes-ref v+p 0))
     (define payload (subbytes v+p 1))
     (unless (= (bytes-length payload) 20)
       (error "expected payload length of 20 bytes"))
     (match version
       [(or 0 111) (make-pkscript-p2pkh payload)]
       [(or 5 196) (make-pkscript-p2sh payload)]
       [_ (error "bad version byte in base58 address")])]))

(define (derive-p2sh-redeemscript compressed-pubkey)
  (unless (equal? (bytes-length compressed-pubkey) 33)
    (error "expected compressed-pubkey to have length 33 bytes"))
  (list (op 'OP_1 #f) (op 33 compressed-pubkey) (op 'OP_1 #f) (op 'OP_CHECKMULTISIG #f)))

(define (derive-p2sh-pkscript compressed-pubkey)
  (define inner-hash
    (ripemd160
     (sha256
      (capture-output (write-script (derive-p2sh-redeemscript compressed-pubkey))))))
  (list (op 'OP_HASH160 #f) (op 20 inner-hash) (op 'OP_EQUAL #f)))

(define ((make-with-child-key proc) root-xpub path)
  (proc
   (point->sec (jacobian->affine (xpub-point (xpub-derive-path root-xpub path))))))

(define derive-child-pkscript (make-with-child-key derive-p2sh-pkscript))

(define derive-child-redeemscript (make-with-child-key derive-p2sh-redeemscript))

(define (sign-input signing-xkey sighash)
  (parameterize
     ([crypto-factories (list libcrypto-factory)])
    (define params (generate-pk-parameters 'ec '((curve "secp256k1"))))
    (define curve-oid (third (pk-parameters->datum params 'rkt-params)))
    (define pubkey (point->sec
                     (jacobian->affine (xpub-point (N signing-xkey)))
                     #:compressed? #f))
    (define key
      (datum->pk-key
        `(ec private ,curve-oid ,pubkey ,(xpriv-exponent signing-xkey))
        'rkt-private))
    (der->rs (pk-sign key sighash))))
