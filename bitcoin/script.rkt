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

(provide (struct-out op)
         (struct-out scriptsig)
         script?
         der->rs
         rs->low-s-der
         push-op
         read-script
         write-script
         remove-codeseparator
         read-der-sig
         encode-scriptsigs
         decode-scriptsig
         make-pkscript-p2pkh
         make-pkscript-p2sh
         make-pkscript-bech32
         address-to-pkscript
         derive-p2sh-redeemscript-multisig
         p2sh-redeemscript->pkscript
         derive-child-redeemscript-multisig
         derive-child-redeemscript
         derive-child-pkscript
         derive-p2sh-redeemscript
         derive-p2sh-pkscript
         encode-scriptsig
         sign-input)

(struct op (code data) #:transparent #:mutable)
(struct scriptsig (der-signature pubkey) #:transparent #:mutable)

(define script? (listof op?))

(define (der->rs bs)
  (match-define
    (hash-table ('r r) ('s s))
    (bytes->asn1/DER (SEQUENCE [r INTEGER] [s INTEGER]) bs))
  (bytes-append
    (integer->bytes r 32 #f #t)
    (integer->bytes s 32 #f #t)))

(define (rs->low-s-der bs [curve secp256k1])
  (define r (bytes->integer (subbytes bs 0 32) #f #t))
  (define s (bytes->integer (subbytes bs 32) #f #t))
  (define order (curve-n curve))
  (define low-s
    (if (> s (quotient order 2))
        (- order s)
        s))
  (asn1->bytes/DER
    (SEQUENCE [r INTEGER] [s INTEGER])
    (hash 'r r 's low-s)))

(define/contract (push-op data)
  (-> bytes? op?)
  (define len (bytes-length data))
  (cond
    [(< len OP_PUSHDATA1)
     (op len data)]
    [(< len 256)
     (op OP_PUSHDATA1 data)]
    [(< len 65536)
     (op OP_PUSHDATA2 data)]
    [else
     (op OP_PUSHDATA4 data)]))

(define (read-script)
  (define b (read-byte))
  (define (read-n b L)
    (define len (read-int L))
    (when (> len (expt 1024 3))
      (error 'read-script "OP_PUSHDATA4 tried to push more than 1MB - something is wrong"))
    (op (op->name b) (read-bytes len)))
  (if (eof-object? b)
      empty
      (cons
       (cond
         [(< b OP_PUSHDATA1)
          (op b (read-bytes b))]
         [(= b OP_PUSHDATA1)
          (read-n b 1)]
         [(= b OP_PUSHDATA2)
          (read-n b 2)]
         [(= b OP_PUSHDATA4)
          (read-n b 4)]
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

(define/contract (encode-scriptsigs redeemscript the-scriptsigs)
  (-> script? (listof scriptsig?) script?)
  (for ([s the-scriptsigs])
    (match-define (scriptsig sig comp-pkey) s)
    (unless (compressed-pubkey? comp-pkey)
      (error 'encode-scriptsigs "expected compressed-pubkey? but got ~a" comp-pkey))
    (unless (and (bytes? sig)
                 (<= 65 (bytes-length sig) 74))
      (error 'encode-scriptsigs "expected signature to be a DER byte string of length between 65 and 74 bytes but got ~a" sig)))
  (define sorted-scriptsigs
    (sort the-scriptsigs (lambda (x y) (bytes<? (scriptsig-pubkey x) (scriptsig-pubkey y)))))
  (define redeemscript-bytes (capture-output (write-script redeemscript)))
  `(,(push-op #"")
    ,@(for/list ([s sorted-scriptsigs])
        (define sig+1 (bytes-append (scriptsig-der-signature s) #"\x01"))
        (push-op sig+1))
    ,(push-op redeemscript-bytes)))

; p2pkh
(define (decode-scriptsig script)
  (match-define (list (op _ signature) (op _ pubkey)) script)
  (scriptsig (subbytes signature 0 (sub1 (bytes-length signature))) pubkey))

(define (make-pkscript-p2pkh payload)
  (unless (= (bytes-length payload) 20)
    (error "Invalid p2pkh payload length"))
  (list (op 'OP_DUP #f) (op 'OP_HASH160 #f) (push-op payload) (op 'OP_EQUALVERIFY #f) (op 'OP_CHECKSIG #f)))

(define (make-pkscript-p2sh payload)
  (unless (= (bytes-length payload) 20)
    (error "Invalid p2sh payload length"))
  (list (op 'OP_HASH160 #f) (push-op payload) (op 'OP_EQUAL #f)))

(define (make-pkscript-bech32 payload)
  (match (bytes-length payload)
    [(or 20 32) (void)]
    [_ (error "Invalid bech32 payload length")])
  (list (push-op #"") (push-op payload)))

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

(define (compressed-pubkey? b)
  (and (bytes? b)
       (= (bytes-length b) 33)
       (member (bytes-ref b 0) '(2 3))
       #t))

(define/contract (derive-p2sh-redeemscript-multisig multisig-m compressed-pubkeys)
  (-> exact-nonnegative-integer? (listof compressed-pubkey?) script?)
  (unless (>= multisig-m 1)
    (error "expected multisig-m >= 1"))
  (unless (<= multisig-m (length compressed-pubkeys))
    (error "expected multisig-m <= number of pubkeys"))
  (unless (<= (length compressed-pubkeys) 16)
    (error "expected at most 16 pubkeys"))
  (unless (= (set-count (list->set compressed-pubkeys))
             (length compressed-pubkeys))
    (error "duplicate pubkeys"))
  (define sorted-pubkeys (sort compressed-pubkeys bytes<?))
  (define op-zero #x50)
  `(
     ,(op (+ multisig-m op-zero) #f)
     ,@(for/list ([pubkey sorted-pubkeys])
         (push-op pubkey))
     ,(op (+ (length sorted-pubkeys) op-zero) #f)
     ,(op 'OP_CHECKMULTISIG #f)
   ))

(define/contract (p2sh-redeemscript->pkscript redeemscript)
  (-> script? script?)
  (define inner-hash
    (ripemd160
     (sha256
      (capture-output (write-script redeemscript)))))
  (list (op 'OP_HASH160 #f) (push-op inner-hash) (op 'OP_EQUAL #f)))

(define (derive-child-redeemscript-multisig multisig-m root-xpubs path)
  (derive-p2sh-redeemscript-multisig
    multisig-m
    (for/list ([root-xpub root-xpubs])
      (point->sec (jacobian->affine (xpub-point (xpub-derive-path root-xpub path)))))))

;; Backwards compatibility
(define (derive-child-redeemscript root-xpub path)
  (derive-child-redeemscript-multisig 1 (list root-xpub) path))

(define (derive-child-pkscript root-xpub path)
  (p2sh-redeemscript->pkscript (derive-child-redeemscript root-xpub path)))

(define (derive-p2sh-redeemscript compressed-pubkey)
  (derive-p2sh-redeemscript-multisig 1 (list compressed-pubkey)))

(define (derive-p2sh-pkscript compressed-pubkey)
  (p2sh-redeemscript->pkscript (derive-p2sh-redeemscript compressed-pubkey)))

(define (encode-scriptsig the-scriptsig)
  (encode-scriptsigs
    (derive-p2sh-redeemscript (scriptsig-pubkey the-scriptsig))
    (list the-scriptsig)))
;;;;;;;;;;;;;;;;;;;

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
