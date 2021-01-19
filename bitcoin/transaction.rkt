#lang racket

(require (prefix-in sha: sha)
         binaryio
         "io-helpers.rkt"
         crypto
         crypto/libcrypto
         "script.rkt"
         "script-symbols.rkt"
         base58
         bip32/ripemd160)

(provide (all-defined-out))

(struct outpoint (tx-hash index) #:transparent #:mutable)
(struct txin (outpoint script sequence) #:transparent #:mutable)
(struct txout (value pkscript) #:transparent #:mutable)
(struct tx (ins outs witness lock-time) #:transparent #:mutable)
(struct tx+v tx (version) #:transparent #:mutable)

(define (read-outpoint)
  (outpoint (read-bytes 32) (read-int 4)))

(define (write-outpoint out)
  (write-bytes (outpoint-tx-hash out))
  (write-int 4 (outpoint-index out)))

(define (read-in)
  (txin
   (read-outpoint)
   (with-input-from-bytes (read-lenprebytes) read-script)
   (read-int 4)))

(define (write-in in)
  (write-outpoint (txin-outpoint in))
  (write-lenprebytes
   (with-output-to-bytes
     (thunk (write-script (txin-script in)))))
  (write-int 4 (txin-sequence in)))

(define (read-out)
  (txout
   (read-int 8)
   (with-input-from-bytes (read-lenprebytes) read-script)))

(define (write-out out)
  (write-int 8 (txout-value out))
  (write-lenprebytes
   (with-output-to-bytes
     (thunk (write-script (txout-pkscript out))))))

(define (read-witnesses len)
  (for/list ([i len])
    (read-lenprearray read-lenprebytes)))

(define (write-witnesses wss)
  (for ([ws wss])
    (write-lenprearray write-lenprebytes ws)))

(define (read-transaction)
  (define version (read-int 4))
  (define num-ins-or-flag (read-varint))
  (define num-ins
    (if (= 0 num-ins-or-flag)
        (begin
          (unless (= (read-int 1) 1)
            (error "expected byte value 1 to follow flag varint of value 0"))
          (read-varint))
        num-ins-or-flag))
  (tx+v
   (for/list ([i num-ins])
     (read-in))
   (read-lenprearray read-out)
   (if (= 0 num-ins-or-flag)
       (read-witnesses num-ins)
       empty)
   (read-int 4)
   version))

(define (write-transaction tx)
  (write-int 4
    (if (tx+v? tx) (tx+v-version tx) 1))
  (unless (empty? (tx-witness tx))
    (write-bytes #"\0\1"))
  (write-lenprearray write-in (tx-ins tx))
  (write-lenprearray write-out (tx-outs tx))
  (unless (empty? (tx-witness tx))
    (write-witnesses (tx-witness tx)))
  (write-int 4 (tx-lock-time tx)))

; only for SIGHASH_ALL
(define (get-sighash txn input-idx outpoint-pkscript)
  (define rewritten
    (struct-copy
     tx txn
     [ins
      (for/list ([in (tx-ins txn)]
                 [i (in-naturals)])
        (struct-copy
         txin in
         [script
          (if (= i input-idx)
              (remove-codeseparator outpoint-pkscript)
              empty)]))]))
  (define serialized
    (with-output-to-bytes
      (thunk
       (write-transaction rewritten))))
  (define preimage (bytes-append serialized (integer->bytes 1 4 #f #f)))
  (sha:sha256 (sha:sha256 preimage)))
