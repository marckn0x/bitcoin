#lang racket

(require binaryio
         "io-helpers.rkt"
         "transaction.rkt")

(provide (all-defined-out))

(struct block
        (version
         previous-hash
         merkle-root
         timestamp
         difficulty-target
         nonce
         transactions)
        #:transparent #:mutable)

(define (read-block)
  (block
    (read-int 4)
    (read-bytes 32)
    (read-bytes 32)
    (read-int 4)
    (read-int 4)
    (read-int 4)
    (read-lenprearray read-transaction)))

(define (write-block the-block)
  (match-define (block v ph mr ts dt n txs) the-block)
  (write-int 4 v)
  (write-bytes ph)
  (write-bytes mr)
  (write-int 4 ts)
  (write-int 4 dt)
  (write-int 4 n)
  (write-lenprearray write-transaction txs))
