#lang racket

(require binaryio)

(provide (all-defined-out))

(define/contract (read-int len)
  (-> (or/c 1 2 4 8 16 32) nonnegative-integer?)
  (bytes->integer (read-bytes len) #f #f))

(define/contract (read-int/b len)
  (-> (or/c 1 2 4 8 16 32) nonnegative-integer?)
  (bytes->integer (read-bytes len) #f #t))

(define/contract (write-int len x)
  (-> (or/c 1 2 4 8 16 32) nonnegative-integer? void)
  (write-bytes
   (integer->bytes x len #f #f)))

(define/contract (write-int/b len x)
  (-> (or/c 1 2 4 8 16 32) nonnegative-integer? void)
  (write-bytes
   (integer->bytes x len #f #t)))

(define/contract (read-varint)
  (-> nonnegative-integer?)
  (match (read-byte)
    [#xFD (read-int 2)]
    [#xFE (read-int 4)]
    [#xFF (read-int 8)]
    [x x]))

(define/contract (write-varint x)
  (-> nonnegative-integer? void)
  (cond
    [(< x #xFD) (write-byte x)]
    [(<= x #xFFFF) (write-byte #xFD) (write-int 2 x)]
    [(<= x #xFFFFFFFF) (write-byte #xFE) (write-int 4 x)]
    [(<= x #xFFFFFFFFFFFFFFFF) (write-byte #xFF) (write-int 8 x)]
    [else (error 'out_of_range)]))

(define (read-lenprebytes)
  (define length (read-varint))
  (read-bytes length))

(define/contract (write-lenprebytes bytes)
  (-> bytes? void?)
  (write-varint (bytes-length bytes))
  (write-bytes bytes)
  (void))

(define/contract (read-lenprearray reader)
  (-> (-> any/c) list?)
  (define length (read-varint))
  (for/list ([i length])
    (reader)))

(define (write-lenprearray writer array)
  (-> (-> any/c any/c) list?)
  (write-varint (length array))
  (for/list ([elem array])
    (writer elem)))

(define-syntax-rule (capture-output body ...)
  (with-output-to-bytes (thunk body ...)))

(define-syntax-rule (use-input bytes body ...)
  (with-input-from-bytes bytes (thunk body ...)))
