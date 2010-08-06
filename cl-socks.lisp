(defpackage :cl-socks
    (:nicknames :socks)
  (:use :cl)
  (:export #:socks-connect))

(in-package :cl-socks)


(defconstant +socks5-no-authorization+ 0
  "Authentication method that requires no credentials.")

(defconstant +socks5-version-byte+ 5
  "Authentication method that requires no credentials.")

(defconstant +socks5-address-type-ipv4+ 1
  "IPV4")

(defconstant +socks5-address-type-domainname+ 3
  "Domain name address type byte")

(defconstant +socks5-address-type-ipv6+ 4
  "IPV6")


(defconstant +socks5-version-byte+ 5
  "Authentication method that requires no credentials.")

(defconstant +socks5-version-byte+ 5
  "Authentication method that requires no credentials.")

(defclass socks-client ()
  ((underlying-stream :initarg :underlying-stream :reader client-underlying-stream
                      :documentation "The STREAM object this object wraps")
   ))

(defun wrap-stream (wrapper-class underlying-stream &rest initargs)
  (apply 'make-instance wrapper-class :underlying-stream underlying-stream initargs))

(defun socks-connect (stream destination-address destination-port)
  "Establishes a SOCKS5 connection to DESTINATION-ADDRESS on
 DESTINATION-PORT through (socket) binary stream STREAM.  After
 this (blocking) function completes, the stream should behave mostly
 as if a direct connection had been made to the desination.

DESTINATION-ADDRESS is either a Fully Qualified Domain Name (including
the dot at the end and less than 255 characters) string, a vector of 4
bytes (ipv4 address), or a vector of 6 bytes (ipv6 address).

Returns (BOUND-ADDRESS-TYPE BOUND-ADDRESS BOUND-PORT) of the
connection on the proxy server.

See http://www.faqs.org/rfcs/rfc1928.html"
  (socks-client-connect (wrap-stream 'socks-client stream) 
                        destination-address destination-port))

(defun destructure-user-address (address)
  "Takes as input a string or byte array and determines the type of
desination address specified.  Returns 2 values: its type (one
of :ipv4 :ipv6 or :domainname) and the processed address that is valid
to pass into  SOCKS-REQUEST."
  (typecase address
    (string (values :domainname address))
    (sequence (case (length address)
                (4 (values :ipv4 address))
                (6 (values :ipv6 address))
                (t (error "Invalid Address ~A" address))))
    (t (error "Invalid Address ~A" address))))

(defun socks-client-connect (client destination-address destination-port)
  (socks-authenticate client)
  (multiple-value-bind (bound-address-type bound-address port)
      (socks-request client :connect :domainname destination-address destination-port)
    #+nil
    (format t "Successfully connected to socks server bound to ~A ~A ~A!~%"
            bound-address-type bound-address port)
    (values bound-address-type bound-address port)))


(defmacro with-syntax-sugar ((socks-stream-var) &body body)
  `(labels ((expect-byte (expected &optional (error-format "Read unexpected SOCKS stream byte value ~A"))
              (let ((value (read-byte ,socks-stream-var)))
                (unless (eql expected value)
                  (error error-format value))
                expected))

            (read-n-bytes (n)
              (let ((array (make-array n :element-type '(unsigned-byte 8))))
                (unless (eql n (read-sequence array ,socks-stream-var))
                  (error "Failed to read ~A bytes from SOCKS stream" n))
                array))

            (expect-version-byte ()
              (expect-byte +socks5-version-byte+ "Invalid SOCKS connection/version ~A")))
     ,@body))

(defun socks-authenticate (client)
  "Performs handshake using the underlying stream."
  (let ((socks-stream (client-underlying-stream client)))
    (with-syntax-sugar (socks-stream)
      ;; http://www.faqs.org/rfcs/rfc1928.html

      ;; Send acceptable authentication methods.  only support no
      ;; authorization for now
      (write-sequence (vector +socks5-version-byte+ 1 +socks5-no-authorization+) socks-stream)
      (finish-output socks-stream)

      (expect-version-byte)
      (expect-byte +socks5-no-authorization+)

      client)))

(defun socks-request (client command address-type address port)
  (declare (type (member :connect) command)
           (type (member :ipv4 :ipv6 :domainname) address-type)
           (type integer port)
           (type  socks-client client))
  (let ((socks-stream (client-underlying-stream client)))
    (with-syntax-sugar (socks-stream)
      ;; write version, cmd, rsv
      (write-sequence (vector +socks5-version-byte+
                              (case command
                                (:connect 1)
                                (:bind 2)
                                (:udp-associate 3))
                              0)
                      socks-stream)
      
      ;; write the address type
      (case address-type
        (:ipv4 (write-sequence (concatenate 'vector
                                            (list +socks5-address-type-ipv4+)
                                            address)
                               socks-stream))
        (:ipv6 (write-sequence (concatenate 'vector
                                            (list +socks5-address-type-ipv6+)
                                            address)
                               socks-stream))
        (:domainname (let ((octets (flexi-streams:string-to-octets address)))
                       (unless (<= (length octets) 255)
                         (error "Fully qualified domain name too long"))
                       (when (not (eql #\. (elt address (- (length octets) 1))))
                         (error "Fully qualified domain name must end in '.'"))
                       (write-sequence (concatenate 'vector
                                                    (list +socks5-address-type-domainname+
                                                          (length octets))
                                                    octets)
                                       socks-stream))))

      ;; write the port number
      (unless (> (expt 2 16) port -1)
        (error "Invalid port number ~A" port))

      (write-sequence (vector (ldb (byte 8 8) port)
                              (ldb (byte 8 0) port))
                      socks-stream)

      (finish-output socks-stream)
      
      ;;; Receive the response
      (expect-version-byte)
      (expect-byte 0  "SOCKS5 error during connect. Code: ~A")
      (read-byte socks-stream)

      (multiple-value-bind (server-bound-address-type server-bound-address)
          (let ((type-byte (read-byte socks-stream)))
            (cond
              ((eql type-byte +socks5-address-type-ipv4+)
               (values :ipv4
                       (read-n-bytes 4)))
              ((eql type-byte +socks5-address-type-ipv6+)
               (values :ipv6
                       (read-n-bytes 6)))
              
              ((eql type-byte +socks5-address-type-domainname+)
               (values :domainname
                       (let ((addr-len (read-byte socks-stream)))
                         (flexi-streams:octets-to-string (read-n-bytes addr-len)))))

              (t (error "Invalid address type byte received ~A" type-byte))))
        
        (let* ((port-bytes (read-n-bytes 2))
               (port (+ (ash (elt port-bytes 0) 8)
                        (elt port-bytes 1))))
          #+nil
          (format t "Connected ~A ~A ~A~%" server-bound-address-type server-bound-address port)
          (values server-bound-address-type server-bound-address port))))))
