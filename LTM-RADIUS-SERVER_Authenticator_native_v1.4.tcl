proc ga_validate {hmac_mode key_size b32_key token allowed_clock_skew_units} {
  ##############################################################################################
  # Initialize the Base32 alphabet to binary conversation (see RFC 4648)
  #
  set b32_to_binary [list \
    A 00000 B 00001 C 00010 D 00011 E 00100 F 00101 G 00110 H 00111 I 01000 J 01001 K 01010 L 01011 M 01100 N 01101 O 01110 P 01111 \
    Q 10000 R 10001 S 10010 T 10011 U 10100 V 10101 W 10110 X 10111 Y 11000 Z 11001 2 11010 3 11011 4 11100 5 11101 6 11110 7 11111 \
    0 "" 1 "" = "" " " "" \
  ]
    if { [string length [set key [string map -nocase $b32_to_binary $b32_key]]] >= $key_size } then {
        # Convert the translated ga(key) binary string representation to binary
        set binary_key [binary format B$key_size $key]
        # Initialize clock timeframe based on Unix epoch time in seconds / 30
        set clock [expr { [clock seconds] / 30 } ]

        ##############################################################################################
        # Configure the allowed clock skew units (1 unit = +/-30 seconds in both directions)
        #
        set allowed_clock_range {0}
        for {set i 1} {$i <= $allowed_clock_skew_units} {incr i} {lappend allowed_clock_range -$i $i}

        ##############################################################################################
        # Perform verification of the provided token

        foreach x $allowed_clock_range {
          ##############################################################################################
          # Perform verification of the provided token for time frame clock + $x 
          #

          # Calculate hex encoded HMAC checksum value for wide-int value of time frame clock+ x using key_binary as secret
          binary scan [CRYPTO::sign -alg $hmac_mode -key $binary_key [binary format W* [expr { $clock + $x }]]] H* hmac_tmp
          # Parse offset based on the last nibble (= 4 bits / 1 hex) of the hmac_tmp HMAC checksum and multiply with 2 for byte to hex conversation
          set offset [expr { "0x[string index $hmac_tmp end]" * 2 } ]
          # Parse (= 4 bytes / 8 hex) from hmac_tmp starting at the offset value, then remove the most significant bit, perform the modulo 1000000 and format the result to a 6 digit number
          set token_calculated [format %06d [expr { ( "0x[string range $hmac_tmp $offset [expr { $offset + 7 } ]]" & 0x7FFFFFFF ) % 1000000 } ]]
          # Compare token_calculated with user provided token value
          if { $token_calculated equals $token } then {
            # The provided token is valid"
            return 1
            break
          }
        }
    } else {
        return -1
    }
    return 0
}
when RULE_INIT {
   set static::client_list "radius_clients"
   set static::allowed_clock_skew_units 1
}

when CLIENT_ACCEPTED {
  binary scan [md5 [UDP::payload]] H* PAYLOAD_HASH
  switch [set DUPLICATE_RESPONSE [table lookup -subtable [IP::client_addr] $PAYLOAD_HASH]] {
    "" {
      # Do nothing, not in table
    }
    drop {
      log local0. "Duplicate packet detected with drop decision... dropping again"
      UDP::drop; return
    }
    default {
      log local0. "Duplicate packet detected sending same answer from table"
      UDP::respond [binary format H* $DUPLICATE_RESPONSE]
      return
    }
  }

   set RespLength 20
   set RespAVP ""
   ############## START OF ALLOWED RADIUS CLIENT IP VALIDATION #################
   if {![class match [IP::client_addr] equals $static::client_list]} {
      log local0. "RADIUS Client not in Datagroup : [IP::client_addr]"
      # RFC 2865 : A request from a client for which the RADIUS server does not have a shared secret MUST be silently discarded
      log local0. "Drop reason 1"
      table add -subtable [IP::client_addr] $PAYLOAD_HASH "drop" 15 60
      UDP::drop
      return
   }
   # Set default values if Datagroup miss this configuration
   set RADCLIENT(REQMSGAUTH_REQUIRE) 0
   set RADCLIENT(RESPMSGAUTH_INSERT) 0
   set RADCLIENT(RFC_2865_COMPLIANCE) 1
    #Retreive RADIUS client shared secret and radius client capabilities.
   array set RADCLIENT [class match -value [IP::client_addr] equals $static::client_list]
   
   ############## END OF ALLOWED RADIUS CLIENT IP VALIDATION #################
   set IDENTIFIER [RADIUS::id]
   ############## START OF RFC COMPLIANCE AND SERVER FEATURES VALIDATION #################
   switch [RADIUS::code] {
      1 {
         set REQUEST_NOT_ALLOWED 0
         # RFC 2865 : Upon receipt of an Access-Request from a valid client, an appropriate reply MUST be transmitted. 
         set MESSAGE_AUTHENTICATOR [RADIUS::avp 80]
         RADIUS::avp replace 80 [binary format H32 0]
         #EVALUATE REQUEST MESSAGE-AUTHENTICATOR
        if {$RADCLIENT(REQMSGAUTH_REQUIRE) && ($MESSAGE_AUTHENTICATOR equals "" || ![CRYPTO::verify -alg hmac-md5 -key $RADCLIENT(KEY) -signature $MESSAGE_AUTHENTICATOR [UDP::payload]])} {
          # RFC 2869 : A RADIUS Server receiving an Access-Request with a Message-Authenticator Attribute present MUST calculate the correct value
          # of the Message-Authenticator and silently discard the packet if it does not match the value sent.
          log local0. "[IP::client_addr] : wrong or missing Message-Authenticator attribute"
          UDP::drop
          return
        }
         set USER_NAME [RADIUS::avp 1]
         set USER_PASSWORD [RADIUS::avp 2]
         set CHAP_PASSWORD [RADIUS::avp 3]
         set NAS_IP_ADDRESS [RADIUS::avp 4 ip4]
         set NAS_PORT [RADIUS::avp 5 integer]
         set STATE [RADIUS::avp 24]
         set NAS_IDENTIFIER [RADIUS::avp 32]
         set NAS_PORT_TYPE [RADIUS::avp 61 integer]
         if {$static::RFC_2865_FULL_COMPLIANCE} {
            if {$NAS_IP_ADDRESS equals "" && $NAS_IDENTIFIER equals ""} {
               # RFC 2865 : It MUST contain either a NAS-IP-Address attribute or a NAS-Identifier attribute (or both).
               set REQUEST_NOT_ALLOWED 1
               set RAVP(18) "REQUEST NOT RFC COMPLIANT"
            } elseif {$USER_PASSWORD equals "" && $CHAP_PASSWORD equals "" && $STATE equals ""} {
               # RFC 2865 : An Access-Request MUST contain either a User-Password or a CHAP-Password or a State.
               set REQUEST_NOT_ALLOWED 1
               set RAVP(18) "REQUEST NOT RFC COMPLIANT"
            } elseif {$USER_PASSWORD ne "" && $CHAP_PASSWORD ne ""} {
               # RFC 2865 : An Access-Request MUST NOT contain both a User-Password and a CHAP-Password.
               set REQUEST_NOT_ALLOWED 1
               set RAVP(18) "REQUEST NOT RFC COMPLIANT"
            }
         }
         if {$USER_PASSWORD equals ""} {
            set REQUEST_NOT_ALLOWED 1
            set RAVP(18) "USER-PASSWORD NOT SET BUT REQUIRED"
         } elseif {$USER_NAME equals ""} {
            set REQUEST_NOT_ALLOWED 1
            set RAVP(18) "USER-NAME NOT SET BUT REQUIRED"
         } elseif {[set userkey [class lookup $USER_NAME "google_auth_keys"]] equals ""} {
            set REQUEST_NOT_ALLOWED 1
            set RAVP(18) "USER-NAME NOT SET BUT REQUIRED"
         }
      }
      2 - 3 - 11 {
         set REQUEST_NOT_ALLOWED 1
         set RAVP(18) "RADIUS CODE NOT SUPPORTED - NOT A RADIUS CLIENT"
      }
      4 - 5 - 6 - 10 {
         set REQUEST_NOT_ALLOWED 1
         set RAVP(18) "RADIUS CODE NOT SUPPORTED - NOT A RADIUS ACCOUNTING SERVER"
      }
      default {
         set REQUEST_NOT_ALLOWED 1
         set RAVP(18) "RADIUS CODE NOT SUPPORTED"
      }
   }
   ############## END OF RFC COMPLIANCE AND SERVER FEATURES VALIDATION #################
 
  #Extract RADIUS Authenticator form PAYLOAD
   if {![binary scan [UDP::payload] @4a16 Q_AUTHENTICATOR]} {
      log local0. "Drop reason 2 Payload length : [UDP::payload length] / QLEN : $QLEN"
      table add -subtable [IP::client_addr] $PAYLOAD_HASH "drop" 15 60
      UDP::drop
      return
   }
   # DO NOT RELEASE UDP PACKET. Drop it to prevent further process by irule or load balancing to an internal server.
   # When UDP packet dropped, PAYLOAD is dropped and RADIUS Commands not available anymore.
   UDP::drop
   if {$REQUEST_NOT_ALLOWED == 0} {
      ########## START OF PASSWORD DECRYPTION ############################
      binary scan [md5 $RADCLIENT(KEY)$Q_AUTHENTICATOR] WW bx_64bits_1 bx_64bits_2
      binary scan $USER_PASSWORD W* USER_PASSWORD_W_LIST
      set PASSWORD_LIST [list]
      foreach {px_64bits_1 px_64bits_2} $USER_PASSWORD_W_LIST {
        lappend PASSWORD_LIST [expr { $px_64bits_1 ^ $bx_64bits_1 }] [expr { $px_64bits_2 ^ $bx_64bits_2 }]
        binary scan [md5 $RADCLIENT(KEY)[binary format WW $px_64bits_1 $px_64bits_2]] WW bx_64bits_1 bx_64bits_2
      }
      binary scan [binary format W* $PASSWORD_LIST] A* PASSWORD
      log local0. "Password is $PASSWORD"
      ########## END OF PASSWORD DECRYPTION ############################

      ########## START OF GOOGLE AUTHENTICATION ############################
      switch -- [call ga_validate "hmac-sha1" 80 $userkey $PASSWORD $static::allowed_clock_skew_units] {
          -1 {
                  # code verification failed
                  set ResponseCode 3
                  if {![info exists RAVP(18)] } {set RAVP(18) "wrong username Password"}
                  log local0. "erreur 2 : wrong User Key"
          }
          0 {
                  # code verification failed
                  set ResponseCode 3
                  if {![info exists RAVP(18)] } {set RAVP(18) "wrong username Password"}
          }
          1 {
                  # code verification successful
                  set ResponseCode 2
                  if {![info exists RAVP(18)] } {set RAVP(18) "Good username Password"}
          }
          default {set result "error: unknown"}
      }
      ########## END OF GOOGLE AUTHENTICATION ############################
   } else {
      set ResponseCode 3
      if {[info exists RAVP(18)] } { log local0. $RAVP(18)}
   }
   ########## ENCODING AND DELIVERY OF RADIUS RESONSE ############################
   foreach attrID [array names RAVP] {
      incr RespLength [set attrLength [expr {[string length $RAVP($attrID)]+2}]]
      append RespAVP [binary format cca* $attrID $attrLength $RAVP($attrID)]
   }
   #CALCULATE RESPONSE MESSAGE-AUTHENTICATOR
   if {$RADCLIENT(RESPMSGAUTH_INSERT)} {
    set UNSIGNED_RespAVP $RespAVP[binary format ccH32 80 18 [string repeat 0 32]]
    incr RespLength 18
    append RespAVP [binary format cc 80 18][CRYPTO::sign -alg hmac-md5 -key $RADCLIENT(KEY) [binary format cH2Sa16a* $ResponseCode $IDENTIFIER $RespLength $Q_AUTHENTICATOR $UNSIGNED_RespAVP]]
    }

   binary scan [md5 [binary format cH2Sa16a[expr {$RespLength-20}]a[string length $RADCLIENT(KEY)] $ResponseCode $IDENTIFIER $RespLength $Q_AUTHENTICATOR $RespAVP $RADCLIENT(KEY) ]] H* ResponseAuth
   set RESPONSE [binary format cH2SH32a* $ResponseCode $IDENTIFIER $RespLength $ResponseAuth $RespAVP]
   UDP::respond $RESPONSE
   binary scan $RESPONSE H* RESPONSE_HEX
   table add -subtable [IP::client_addr] $PAYLOAD_HASH $RESPONSE_HEX 15 60
}
