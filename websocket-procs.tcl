package require nsf
ns_logctl severity Debug(ws) false

namespace eval ::ws {

    nsf::proc ::ws::log {msg} {
        ns_log Debug(ws) $msg
    }

    nsf::proc ::ws::handshake {
        {-readevent:boolean true} 
        {-callback ""}
    } {
        #::ws::log handshake

        set h [ns_conn headers]
        if {[ns_set iget $h upgrade] eq "websocket"} {
            set key               [ns_set iget $h Sec-WebSocket-Key]
            set client_protocols  [ns_set iget $h Sec-WebSocket-Protocol]
            ::ws::log "key: $key Client Protocols: '$client_protocols'"
            
            if {[llength $client_protocols] > 0} {
                set protocol_line "\r\nSec-WebSocket-Protocol: [lindex $client_protocols 0]"
            } else {
                set protocol_line ""
            }

            set guid "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
            set reply [ns_base64encode [binary format H* [ns_sha1 $key$guid]]]

            ns_write \
                "HTTP/1.1 101 Switching Protocols\r\n" \
                "Upgrade: websocket\r\n" \
                "Connection: Upgrade\r\n" \
                "Sec-WebSocket-Accept: ${reply}${protocol_line}\r\n\r\n"
            
            #
            # Unplug the connection channel from the current connection
            # thread. The currently unplugged channels can be queried via
            # "ns_connchan list"
            #
            set handle [ns_connchan detach]

            # event based reading
            if {$readevent} {
                # register a callback to be executed when the channel is readable
                ns_connchan callback $handle [list ws::readable $handle $callback] r
            }

            return $handle

        } else {
            ns_write "HTTP/1.0 200 OK\r\nContent-type: text/plain\r\n\r\n"
            return ""
        }
    }

    #
    # Callback to be called, when a connchan is becoming readable. The
    # callback might be called as well when a timeout is received
    # (when 't'), an exception occurred (when 'e') or the server exits
    # (when 'x').
    #
    
    nsf::proc ::ws::readable {
        channel 
        callback 
        when
    } {
        ::ws::log "ws::readable channel $channel callback $callback when $when"

        # When the result is 1, so the event will fire again; when the
        # result is 0 -> close. Per default, set result to 1 and in
        # terminating cases below to 0.
        set result 1
        
        if {$when ne "r"} {
            ::ws::log "ws::readable channel $channel reveived when <$when>"
            return 0
        }

        set msg [ns_connchan read $channel]
        ::ws::log "ns_connchan read $channel got [string length $msg] bytes"

        if {$msg ne ""} {
            ::ws::log "ns_connchan read $channel got [string length $msg] bytes"
            
            lassign [ws::decode_msg $channel $msg] payload rest opcode
            ::ws::log "ws::readable $channel decode -> <$payload> <$rest> <$opcode>"
            #
            # opcodes: 0 continuation, 1 text, 2 binary, 3-7 reserved,
            # 8 close, 9 ping, 10 pong, 11-15 reserved
            #
            switch $opcode {
                0 -
                1 -
                2 { if {$callback ne ""} { {*}$callback $channel $payload } }
                8 { set result 0 }
                9 { ws::send $channel [ws::build_msg -opcode pong "PONG"] }
                default { }
            }
        } else {
            ::ws::log "ws::readable on $channel got 0 bytes"
            set result 0
        }

        return $result
    }

    #
    # Set a few constants used for encoding messages
    #
    set ::ws::FIN 1
    set ::ws::RSV1 0
    set ::ws::RSV2 0
    set ::ws::RSV3 0
    set ::ws::OPCODE(continuation) 0000
    set ::ws::OPCODE(text)         0001
    set ::ws::OPCODE(binary)       0010
    set ::ws::OPCODE(close)        1000
    set ::ws::OPCODE(ping)         1001
    set ::ws::OPCODE(pong)         1010
    
    #
    # build a websocket message
    #
    nsf::proc ::ws::build_msg {
        {-opcode "text"} 
        payload
    } {
        #::ws::log ws::build_msg

        set OPCODE $::ws::OPCODE($opcode)
        set payload [encoding convertto utf-8 $payload]
        set msg [binary format B8 $::ws::FIN$::ws::RSV1$::ws::RSV2$::ws::RSV3$OPCODE]

        #::ws::log"length [string length $payload] binary $::ws::FIN$::ws::RSV1$::ws::RSV2$::ws::RSV3$OPCODE"
        set payload_length [string length $payload]

        if {$payload_length <= 125} {
            append msg [format %c $payload_length]
        } elseif {$payload_length <= 0xFFFF} {
            # 126 -> the next 2 bytes give the payload length
            append msg [format %c 126]
            append msg [format %c [expr {$payload_length >> 8}]]
            append msg [format %c [expr {($payload_length & 0x00FF) >> 0}]]
        } else {
            # 127 -> the next 8 bytes give the payload length
            append msg [format %c 127]
            append msg [format %c [expr {($payload_length & 0xFFFFFFFFFFFFFFFF) >> 56}]]
            append msg [format %c [expr {($payload_length & 0x00FFFFFFFFFFFFFF) >> 48}]]
            append msg [format %c [expr {($payload_length & 0x0000FFFFFFFFFFFF) >> 40}]]
            append msg [format %c [expr {($payload_length & 0x000000FFFFFFFFFF) >> 32}]]
            append msg [format %c [expr {($payload_length & 0x00000000FFFFFFFF) >> 24}]]
            append msg [format %c [expr {($payload_length & 0x0000000000FFFFFF) >> 16}]]
            append msg [format %c [expr {($payload_length & 0x000000000000FFFF) >>  8}]]
            append msg [format %c [expr {($payload_length & 0x00000000000000FF) >>  0}]]
        }
        append msg $payload

        return $msg
    }

    #
    # Decode message(s) from a client
    #
    
    nsf::proc ::ws::decode_msg {
        channel
        msg
    } {
        
        ::ws::log ws::decode

        set b [scan [string index $msg 0] %c]
        if {$b ne ""} {
            # ------- FIRST BYTE --------------
            # first byte is FIN + RSV[1-3] + Opcode
            set FIN            [expr {($b & 0b11111111) >> 7}]
            set RSV1           [expr {($b & 0b01111111) >> 6}]
            set RSV2           [expr {($b & 0b00111111) >> 5}]
            set RSV3           [expr {($b & 0b00011111) >> 4}]
            # 0 = CONTINUATION, 1 = Text, 2 = Binary, 8 = close, 9 = Ping, 10 = Pong
            set OPCODE         [expr {($b & 0b00001111)}]

            # ------- SECOND BYTE --------------
            set b [scan [string index $msg 1] %c]

            set MASK           [expr {($b & 0b11111111) >> 7}]
            set PAYLOAD_LENGTH [expr {($b & 0b01111111)}]        

            #::ws::log "FIN: $FIN, RSVs: $RSV1 $RSV2 $RSV3, Opcode: $OPCODE, Mask: $MASK, Payload_Length: $PAYLOAD_LENGTH"

            if {$PAYLOAD_LENGTH <= 125} {
                # just cut away first 2 bytes
                set msg [string range $msg 2 end]
            } elseif {$PAYLOAD_LENGTH == 126} {
                # the payload length is in the next two bytes
                set b [scan [string index $msg 2] %c]
                set PAYLOAD_LENGTH [expr {$b << 8}]
                set b [scan [string index $msg 3] %c]
                set PAYLOAD_LENGTH [expr {$PAYLOAD_LENGTH + $b}]
                # cut away first 2 + 2 bytes
                set msg [string range $msg 4 end]
            } elseif {$PAYLOAD_LENGTH == 127} {
                # the payload length is in the next eight bytes
                set PAYLOAD_LENGTH 0
                for {set i 0} {$i<8} {incr i} {
                    set b [scan [string index $msg [expr {2+$i}]] %c]
                    set PAYLOAD_LENGTH [expr {($PAYLOAD_LENGTH << 8) + $b}]
                }
                set msg [string range $msg 10 end]
            }
            #::ws::log "Payload Length $channel: $PAYLOAD_LENGTH length msg [string length $msg]"

            if {$MASK} {
                set frame_mask   [string range $msg 0 3]
                set payload      [string range $msg 4 $PAYLOAD_LENGTH+3] 
                set rest_payload [string range $msg $PAYLOAD_LENGTH+4 end]
                set unmasked_payload ""
                
                # scan the 4 bytes of the mask
                binary scan $frame_mask cccc m(0) m(1) m(2) m(3)
                
                #::ws::log "mask: $m(0) $m(1) $m(2) $m(3) "
                for {set i 0} {$i < [string length $payload]} {incr i} {
                    set p [expr {$i % 4}]
                    append unmasked_payload [format %c [expr {[scan [string index $payload $i] %c] ^ ($m($p) & 255) }]]
                }
                set payload [encoding convertfrom identity $unmasked_payload]
            } else {
                set payload      [string range $msg 0 $PAYLOAD_LENGTH-1] 
                set rest_payload [string range $msg $PAYLOAD_LENGTH end] 
            }
        } else {
            ::ws::log "Message: $msg - could not decode"
        }
        #::ws::log "FINAL WS PAYLOAD: $payload"

        if {$FIN == 0 && ($OPCODE == 0 || $OPCODE == 1 || $OPCODE == 2) } {
            #
            # This is not the last frame of the message, so we store
            # it as a fragment in a nsv.
            #
            # ::ws::log "FRAGMENTED WS MESSAGE: $payload"
            nsv_append ws "fragments-$channel" $payload
            set payload ""
        } elseif {$FIN == 1 && $OPCODE == 0} {
            #
            # This is the end of the message and we have a
            # continuation frame append this payload to the message
            # and return it.
            #
            set payload [nsv_get ws "fragments-$channel"]$payload
            nsv_unset "fragments-$channel"
        }

        return [list $payload $rest_payload $OPCODE]
    }

    #
    # Subscribe to a named websocket channel feed
    #
    nsf::proc ::ws::subscribe {
        channel 
        subscription
    } {

        ns_log notice "ws::subscribe $channel $subscription"

        ns_mutex eval [nsv_get ws subscription_mutex] {
            set subscribers [nsv_lappend ws multicast-$subscription $channel]
        }

        ::ws::log "subscribers of $subscription: $subscribers"
        return $subscribers
    }

    #
    # Cancel a subscription to a named websocket feed
    #
    nsf::proc ::ws::unsubscribe {
        channel 
        subscription
    } {
        ns_log notice "unsubscribing $channel"

        if {[nsv_exists ws "multicast-$subscription"]} {
            ns_mutex eval [nsv_get ws subscription_mutex] {
                set subscribers [nsv_get ws "multicast-$subscription"]
                set idx [lsearch -exact $subscribers $channel]
                nsv_set ws "multicast-$subscription" [lreplace $subscribers $idx $idx]
            }
        }
    }

    #
    # Send a websocket message to "all" or to subscribers of a named
    # feed. It is expected that msg is already encoded (via ws::build_msg).
    #
    nsf::proc ::ws::multicast {
        {-exclude ""} 
        subscription 
        msg
    } {
        if {$subscription ne "all"} {
            #::ws::log "ws::multicast send to subscriber of $subscription"
            if {[nsv_exists ws "multicast-$subscription"]} {
                foreach channel [nsv_get ws "multicast-$subscription"] {
                    #::ws::log "Sending to $channel"
                    if {$channel ni $exclude} {
                        if {![ws::send $channel $msg]} {
                            # we got an error, the channel is probably closed
                            ws::unsubscribe $channel $subscription
                        }
                    }
                }
            }
        } else {
            # send to all shared channels
            #::ws::log "send to all <[ns_connchan list]> except <$exclude>"
            foreach channel_info [ns_connchan list] {
                lassign $channel_info channel
                if {$channel ni $exclude} {
                    ::ws::log "Sending to $channel"
                    ws::send $channel $msg
                }
            }
        }
    }

    #
    # Send a websocket message (built by ws::build_msg) to a single client
    #
    nsf::proc ::ws::send {
        channel 
        msg
    } {
        #::ws::log "ws::send $channel"

        if [catch {
            ns_connchan write $channel $msg
        } errmsg] {
            return 0
        } else {
            return 1
        }
    }

    #
    # initialize package
    #
    if {![nsv_exists ws mutex]} {
        nsv_set ws subscription_mutex  [ns_mutex create]
    }
}

#
# Local variables:
#    mode: tcl
#    tcl-indent-level: 4
#    indent-tabs-mode: nil
# End:
