#
# WebSocket implementation based on NaviServer's ns_connchan with
# internal buffering.
#
package require nsf
ns_logctl severity Debug(ws) false

#
# For more intense debugging, you might activate (some) the following
# debug levels.
#

#ns_logctl severity Debug(ws) true
#ns_logctl severity Debug(connchan) true

#
# Activate/Deactivate a simple WebSocket echo service (e.g. for testing)
#
namespace eval ::ws {}
set ::ws::echo_service 1

#
# Make sure that we have a sufficiently recent version of
# NaviServer. Otherwise bail out with an exception.
#
catch {ns_connchan read "" ""} errorMsg
if {![string match "*-websocket*" $errorMsg]} {
    error "Please upgrade to a newer version of NaviServer"
}

namespace eval ::ws {

    nsf::proc ::ws::log {args} {
        #
        # Support single and multi argument log messages (like
        # "ns_log").
        #
        ns_log Debug(ws) {*}$args
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
            set reply [ns_crypto::md string -digest sha1 -encoding base64 $key$guid]

            #
            # Make sure, to send the upgrade command in a single sweep
            # (single send buffer), no matter how the server is
            # configured.  Otherwise, we could run into an issue with
            # the current revproxy.
            #
            # In Tcl 8.6, we should use [string cat ...] instead of
            # the "append" stunt.
            set _ {}
            ns_write [append _ \
                          "HTTP/1.1 101 Switching Protocols\r\n" \
                          "Upgrade: websocket\r\n" \
                          "Connection: Upgrade\r\n" \
                          "Sec-WebSocket-Accept: ${reply}${protocol_line}\r\n\r\n"]
            #
            # Unplug the connection channel from the current connection
            # thread. The currently unplugged channels can be queried via
            # "ns_connchan list"
            #
            set handle [ns_connchan detach]

            # event based reading
            if {$readevent} {
                # register a callback to be executed when the channel is readable
                ns_connchan callback $handle [list ws::io $handle $callback] rex
            }

            return $handle

        } else {
            ns_write "HTTP/1.0 200 OK\r\nContent-type: text/plain\r\n\r\n"
            return ""
        }
    }

    nsf::proc ::ws::receive_msg {channel} {
        while {1} {

            try {
                ns_connchan read -websocket $channel
            } trap {POSIX ECONNRESET} {} {
                #
                # The other side has closed the connection. Don't
                # complain and perform standard cleanup.
                #
                ns_log warning "ws::receive_msg: peer has reset connection on $channel"
                dict set d continue 0
                break

            } on error {errorMsg} {
                ns_log error "ws::receive_msg error on $channel: $errorMsg ($::errorCode)"
                dict set d continue 0
                break

            } on ok {d} {
            }
            #ns_log notice "GOT <$d>"

            if {[dict exists $d payload]} {
                #
                # The dictionary contains "payload" only when also the
                # "fin" bit of the frame was set. Since we got some
                # data, receive_msg can report it back.
                #
                if {[dict get $d opcode] == 1} {
                    dict set d payload [encoding convertfrom utf-8 [dict get $d payload]]
                }
                dict set d continue 1
                break

            } elseif {[dict get $d bytes] < 0} {
                #
                # There must have been an error condition.
                #
                ::ws::log "ws::receive_msg on $channel got [dict get $d bytes] bytes"
                dict set d continue 0
                break

            } elseif {[dict get $d bytes] == 0 && ![dict get $d havedata]} {
                #
                # We got no fresh data, but maybe we have still some
                # more unprocessed either in the frame buffer or in
                # the segments buffer.
                #
                ::ws::log "ws::receive_msg on $channel: check unprocessed $d"
                set unprocessed [dict get $d unprocessed]
                incr unprocessed [dict get $d fragments]
                dict set d continue [expr {$unprocessed > 0}]
                ns_log warning "ws::receive_msg on $channel should stop?" \
                    " $d unprocessed $unprocessed -> [dict get $d continue]"

            } elseif {[dict exists $d fin]
                      && [dict get $d fin] == 0
                      && [dict get $d frame] eq "complete"
                  } {
                #
                # The frame is complete, but not final, we have to
                # continue.
                #
                dict set d continue 1

            } elseif {[dict get $d bytes] > 0
                      && [dict get $d frame] eq "incomplete"
                      && [dict get $d unprocessed] > 0
                      && ![dict get $d havedata]
                  } {
                #
                # We got some data, but the data is not sufficient
                # to process the frame.  So, we need more data to
                # fill up this frame.
                #
                ns_log warning "ws::receive_msg need more data <$d>"
                dict set d continue 1

            } else {
                #
                # There might be potentially more cases requiring
                # special handling, but for the time being, we
                # continue.
                #
                ns_log warning "ws::receive_msg essentially unhandled case <$d>"
                dict set d continue 1
            }

            if {![dict get $d havedata]} {
                break
            }
        }
        ::ws::log "ws::revceive_msg returns $d"
        return $d
    }

    #
    # ::ws::io is the callback for readable or writable conditions
    # (and for handling timeouts or errors). The handlers switching
    # between readable and writable conditions whenever an output
    # channel is saturated. In readmode (default) it reads data, when
    # the channel is readable, in write mode the handler is delivering
    # data on the channel whenever it is writable. This is necessary
    # to handle partial write operations in an event driven fashion.
    #

    nsf::proc ::ws::io {
        channel
        callback
        when
    } {
        ::ws::log "ws::io channel $channel callback $callback when $when"
        switch $when {
            r {
                return [::ws::io_readable $channel $callback $when]
            }
            w {
                return [::ws::io_writable $channel $callback $when]
            }
            default {
                ::ws::log "ws::io channel $channel received when <$when>"
                return 0
            }
        }
    }

    nsf::proc ::ws::io_readable {
        channel
        callback
        when
    } {
        #
        # When continue is 1, the event will fire again; when continue
        # is 0 channel will be closed.  A continue of 2 means cancel
        # the callback, but don't close the channel.  Per default, set
        # continue to 1 and in terminating cases to 0.
        #
        set continue 1

        #
        # One physical read operation from the channel might contain
        # multiple messages. In these cases, the dict member
        # "havedata" is set, and we can try to get further messages
        # from the receive buffer contained in the connection channel.
        #
        while {$continue} {
            set d [::ws::receive_msg $channel]
            set continue [dict get $d continue]
            if {$continue && [dict exists $d payload]} {
                switch [dict get $d opcode] {
                    1 -
                    2 { if {$callback ne ""} { {*}$callback $channel [dict get $d payload] }}
                    8 { set continue 0 }
                    9 { ws::send $channel [ns_connchan wsencode -opcode pong "PONG"] }
                    default { }
                }
            }
            if {![dict get $d havedata]} {
                break
            }
        }

        log "ws::io_readable returns $continue (channel $channel)"
        return $continue
    }

    nsf::proc ::ws::io_writable {
        channel
        callback
        condition
    } {
        # When continue is 1, the event will fire again; when continue
        # is 0 channel will be closed.  A continue of 2 means cancel
        # the callback, but don't close the channel.
        #
        log "ws::io_writable on $channel (condition $condition)"

        set result [ns_connchan write -buffered $channel ""]
        set status [ns_connchan status $channel]
        log "ws::io_writable result <$result> status $status"
        if {$result == 0 || [dict get $status sendbuffer] > 0} {
            ns_log warning "ws::io_writable was not successful flushing the buffer " \
                "(still [dict get $status sendbuffer])... trigger again. status: $status"
            set continue 1
        } else {
            #
            # All was sent, fall back to normal read-event driven handler
            #
            set continue 1
            #ns_log notice "ws::io_writable all was sent, register callback for reading "
            ns_connchan callback $channel [list ws::io $channel $callback] rex
            #ns_log notice "ws::io_writable all was sent, register callback for reading DONE"
        }

        log "ws::io_writable returns $continue (channel $channel)"
        return $continue
    }

    #
    # Subscribe to a named WebSocket channel feed.
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
    # Cancel a subscription to a named WebSocket feed
    #
    nsf::proc ::ws::unsubscribe {
        channel
        subscription
    } {
        ns_log notice "unsubscribing $channel"

        if {[nsv_get ws "multicast-$subscription" subscribers]} {
            ns_mutex eval [nsv_get ws subscription_mutex] {
                set idx [lsearch -exact $subscribers $channel]
                nsv_set ws "multicast-$subscription" [lreplace $subscribers $idx $idx]
            }
        }
    }

    #
    # Send a WebSocket message to "all" or to subscribers of a named
    # feed. It is expected that the msg is already already encoded as
    # a frame.
    #
    nsf::proc ::ws::multicast {
        {-exclude ""}
        subscription
        msg
    } {
        if {$subscription ne "all"} {
            #
            # Send message to all subscribers
            #
            #::ws::log "ws::multicast send to subscriber of $subscription"
            if {[nsv_get ws "multicast-$subscription" channels]} {
                foreach channel $channels {
                    #::ws::log "Sending to $channel"
                    if {$channel ni $exclude} {
                        if {![ws::send $channel $msg]} {
                            # we got an error, the channel is probably closed
                            ws::log "ws::multicast: automatically unsubscribe $channel from $subscription due to error"
                            ws::unsubscribe $channel $subscription
                        }
                    }
                }
            }
        } else {
            #
            # Send message to all shared channels. This is very
            # dangerous, since probably connchans might be used also
            # for other applications.
            #
            #::ws::log "send to all <[ns_connchan list]> except <$exclude>"
            foreach channel_info [ns_connchan list] {
                lassign $channel_info channel
                if {$channel ni $exclude} {
                    ws::log "Sending to $channel"
                    ws::send $channel $msg
                }
            }
        }
    }

    #
    # Send a WebSocket frame (built by ns_connchan wsencode) to a
    # single client.
    #
    # A result of 1 means success, 0 means something went wrong,
    # connection should be terminated.
    #
    nsf::proc ::ws::send {
        channel
        msg
    } {
        #::ws::log "ws::send $channel"

        try {
            ns_connchan write -buffered $channel $msg

        } on ok {nrBytesSent} {
            #ns_log notice "ws::send $channel -> $nrBytesSent"
            set toSend [string length $msg]
            if {$nrBytesSent < $toSend} {
                set status [ns_connchan status $channel]
                ns_log warning "ws::send: partial write on $channel: " \
                    "actually sent $nrBytesSent toSend $toSend\n$status"
                #
                # We must register a callback for the socket becoming writable again.
                #
                set previousCallback [dict get $status callback]
                set previousCondition [dict get $status condition]
                if {$previousCondition ne "wex"} {
                    set callback [lindex $previousCallback 2]
                    ns_connchan callback $channel [list ws::io $channel $callback] wex
                    ::ws::log "Switch registered callback <$callback> wex"
                }
            }
            return 1
        } on error {errorMsg} {
            ns_log warning "ws::send $channel returned error: $errorMsg"
            return 0
        }
    }

    #
    # Initialize package.
    #
    if {![nsv_exists ws mutex]} {
        nsv_set ws subscription_mutex [ns_mutex create websocket-subscription]
    }
}

namespace eval ::ws::client {
    #
    # Simple WebSocket client implementation
    #
    nsf::proc ::ws::client::open {url} {
        set d [ns_parseurl $url]
        set host [dict get $d host]
        set proto [expr {[dict get $d proto] eq "ws"
                         ? "http"
                         : [dict get $d proto] eq "wss"
                         ? "https"
                         : "unknown"}]
        if {$proto eq "unknown"} {
            error "protocol must be ws:// or wss://"
        }
        set location ${proto}://$host
        if {[dict exists $d port]} {
            append location :[dict get $d port]
            append host :[dict get $d port]
        }
        set request_url $location
        if {[dict get $d path] ne ""} {
            append request_url /[dict get $d path]
        }
        if {[dict get $d tail] ne ""} {
            append request_url /[dict get $d tail]
        }

        set nonce [ns_crypto::randombytes -encoding base64 16]
        set headers [ns_set create headers \
                         Host $host \
                         Upgrade websocket \
                         Connection Upgrade \
                         Cache-Control no-cache \
                         Origin $location \
                         Sec-WebSocket-Key $nonce \
                         Sec-WebSocket-Version 13]
        ::ws::log [list ns_connchan open -headers $headers -version 1.1 -hostname $host $request_url]
        set chan [ns_connchan open -headers $headers -version 1.1 -hostname $host $request_url]
        set replyMsg [ns_connchan read $chan]

        set firstline 1
        set reply [ns_set create reply]

        foreach line [split $replyMsg \n] {
            set line [string trimright $line]
            if {$line eq ""} continue
            if {$firstline} {
                set firstline 0
                ns_set put $reply :status [lindex $line 1]
                continue
            }
            #ns_log notice "<$line>"
            ns_parseheader $reply $line
        }
        if {[ns_set get $reply :status] ne 101} {
            ns_log Warning "reply: [ns_set array $reply]"
            error "ws::client::open returned unexpected status code [ns_set get $reply :status]"
        }
        return $chan
    }

    nsf::proc ::ws::client::send {chan msg} {
        ns_connchan write $chan [ns_connchan wsencode -mask $msg]
    }

    nsf::proc ::ws::client::receive {chan} {
        #
        # Read a single message and return it
        #
        while {1} {
            #
            # In case the received message does not have opcode 1,
            # read on until either sich a message or an error occurs.
            #
            set d [::ws::receive_msg $chan]
            if {[dict exists $d payload]} {
                switch [dict get $d opcode] {
                    1 {
                        #
                        # Here we are done, we received the full
                        # message with the right opcode.
                        #
                        return [dict get $d payload]
                    }
                    default { ns_log notice "no special handling of opcode $opcode"}
                }
            } elseif {[dict get $d frame] eq "exception" || [dict get $d continue] != 1} {
                ns_log Warning "exception on websocket: $d"
                break
            }
        }
    }

    nsf::proc ::ws::client::close {chan} {
        ns_connchan close $chan
    }

    nsf::proc -deprecated ::ws::build_msg {
        {-opcode "text"}
        {-mask:switch}
        payload
    } {
        #
        # This function is just easier migration, since "connchan
        # wsencode" provides a superset of functionality.
        #
        set maskArg [expr {$mask ? "-mask" : ""}]
        return [ns_connchan wsencode {*}$maskArg -opcode $opcode $payload]
    }

}

if {$::ws::echo_service} {
    ns_register_proc GET /websocket/echo ::ws::echo::connect
    namespace eval ws::echo {
        nsf::proc connect {} {
            set chat [ns_conn url]
            set channel [ws::handshake -callback [list ws::echo::send -chat $chat]]
            ws::subscribe $channel $chat
        }

        nsf::proc send {
            {-chat "chat"}
            channel msg
        } {
            #ns_log notice "ws::test::echo call send"
            set r [::ws::send $channel [ns_connchan wsencode $msg]]
            #ns_log notice "ws::test::echo returns <$r>"
            return $r
        }
    }
}

#
# Local variables:
#    mode: tcl
#    tcl-indent-level: 4
#    indent-tabs-mode: nil
# End:
