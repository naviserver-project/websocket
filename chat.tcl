#
# Chat demo application for WebSockets.
#
# This demo program shows how to establish a WebSocket connection and
# how to multicast messages. This script is accompanied by chat.adp,
# which resides in the same directory as this script.
#
# Gustaf Neumann, Jan 2015
#
package require nsf

#
# Get configured URLs
#
set URLs [ns_config ns/server/[ns_info server]/module/websocket/chat urls]

if {$URLs eq ""} {
    ns_log notice "WebSocket: no chat configured ([info script])"
    return
}

#
# Register WebSocket chat under every configured URL
#
foreach url $URLs {
    ns_log notice "WebSocket: chat available under $url"
    ns_register_adp  GET $url [file dirname [info script]]/chat.adp
    ns_register_proc GET $url/connect ::ws::chat::connect
}

namespace eval ws::chat {
    #
    # The proc "connect" is called, whenever a new WebSocket is
    # established.  The chat is named via the url to allow multiple
    # independent chats on different URLs.
    #
    nsf::proc connect {} {
        set chat [ns_conn url]
        set channel [ws::handshake -callback [list ws::chat::send_to_all -ip [ns_conn peeraddr] -chat $chat]]
        ws::subscribe $channel $chat
    }

    #
    # Whenever we receive a message, send it to all subscribers of the
    # chat, except the current one.
    #
    nsf::proc send_to_all {{-ip ""} {-chat "chat"} channel msg} {
        if {$ip ne ""} {
            set msg "$ip: $msg"
        }
        ::ws::multicast -exclude [list $channel] $chat [::ws::build_msg $msg]
    }
}

#
# Local variables:
#    mode: tcl
#    tcl-indent-level: 4
#    indent-tabs-mode: nil
# End:
