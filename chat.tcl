#
# Chat demo application for websockets.
#
# This demo program shows how to establish a websocket connection and
# how to multicast messages. This script is accompanied by chat.adp,
# which resides in the same directory as this script.
#
# Gustaf Neumann, Jan 2015
#
package require nsf

#
# Get configured urls
#
set urls [ns_config ns/server/[ns_info server]/module/websocket/chat urls]

if {$urls eq ""} {
    ns_log notice "websocket: no chat configured"
    return
}

#
# Register websocket chat under every configured url
#
foreach url $urls {
    ns_log notice "websocket: chat available under $url"
    ns_register_adp  GET $url [file dirname [info script]]/chat.adp
    ns_register_proc GET $url/connect ::ws::chat::connect
}

namespace eval ws::chat {
    #
    # The proc "connect" is called, whenever a new websocket is
    # established.  The chat is named via the url to allow multiple
    # independent chats on different urls.
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

