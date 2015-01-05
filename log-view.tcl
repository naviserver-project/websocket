#
# Log-view demo application for websockets.
#
# This demo program shows how to establish a websocket connection and
# how to multicast messages. This script is accompanied by log-view.adp,
# which resides in the same directory as this script.
#
# Gustaf Neumann, Jan 2015
#
package require nsf

#
# Get configured urls
#
set urls [ns_config ns/server/[ns_info server]/module/websocket/log-view urls]

if {$urls eq ""} {
    ns_log notice "websocket: no chat configured"
    return
}

#
# Register websocket log-viewer under every configured url
#
foreach url $urls {
    ns_log notice "websocket: log-viewer available under $url"
    ns_register_adp  GET $url [file dirname [info script]]/log-view.adp
    ns_register_proc GET $url/connect ::ws::log::connect
    ns_register_proc GET $url/set ::ws::log::set_logging
}

namespace eval ws::log {
    #
    # The proc "connect" is called, whenever a new websocket is
    # established.  Per default, the log-viewer logs the "access.log" of
    # the server. The query parameter "log" can be used to specify
    # other files to be logged, such as e.g. the "error.log". The
    # logfile name is used as channel names for broadcasting to
    # multiple potential subscribers.
    #
    nsf::proc connect {} {
        set log [ns_queryget log "access.log"]
        set channel [ws::handshake -readevent true -callback [list ws::log::send_to_all -log $log]]
        ::ws::subscribe $channel $log
    }

    nsf::proc send_to_all {{-log "access.log"} channel msg} {
        ::ws::multicast $log [ws::build_msg $msg]
    }

    nsf::proc set_logging {} {
        foreach s [ns_logctl severities] {
            set level [ns_queryget $s ""]
            ns_logctl severity $s [expr {$level eq "" ? false : true}] 
        }
        ns_return 200 text/plain ""
    }


    nsv_set watch files [list [ns_accesslog file] [ns_info log]]

    ns_thread begindetached -name tail {
        #
        # The global state of the currently watched files is
        # maintained in the associative array "watched". The keys are
        # the file names, the values are file handles.
        #
        array set ::watched {}

        ns_log notice DETACHED=[ns_info server]

        #
        # Close all files wich are currently nor watched
        #
        nsf::proc ::ws::log::close_unwatched {watch_files} {
            foreach fn [array names ::watched] {
                if {$fn ni $watch_files} {
                    ns_log notice "watch: stop watching $fn"
                    close $::watched($fn)
                    unset ::watched($fn)
                }
            }
        }

        #
        # Open all files wich are currently watched
        #
        nsf::proc ::ws::log::open_watched {watch_files} {
            foreach fn $watch_files {
                if {![info exists ::watched($fn)]} {
                    ns_log notice "watch: start watching $fn"
                    set ::watched($fn) [open $fn]
                }
            }
        }

        #
        # For every watched file, report changes via multicast
        #
        nsf::proc ::ws::log::report_updates {} {
            foreach {filename f} [array get ::watched] {
                set size [file size $filename]
                set pos  [tell $f]
                if {$pos == 0} {
                    #
                    # first, step to the end and start to watch from there
                    #
                    seek $f 0 end
                } elseif {$size < $pos} {
                    #
                    # file shrunk, restart
                    #
                    ns_log notice "tail: file $filename shrunk"
                    close $::watched($filename)
                    unset ::watched($filename)
                } elseif {$size > $pos} {
                    #
                    # report delta
                    #
                    set delta [read $f]
                    #ns_log notice "tail: multicast <$delta>"
                    ws::multicast $filename [ws::build_msg $delta]
                }
            }
        }

        #
        # For every watched file, report changes via multicast
        #        
        if {[catch {
            while {1} {
                set watch_files [nsv_get watch files]
                ws::log::close_unwatched $watch_files
                ws::log::open_watched $watch_files
                ws::log::report_updates
                after [ns_config ns/server/[ns_info server]/module/websocket/log-view refresh 1000] 

            }
        } errorMsg]} {
            ns_log error "file watcher returned $errorMsg"
        }
    }
}

#
# Local variables:
#    mode: tcl
#    tcl-indent-level: 4
#    indent-tabs-mode: nil
# End:

