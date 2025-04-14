# WebSockets for NaviServer

## Release 0.3

```
neumann@wu-wien.ac.at
wolfgang.winkler@digital-concepts.com
```

This is a NaviServer module that implements WebSockets for NaviServer and provides an API for it. The WebSockets are integrated in NaviServer using the `ns_chan` command. The current implementation requires NaviServer 4.99.20 or newer.

Connections are established via `ws::handshake`, which is typically initiated via JavaScript. Common libraries such as jQuery provided support for WebSockets.

The [WebSocket protocol (RFC 6455)](https://datatracker.ietf.org/doc/html/rfc6455) defines a `ws://` and `wss://` prefix to indicate a WebSocket or a WebSocket Secure connection. Both schemes use the HTTP upgrade mechanism to upgrade to the WebSocket protocol. For WebSocket Secure connection, the NaviServer module `nsssl` has to be installed and configured. For incoming HTTP/HTTPS connections the upgrade is provided via the command `ws::handshake`, which returns a handle for the connection channel. This handle must be used for all other operations on the WebSocket, such as sending data to a single channel or subscribing/unsubscribing the channel from a subscription. The API provides means for encoding and decoding WebSocket messages and for sending messages as single- or multi-casts using a subscriber interface.

The package contains two sample WebSocket applications:

- **chat:** A simple chat application with the sole purpose of providing an example of how to use WebSockets.
- **log-view:** A WebSocket application that allows live viewing of log contents. It uses a Tcl-based "tail -f"-like command that watches certain files (e.g., `access.log` or `error.log`) and reports recent changes to the subscribed clients.

By default, the sample applications are deactivated. See the configuration section below on how to activate the sample applications.

The implementation is based on `nsf`, which is available from [http://next-scripting.org/](http://next-scripting.org/).

---

## Configuration

In order to configure WebSockets, add the following lines to the configuration file of NaviServer. The section `module/websocket/$appname` is optional and allows you to configure the named WebSocket applications.

When the section `module/websocket/$appname` is missing, or the `urls` parameter is empty, the application is deactivated. Using the `urls` parameter, multiple URLs can be specified under which the WebSocket applications are available. This allows you to define multiple chats with different subscriber lists.

Be aware that the log-view application might reveal internal information, so exercise caution when registering it on public sites. In the example below, it is provided under `/admin/`, which is restricted for site-wide administrators in OpenACS.

```tcl
ns_section "ns/server/${server}/modules" {
   ns_param websocket tcl
}
ns_section "ns/server/${server}/module/websocket/chat" {
   ns_param urls     /websocket/chat
}
ns_section "ns/server/${server}/module/websocket/log-view" {
   ns_param urls     /admin/websocket/log-view
   ns_param refresh  1000   ;# refresh time for file watcher in milliseconds
}
```

---

## Installation

```bash
make install
```

---

## Usage

The provided WebSocket **server API** consists of the following commands:

```tcl
ws::handshake ?-readevent /boolean/? ?-callback /script/?
ws::log /msg/
ws::multicast ?-exclude /value/? /subscription/ /msg/
ws::io /channel/ /callback/ /when/
ws::send /channel/ /msg/
ws::subscribe /channel/ /subscription/
ws::unsubscribe /channel/ /subscription/
```

The provided WebSocket **client API** consists of the following commands:

```tcl
ws::client::open /websocketurl/
ws::client::send /channel/ /textmessage/
ws::client::receive /channel/
ws::client::close /channel/
```

See the included example WebSocket server applications for usage patterns.

---

## Authors

```
Gustaf Neumann <neumann@wu-wien.ac.at>
Wolfgang Winkler <wolfgang.winkler@digital-concepts.com>
```
