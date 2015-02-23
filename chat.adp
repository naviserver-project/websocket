<!DOCTYPE html>
<%
   set host [ad_host]
   set wsProtocol [expr {[ns_conn protocol] eq "http" ? "ws" : "wss"}]
   set port [ns_config [ns_driversection] port [ns_conn port]]
   set baseUrl [string trimright $host:$port/[ns_conn url]]
   set wsUri $wsProtocol://$baseUrl/connect
 %>
<html>
	<head>
		<title>ws chat</title>
		<meta http-equiv="Content-Type" content="text/html;charset=utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
  	        <link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.1/css/bootstrap.min.css">
    	        <link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.1/css/bootstrap-theme.min.css">
                <script src="//ajax.googleapis.com/ajax/libs/jquery/2.1.1/jquery.min.js"></script>
		<script language="javascript" type="text/javascript">  
			var wsUri = '<%= $wsUri %>';
			var output;
			var state;
			var websocket = 0;

			function init() {
			   output = document.getElementById('output');
			   state = document.getElementById('state');
			   testWebSocket();
			}  
			function testWebSocket() { 
			       if ("WebSocket" in window) {
					websocket = new WebSocket(wsUri);
				} else {
					websocket = new MozWebSocket(wsUri);
				}
				websocket.onopen 	= function(evt) { onOpen(evt) }; 
				websocket.onclose 	= function(evt) { onClose(evt) }; 
				websocket.onmessage = function(evt) { onMessage(evt) }; 
				websocket.onerror 	= function(evt) { onError(evt) }; 
			}

			function onOpen(evt) 		{ state.innerHTML = '<span style="color:green;">CONNECTED</span>';  }
			function onClose(evt) 		{ state.innerHTML = '<span style="color:red;">DISCONNECTED</span>'; testWebSocket(); }  
			function onMessage(evt) 	{ writeToScreen("RESPONSE:", "blue", evt.data); }  
			function onError(evt)		{ writeToScreen("ERROR:", "red", evt.data); }  
			function doSend(message)	{ websocket.send(message); writeToScreen("SENT:", "green",  message);}
			function checkSubmit(e)		{ if (e && e.keyCode ==13) { doSend($('#msg').val()); }}

			function writeToScreen(tag, color, message) {
			        if (message !== undefined) {
			           var pre = document.createElement("p");
			           pre.style.wordWrap = "break-word";
			           var content = "<span style='color: " + color + ";'>" + tag + '</span> ';
			           pre.innerHTML = content + message.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
		                   output.appendChild(pre);
		                }
			}
			function clearOutput() {
				output.innerHTML = '';
			}
  		        $( document ).ready(function() { init()});
		</script>
	</head>

	<body role="document">

	  <div class="container theme-showcase" role="main">
	    <div class="page-header">
	      <h1>Websocket Chat</h1>
	      <p class="lead">running at  <%= $wsProtocol://$baseUrl %> </p>
	    </div>
	    
	    <div style="margin: 5px 0px;">
	      Status: <span id="state">Uninitialized</span>
	      <button type="button" class="btn btn-default" onclick="clearOutput();">Clear Output</button>
	    </div>

	    <div class="row">
	      <div class="col-lg-6">
		<div class="input-group">
		  <span class="input-group-btn">
		    <button class="btn btn-primary" type="submit" onclick="doSend($('#msg').val());">Send</button>
		  </span>
		  <input type="text" id="msg" class="form-control" onKeyPress="return checkSubmit(event);">
		  </div><!-- /input-group -->
		</div><!-- /.col-lg-6 -->
	      </div> <!-- /row -->
	      <br>
		<div class="well" id="output">
		</div>
	      </div>
	    </div>
	    
	</body>
</html>
