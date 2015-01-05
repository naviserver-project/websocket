<!DOCTYPE html>
<% 
   set host [ad_host] 
   set port [ns_config [ns_driversection] port [ns_conn port]]
   set wsProtocol [expr {[ns_conn protocol] eq "http" ? "ws" : "wss"}]
   set baseUrl [string trimright $host:$port/[ns_conn url] /]
   set log [ns_queryget log "access.log"]
   set logControls ""
   if {$log eq "access.log"} {set log [ns_accesslog file]}
   if {$log eq "error.log"} {
      set log [ns_info log]
      set logControls "Logging: <form id='logctl' style='display: inline;' acton='<%= $baseUrl %>/set' method='GET'>"
      foreach s [ns_logctl severities] {
         set c [expr {[ns_logctl severity $s] ? "checked" : ""}]
         append logControls "<input type='checkbox' name='$s' value='$s' $c >$s, "
      }
      append logControls "</form>"
   }
   set wsUri $wsProtocol://$baseUrl/connect?log=$log
%>
<html>
	<head>
	  <title>ws log</title>
	  <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	  <meta name="viewport" content="width=device-width, initial-scale=1.0">
	    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.1/css/bootstrap.min.css">
    	      <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.1/css/bootstrap-theme.min.css">
              <script src="//ajax.googleapis.com/ajax/libs/jquery/2.1.1/jquery.min.js"></script>
	      <script language="javascript" type="text/javascript">  
			var wsUri = '<%= $wsUri %>';
			var output;
			var state;
			var websocket = 0;
			var interval;

			function init() {
			   output = document.getElementById('output');
			   state = document.getElementById('state');
			   testWebSocket();
			   startAutoScroll();
			   $('#logctl').change(function(){
			     var formdata = $(this).serialize();
			     $.ajax({ url: "<%= $baseUrl %>/ws-set-logging", data: formdata } );
			    });
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
			function onMessage(evt) 	{ writeToScreen("RESPONSE:", "blue", evt.data); /*websocket.close();*/ }  
			function onError(evt) 		{ console.log(evt); writeToScreen("ERROR:", "red", evt.data); }  
			function doSend(message) 	{ websocket.send(message); writeToScreen("SENT: ", "green",  message);}
			
			function writeToScreen(tag, color, message) {  if (interval != "") {$( '#output').append(message);} }
			function clearOutput() { output.innerHTML = ''; }
			function startAutoScroll() {
			   interval = window.setInterval(function() {
			      var elem = document.getElementById('logwindow');
			      elem.scrollTop = elem.scrollHeight;
			    }, 1000);
			    $( '#logging').html('Stop logging');
			}
			function stopAutoScroll() { clearInterval(interval); $( '#logging').html('Start logging'); interval = "";}
			function toggleLogging() { if (interval == "") {startAutoScroll();} else {stopAutoScroll()};}

  		        $( document ).ready(function() { init()});
		</script>
		<style>
		  .wrapper {
		     background-color: #fec;
		     margin: auto;
		     position: relative;
		  }
		  .header {
		     height: 40px;
		     background-color: green;
		     color: #fff;
		  }
		  .content {
		     position:absolute;
		     bottom:0px;
		     top: 40px;
		     width:100%;
		     overflow: auto;
		     background-color: #333;
		     color: #666;
		  }
		  .button {
		     appearance: button;
		     -moz-appearance: button;
		     -webkit-appearance: button;
		     text-decoration: none; font: menu; color: ButtonText;
		     display: inline-block; padding: 2px 8px;
		  }
		  pre {
		     font-size: x-small;
		  }
		</style>
	</head>
	      
	  <body role="document">

	  <div class="container-fluid theme-showcase" role="main">
	    <div class="page-header">
	      <h1>Websocket LogViewer</h1>
      	      <p class="lead">running at  <%= $wsProtocol://$baseUrl %> </p>
	    </div>
	    
		<div style="margin: 5px 0px;">
		  Status: <span id="state">Uninitialized</span>
		  <%= $logControls %>
		</div>
		<p>
		  <button type="button" class="btn btn-default" onclick="clearOutput();">Clear Output</button>
		  <button type="button" class="btn btn-default" onclick="toggleLogging();" id="logging">Toggle logging on</button>
		</p>
		<div class="wrapper">
		  <div class="header">
		    <%= $log %>
		  </div>
		  <div id="logwindow" style="overflow-y: scroll; height:600px;">
		    <pre id="output"></pre>
		  </div> 
		</div>

	</body>

</html>
