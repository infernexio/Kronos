import ../structs
import ../utils

when defined(windows):
  import json
  import winim
  import winim/winstr
else:
  from osproc import execProcess

when defined(windows):
  type
    AdapterInfo = object
      AdapterName: string
      AdapterId: string
      Description: string
      AddressesV4: seq[string]
      AddressesV6: seq[string]
      DnsServers: seq[string]
      Gateways: seq[string]
      DhcpAddresses: seq[string]
      Status: string
      DnsSuffix: string
      DnsEnabled: string
      DynamicDnsEnabled: string

  proc resolveIps[T](firstEntry: T): seq[string] =
    var unicastAddr = cast[T](firstEntry)

    while cast[int](unicastAddr) != 0:
      if unicastAddr.Address.lpSockaddr.sa_family == AF_INET:
        var si: ptr sockaddr_in = cast[ptr sockaddr_in](unicastAddr.Address.lpSockaddr)

        var ipAddr: PSTR = cast[PSTR](alloc(16))
        RtlIpv4AddressToStringA(si[].sin_addr, ipAddr)
        result.add($ipAddr)
        unicastAddr = unicastaddr.Next
      else:
        var si: ptr sockaddr_in6 = cast[ptr sockaddr_in6](unicastAddr.Address.lpSockaddr)
        var ipAddr: PSTR = cast[PSTR](alloc(40))
        RtlIpv6AddressToStringA(si[].sin6_addr, ipAddr)

  proc getIps(): seq[AdapterInfo] =
    const WORKING_BUFFER_SIZE = 15000
    var adpAddresses = cast[PIP_ADAPTER_ADDRESSES](alloc(WORKING_BUFFER_SIZE))
    var bufSize: ULONG
    var status = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, adpAddresses, addr bufSize)

    if status == ERROR_BUFFEROVERFLOW:
      adpAddresses = cast[PIP_ADAPTER_ADDRESSES](alloc(bufSize))
      status = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, adpAddresses, addr bufSize)
      if status != ERROR_SUCCESS:
        return @[]
    elif status != ERROR_SUCCESS:
      return @[]

    while cast[int](adpAddresses) != 0:
      var state = "down"
      if adpAddresses[].OperStatus == ifOperStatusUp:
        state = "up"

      result.add(AdapterInfo(
                  AdapterName: $adpAddresses[].FriendlyName,
                  Description: $adpAddresses[].Description,
                  AdapterId: $adpAddresses[].AdapterName,
                  Status: state,
                  AddressesV4: resolveIps(adpAddresses[].FirstUnicastAddress),
                  DnsServers: resolveIps(adpAddresses[].FirstDnsServerAddress),
                  DnsSuffix: $adpAddresses[].DnsSuffix
                  ))

      adpAddresses = adpAddresses.Next

proc cmd_ifconfig*(task: Task): seq[TaskResponse] {.cdecl.} =
  when defined(windows):
    var
      output = ""
      status = ""

    let ips = getIps()

    if len(ips) == 0:
      status = "error"
    else:
      output = $(%* ips)

    return buildReturnData(task.id, output, status)
  else:
    var output = ""
    var status = ""

    try:
      when defined(macosx):
        output = execProcess("ifconfig")
      else:
        output = execProcess("ip addr || ifconfig")

      return buildReturnData(task.id, output, status)
    except:
      status = "error"
      return buildReturnData(task.id, output, status)
