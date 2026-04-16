import ../structs
import ../utils
import json

when defined(windows):
  import ../rth/utils/winapi_wrapper
  import winim
  import std/tables
else:
  from osproc import execProcess
  import std/strutils

when defined(windows):
  type
    ProcessInfo = object
      process_id: int
      host: string
      architecture: string
      bin_path: string
      commmand_line: string
      name: string
      description: string
      integrity_level: int
      parent_process_id: int
      user: string
      signer: string


proc cmd_ps*(task: Task): seq[TaskResponse] {.cdecl.} =
  when defined(windows):
    var
      output = ""
      entry: PROCESSENTRY32
      hSnapshot: HANDLE

    var processList: seq[ProcessInfo]

    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer: CloseHandle(hSnapshot)

    if Process32First(hSnapshot, addr entry):
      while Process32Next(hSnapshot, addr entry):
        var pInfo = ProcessInfo()
        pInfo.name = entry.szExeFile.toString
        pInfo.process_id = cast[int](entry.th32ProcessID)
        pInfo.parent_process_id = cast[int](entry.th32ParentProcessID)

        DBG(entry.szExeFile.toString)

        var pHandle = wOpenProcess(cast[DWORD](PROCESS_QUERY_LIMITED_INFORMATION), false, entry.th32ProcessID)

        if pHandle == 0:
          processList.add(pInfo)
          continue

        pInfo.architecture = getArchitecture(pHandle)
        pInfo.user = getProcessOwner(pHandle)
        pInfo.integrity_level = getIntegrityLevel(pHandle)
        pInfo.host = getHost()

        processList.add(pInfo)

    output = $(%*{"processes": process_list}.toTable)
    return buildReturnData(task.id, output)
  else:
    var status = ""
    try:
      let raw = execProcess("ps -eo pid,ppid,user,comm")
      let lines = raw.splitLines()
      var processes = newSeq[JsonNode]()

      for idx in 0..<lines.len:
        let line = lines[idx].strip()
        if line.len == 0 or idx == 0:
          continue

        let parts = line.splitWhitespace()
        if parts.len < 4:
          continue

        let pid = parseInt(parts[0])
        let ppid = parseInt(parts[1])
        let user = parts[2]
        let name = parts[3..^1].join(" ")

        processes.add(%*{
          "process_id": pid,
          "parent_process_id": ppid,
          "user": user,
          "name": name,
          "host": getHost(),
          "architecture": getArchitecture(nil),
          "integrity_level": getIntegrityLevel(nil)
        })

      let output = $(%*{"processes": processes})
      return buildReturnData(task.id, output, status)
    except:
      status = "error"
      return buildReturnData(task.id, "", status)
