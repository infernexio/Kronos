import ../structs
import ../utils
import json

when defined(windows):
  import ../rth/utils/winapi_wrapper
  import winim/lean
else:
  from osproc import execCmdEx

proc cmd_kill*(task: Task): seq[TaskResponse] {.cdecl.} =
  let params = parseJson(task.parameters)
  let pid = params["pid"].getInt()

  when defined(windows):
    var
      output = ""
      status= ""

    var hProc: HANDLE
    var exitCode: DWORD

    hProc = wOpenProcess(PROCESS_TERMINATE.or(PROCESS_QUERY_LIMITED_INFORMATION), 0, cast[DWORD](pid))

    if hProc == 0:
      return buildReturnData(task.id, output, "error")

    if GetExitCodeProcess(hProc, addr exitCode):
      DBG("Terminating Process")
      if TerminateProcess(hProc, cast[UINT](exitCode)) == FALSE:
        status = "error"
    else:
      status = "error"

    return buildReturnData(task.id, output, status)
  else:
    var output = ""
    var status = ""

    try:
      let (_, code) = execCmdEx("kill -9 " & $pid)
      if code != 0:
        status = "error"

      return buildReturnData(task.id, output, status)
    except:
      status = "error"
      return buildReturnData(task.id, output, status)
