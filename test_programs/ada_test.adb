with Ada.Text_IO;           use Ada.Text_IO;
with Ada.Integer_Text_IO;   use Ada.Integer_Text_IO;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Strings.Fixed;     use Ada.Strings.Fixed;
with Ada.Calendar;          use Ada.Calendar;
with Ada.Directories;       use Ada.Directories;
with Ada.Environment_Variables;
with Ada.Streams.Stream_IO;
with Ada.Numerics.Elementary_Functions; use Ada.Numerics.Elementary_Functions;
with Ada.Command_Line;
with Ada.Exceptions;
with Interfaces.C;          use Interfaces.C;
with System;

procedure Ada_Test is
   
   -- Constants
   C2_Server     : constant String := "msftupdater.com";
   C2_Port       : constant := 443;
   XOR_Key       : constant := 16#42#;
   Malware_Path  : constant String := "/tmp/.ada_malware";
   
   -- Types
   type Byte is mod 256;
   type Byte_Array is array (Positive range <>) of Byte;
   
   type Payload_Record is record
      Command   : Unbounded_String;
      Data      : Byte_Array (1 .. 256);
      Timestamp : Time;
   end record;
   
   -- Global variables
   Debugger_Detected : Boolean := False;
   Sandbox_Detected  : Boolean := False;
   VM_Detected       : Boolean := False;
   
   -- C interface for system calls
   function C_System (Command : Interfaces.C.char_array) return Interfaces.C.int
      with Import => True, Convention => C, External_Name => "system";
   
   function C_Getpid return Interfaces.C.int
      with Import => True, Convention => C, External_Name => "getpid";
   
   procedure C_Sleep (Seconds : Interfaces.C.unsigned)
      with Import => True, Convention => C, External_Name => "sleep";
   
   -- XOR encryption/decryption
   procedure XOR_Crypt (Data : in out Byte_Array) is
   begin
      for I in Data'Range loop
         Data(I) := Data(I) xor XOR_Key;
      end loop;
   end XOR_Crypt;
   
   -- String obfuscation
   function Obfuscate (S : String) return String is
      Result : String (S'Range);
   begin
      for I in S'Range loop
         Result(I) := Character'Val((Character'Pos(S(I)) xor 16#55#) mod 256);
      end loop;
      return Result;
   end Obfuscate;
   
   function Deobfuscate (S : String) return String is
   begin
      return Obfuscate(S);  -- XOR is its own inverse
   end Deobfuscate;
   
   -- Anti-debugging check
   procedure Check_Debugger is
      Start_Time : Time;
      End_Time   : Time;
      Elapsed    : Duration;
   begin
      -- Timing-based detection
      Start_Time := Clock;
      C_Sleep(1);
      End_Time := Clock;
      Elapsed := End_Time - Start_Time;
      
      if Elapsed > 2.0 then
         Debugger_Detected := True;
      end if;
      
      -- Check /proc/self/status for TracerPid
      declare
         File : File_Type;
         Line : String (1 .. 256);
         Last : Natural;
      begin
         if Exists("/proc/self/status") then
            Open(File, In_File, "/proc/self/status");
            while not End_Of_File(File) loop
               Get_Line(File, Line, Last);
               if Last > 10 and then Line(1..10) = "TracerPid:" then
                  if Line(11..Last) /= " 0" and Line(11..Last) /= Character'Val(9) & "0" then
                     Debugger_Detected := True;
                  end if;
               end if;
            end loop;
            Close(File);
         end if;
      exception
         when others => null;
      end;
   end Check_Debugger;
   
   -- Environment and VM detection
   procedure Check_Environment is
   begin
      -- Check for sandbox environment variables
      if Ada.Environment_Variables.Exists("SANDBOX") or
         Ada.Environment_Variables.Exists("MALWARE_ANALYSIS") then
         Sandbox_Detected := True;
      end if;
      
      -- Check for VM indicators
      if Exists("/sys/devices/virtual/dmi/id/product_name") then
         declare
            File : File_Type;
            Content : String (1 .. 256);
            Last : Natural;
         begin
            Open(File, In_File, "/sys/devices/virtual/dmi/id/product_name");
            Get_Line(File, Content, Last);
            Close(File);
            
            if Last > 0 then
               declare
                  Lower_Content : String := Content(1..Last);
               begin
                  -- Convert to lowercase manually
                  for I in Lower_Content'Range loop
                     if Lower_Content(I) in 'A'..'Z' then
                        Lower_Content(I) := Character'Val(
                           Character'Pos(Lower_Content(I)) + 32);
                     end if;
                  end loop;
                  
                  if Index(Lower_Content, "virtualbox") > 0 or
                     Index(Lower_Content, "vmware") > 0 or
                     Index(Lower_Content, "qemu") > 0 then
                     VM_Detected := True;
                  end if;
               end;
            end if;
         exception
            when others => null;
         end;
      end if;
   end Check_Environment;
   
   -- Simple string search
   function Index (S : String; Pattern : String) return Natural is
   begin
      if Pattern'Length > S'Length then
         return 0;
      end if;
      
      for I in S'First .. S'Last - Pattern'Length + 1 loop
         if S(I .. I + Pattern'Length - 1) = Pattern then
            return I;
         end if;
      end loop;
      return 0;
   end Index;
   
   -- Network beacon simulation
   procedure Network_Beacon is
      Beacon : Unbounded_String;
      User : constant String := (if Ada.Environment_Variables.Exists("USER") then
                                    Ada.Environment_Variables.Value("USER")
                                 else "unknown");
   begin
      Put_Line(Deobfuscate(Obfuscate("Attempting network beacon...")));
      
      Beacon := To_Unbounded_String("BEACON|" & User & "|" & 
                                    Integer'Image(Integer(C_Getpid)) & "|" &
                                    Duration'Image(Seconds(Clock)));
      
      -- Would encrypt and send over network
      Put_Line("Beacon: " & To_String(Beacon));
   end Network_Beacon;
   
   -- Process injection simulation
   procedure Inject_Process is
      Shellcode : constant Byte_Array := (16#90#, 16#90#, 16#90#, 16#90#,
                                         16#90#, 16#90#, 16#90#, 16#90#);
   begin
      Put_Line(Deobfuscate(Obfuscate("Simulating process injection...")));
      Put_Line("Shellcode size: " & Integer'Image(Shellcode'Length) & " bytes");
   end Inject_Process;
   
   -- Persistence installation
   procedure Install_Persistence is
      Cron_Command : Unbounded_String;
   begin
      Put_Line(Deobfuscate(Obfuscate("Installing persistence...")));
      
      Cron_Command := To_Unbounded_String(
         "(crontab -l 2>/dev/null; echo ""* * * * * " & 
         Malware_Path & """ ) | crontab -");
      
      Put_Line("Persistence command: " & To_String(Cron_Command));
   end Install_Persistence;
   
   -- Resource exhaustion
   procedure Resource_Exhaustion is
      Result : Float := 0.0;
   begin
      Put_Line(Deobfuscate(Obfuscate("Starting resource exhaustion...")));
      
      for I in 1 .. 1_000_000 loop
         for J in 1 .. 100 loop
            Result := Result + Sin(Float(I * J)) * Cos(Float(I) / Float(J));
         end loop;
         
         if I mod 100_000 = 0 then
            Put_Line("Progress: " & Integer'Image(I / 10_000) & "%");
         end if;
      end loop;
      
      Put_Line("Resource exhaustion completed");
   end Resource_Exhaustion;
   
   -- Keylogger simulation
   procedure Keylogger is
      Log_Entry : Unbounded_String;
   begin
      Put_Line(Deobfuscate(Obfuscate("Keylogger simulation...")));
      
      Log_Entry := To_Unbounded_String(
         Year(Clock)'Image & "-" & 
         Month(Clock)'Image & "-" &
         Day(Clock)'Image & " - " &
         "Captured: username: admin password: AdaP@ss123");
      
      Put_Line("Keylog: " & To_String(Log_Entry));
   end Keylogger;
   
   -- Data exfiltration
   procedure Exfiltrate_Data is
      Sensitive_Data : Unbounded_String;
      Hash_Value : Natural := 0;
   begin
      Put_Line(Deobfuscate(Obfuscate("Exfiltrating data...")));
      
      -- Collect environment info
      Append(Sensitive_Data, "User: " & 
             (if Ada.Environment_Variables.Exists("USER") then
                 Ada.Environment_Variables.Value("USER")
              else "unknown") & ASCII.LF);
              
      Append(Sensitive_Data, "Home: " &
             (if Ada.Environment_Variables.Exists("HOME") then
                 Ada.Environment_Variables.Value("HOME")
              else "unknown") & ASCII.LF);
      
      -- Add fake sensitive data
      Append(Sensitive_Data, "Credit Card: 4111-1111-1111-1111" & ASCII.LF);
      Append(Sensitive_Data, "SSN: 123-45-6789" & ASCII.LF);
      Append(Sensitive_Data, "API Key: sk_live_ada_1234567890" & ASCII.LF);
      
      -- Simple hash calculation
      for C of To_String(Sensitive_Data) loop
         Hash_Value := Natural((Hash_Value * 31 + Character'Pos(C)) mod 2147483648);
      end loop;
      
      Put_Line("Data hash: " & Integer'Image(Hash_Value));
      
      -- Simulate sending to C2
      Network_Beacon;
   end Exfiltrate_Data;
   
   -- Self-modification simulation
   procedure Self_Modify is
      Signature : Byte_Array (1 .. 16);
   begin
      Put_Line(Deobfuscate(Obfuscate("Self-modification...")));
      
      -- Generate pseudo-random signature
      for I in Signature'Range loop
         Signature(I) := Byte((I * 13 + 7) mod 256);
      end loop;
      
      Put("Signature: ");
      for B of Signature loop
         Put(Integer'Image(Integer(B)) & " ");
      end loop;
      New_Line;
   end Self_Modify;
   
   -- Main program
begin
   Put_Line("Ada Test Binary for Analysis");
   Put_Line("============================");
   
   -- Anti-analysis checks
   Check_Debugger;
   Check_Environment;
   
   if Debugger_Detected then
      Put_Line(Deobfuscate(Obfuscate("Debugger detected!")));
   end if;
   
   if Sandbox_Detected then
      Put_Line(Deobfuscate(Obfuscate("Sandbox detected!")));
   end if;
   
   if VM_Detected then
      Put_Line(Deobfuscate(Obfuscate("Virtual machine detected!")));
   end if;
   
   -- Command line processing
   if Ada.Command_Line.Argument_Count > 0 then
      declare
         Command : constant String := Ada.Command_Line.Argument(1);
      begin
         if Command = "--inject" then
            Inject_Process;
         elsif Command = "--persist" then
            Install_Persistence;
         elsif Command = "--resource" then
            Resource_Exhaustion;
         elsif Command = "--keylog" then
            Keylogger;
         elsif Command = "--exfil" then
            Exfiltrate_Data;
         elsif Command = "--beacon" then
            Network_Beacon;
         elsif Command = "--modify" then
            Self_Modify;
         else
            Put_Line("Unknown command: " & Command);
         end if;
      end;
   else
      -- Default: run all operations
      Inject_Process;
      Install_Persistence;
      Keylogger;
      Exfiltrate_Data;
      Network_Beacon;
   end if;
   
   Put_Line(Deobfuscate(Obfuscate("Program completed")));
   
exception
   when E : others =>
      Put_Line("Error: " & Ada.Exceptions.Exception_Information(E));
end Ada_Test;