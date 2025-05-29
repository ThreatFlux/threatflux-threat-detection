with Ada.Text_IO;           use Ada.Text_IO;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Calendar;          use Ada.Calendar;
with Ada.Environment_Variables;
with Ada.Command_Line;
with Interfaces;            use Interfaces;

procedure Ada_Simple is
   
   -- Constants
   C2_Server : constant String := "msftupdater.com";
   C2_Port   : constant := 443;
   XOR_Key   : constant := 16#42#;
   
   -- Global variables
   Debugger_Detected : Boolean := False;
   Sandbox_Detected  : Boolean := False;
   
   -- Simple XOR obfuscation
   function XOR_String (S : String) return String is
      Result : String (S'Range);
   begin
      for I in S'Range loop
         Result(I) := Character'Val(Unsigned_8(Character'Pos(S(I))) xor Unsigned_8(XOR_Key));
      end loop;
      return Result;
   end XOR_String;
   
   -- Check for debugger (simplified)
   procedure Check_Debugger is
      Start_Time : Time;
      End_Time   : Time;
   begin
      Start_Time := Clock;
      delay 0.1;
      End_Time := Clock;
      
      if End_Time - Start_Time > 0.5 then
         Debugger_Detected := True;
      end if;
      
      -- Check TracerPid in /proc/self/status
      declare
         File : File_Type;
         Line : String (1 .. 256);
         Last : Natural;
      begin
         Open(File, In_File, "/proc/self/status");
         while not End_Of_File(File) loop
            Get_Line(File, Line, Last);
            if Last > 10 and then Line(1..10) = "TracerPid:" then
               if Line(11..Last) /= " 0" then
                  Debugger_Detected := True;
               end if;
            end if;
         end loop;
         Close(File);
      exception
         when others => null;
      end;
   end Check_Debugger;
   
   -- Check environment
   procedure Check_Environment is
   begin
      if Ada.Environment_Variables.Exists("SANDBOX") or
         Ada.Environment_Variables.Exists("MALWARE_ANALYSIS") then
         Sandbox_Detected := True;
      end if;
   end Check_Environment;
   
   -- Network beacon simulation
   procedure Network_Beacon is
      User : constant String := (if Ada.Environment_Variables.Exists("USER") then
                                    Ada.Environment_Variables.Value("USER")
                                 else "unknown");
      Message : String := "BEACON|" & User & "|" & C2_Server;
   begin
      Put_Line(XOR_String("Attempting network beacon..."));
      Put_Line("Beacon message: " & XOR_String(Message));
      -- Would connect to C2_Server:C2_Port in real malware
   end Network_Beacon;
   
   -- Process injection simulation
   procedure Inject_Process is
   begin
      Put_Line(XOR_String("Simulating process injection..."));
      Put_Line("Target: explorer.exe");
      -- Would perform actual injection in real malware
   end Inject_Process;
   
   -- Persistence installation
   procedure Install_Persistence is
      Cron_Command : String := "* * * * * /tmp/.ada_malware";
   begin
      Put_Line(XOR_String("Installing persistence..."));
      Put_Line("Cron: " & Cron_Command);
      -- Would write to crontab in real malware
   end Install_Persistence;
   
   -- Resource exhaustion
   procedure Resource_Exhaustion is
      Result : Float := 0.0;
   begin
      Put_Line(XOR_String("Starting resource exhaustion..."));
      
      for I in 1 .. 100_000 loop
         for J in 1 .. 100 loop
            Result := Result + Float(I * J);
         end loop;
         
         if I mod 10_000 = 0 then
            Put_Line("Progress: " & Integer'Image(I / 1_000) & "%");
         end if;
      end loop;
   end Resource_Exhaustion;
   
   -- Keylogger simulation
   procedure Keylogger is
   begin
      Put_Line(XOR_String("Keylogger simulation..."));
      Put_Line("Captured: username: admin password: AdaP@ss123");
      -- Would write to hidden log file in real malware
   end Keylogger;
   
   -- Data exfiltration
   procedure Exfiltrate_Data is
      Sensitive_Data : Unbounded_String;
   begin
      Put_Line(XOR_String("Exfiltrating data..."));
      
      Append(Sensitive_Data, "User: " & 
             (if Ada.Environment_Variables.Exists("USER") then
                 Ada.Environment_Variables.Value("USER")
              else "unknown") & ASCII.LF);
              
      Append(Sensitive_Data, "Credit Card: 4111-1111-1111-1111" & ASCII.LF);
      Append(Sensitive_Data, "SSN: 123-45-6789" & ASCII.LF);
      
      Put_Line("Data collected: " & To_String(Sensitive_Data));
      
      -- Simulate sending to C2
      Network_Beacon;
   end Exfiltrate_Data;
   
begin
   Put_Line("Ada Test Binary for Analysis");
   Put_Line("============================");
   
   -- Anti-analysis checks
   Check_Debugger;
   Check_Environment;
   
   if Debugger_Detected then
      Put_Line(XOR_String("Debugger detected!"));
   end if;
   
   if Sandbox_Detected then
      Put_Line(XOR_String("Sandbox detected!"));
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
   
   Put_Line(XOR_String("Program completed"));
   
exception
   when others =>
      Put_Line("Error occurred");
end Ada_Simple;