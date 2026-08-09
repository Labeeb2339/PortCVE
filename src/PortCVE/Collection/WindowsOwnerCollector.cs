using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using PortCVE.Domain;

namespace PortCVE.Collection;

[SupportedOSPlatform("windows")]
public sealed class WindowsOwnerCollector
{
    public CollectionResult<IReadOnlyDictionary<int, OwnerEvidence>> Collect(
        IEnumerable<int> processIds,
        bool hashBinaries,
        bool resolveAccounts)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var stopwatch = Stopwatch.StartNew();
        var diagnostics = new List<CollectorDiagnostic>();
        var parentMap = CollectParentMap(diagnostics);
        var serviceMap = CollectServiceMap(diagnostics);
        var owners = new Dictionary<int, OwnerEvidence>();

        foreach (var pid in processIds.Distinct().Order())
        {
            owners[pid] = CollectProcess(pid, parentMap, serviceMap, diagnostics, hashBinaries, resolveAccounts);
        }

        var processDiagnostics = diagnostics
            .Where(static item => item.Code == "process_metadata_partial")
            .ToArray();
        if (processDiagnostics.Length > 1)
        {
            diagnostics.RemoveAll(static item => item.Code == "process_metadata_partial");
            diagnostics.Add(new(
                "process_owners",
                CollectorStatus.Partial,
                "process_metadata_partial",
                $"Process metadata was partial for {processDiagnostics.Length} endpoint owner(s), usually because Windows denied access or a process exited."));
        }

        stopwatch.Stop();
        var partialOwners = owners.Values.Count(static owner => !owner.IsComplete);
        var status = partialOwners > 0 || diagnostics.Count > 0
            ? CollectorStatus.Partial
            : CollectorStatus.Complete;

        return new(
            owners,
            new("process_owners", status, startedAt, stopwatch.ElapsedMilliseconds, diagnostics));
    }

    private static OwnerEvidence CollectProcess(
        int pid,
        IReadOnlyDictionary<int, ParentEntry> parents,
        IReadOnlyDictionary<int, ServiceAttribution> services,
        List<CollectorDiagnostic> diagnostics,
        bool hashBinaries,
        bool resolveAccounts)
    {
        var limitations = new List<string>();
        var imageName = pid switch
        {
            0 => "System Idle Process",
            4 => "System",
            _ => $"pid-{pid}",
        };
        string? imagePath = null;
        string? imageSha256 = null;
        DateTimeOffset? creationTime = null;
        string? sid = null;
        string? accountName = null;
        parents.TryGetValue(pid, out var parentEntry);
        var serviceAttribution = services.TryGetValue(pid, out var mappedServices)
            ? mappedServices
            : ServiceAttribution.None;
        var serviceNames = serviceAttribution.Names;

        if (parentEntry is not null && !string.IsNullOrWhiteSpace(parentEntry.ImageName))
        {
            imageName = parentEntry.ImageName;
        }

        if (pid > 0)
        {
            var processHandle = NativeMethods.OpenProcess(NativeMethods.ProcessQueryLimitedInformation, false, pid);
            if (processHandle == IntPtr.Zero)
            {
                limitations.Add($"Process metadata unavailable: Win32 error {Marshal.GetLastWin32Error()}.");
            }
            else
            {
                try
                {
                    imagePath = QueryImagePath(processHandle);
                    if (!string.IsNullOrWhiteSpace(imagePath))
                    {
                        imageName = Path.GetFileName(imagePath);
                        if (hashBinaries)
                        {
                            imageSha256 = TryHashBinary(imagePath, limitations);
                        }
                    }

                    creationTime = QueryCreationTime(processHandle);
                    (sid, accountName) = QueryProcessIdentity(processHandle, resolveAccounts);
                    if (sid is null)
                    {
                        limitations.Add("Process owner SID was not available.");
                    }
                }
                finally
                {
                    NativeMethods.CloseHandle(processHandle);
                }
            }
        }

        var isComplete = imagePath is not null && creationTime is not null && (sid is not null || pid is 0 or 4);
        if (!isComplete)
        {
            diagnostics.Add(new(
                "process_owners",
                CollectorStatus.Partial,
                "process_metadata_partial",
                $"PID {pid}: {string.Join(' ', limitations)}"));
        }

        return new(
            pid,
            creationTime,
            imageName,
            imagePath,
            imageSha256,
            parentEntry?.ParentPid,
            parentEntry?.ParentImageName,
            sid,
            accountName,
            serviceNames,
            serviceAttribution.AreCandidates,
            isComplete,
            limitations);
    }

    private static string? TryHashBinary(string path, List<string> limitations)
    {
        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            limitations.Add($"Binary hash unavailable: {exception.Message}");
            return null;
        }
    }

    private static string? QueryImagePath(IntPtr processHandle)
    {
        var capacity = 32768;
        var builder = new StringBuilder(capacity);
        return NativeMethods.QueryFullProcessImageName(processHandle, 0, builder, ref capacity)
            ? builder.ToString()
            : null;
    }

    private static DateTimeOffset? QueryCreationTime(IntPtr processHandle)
    {
        if (!NativeMethods.GetProcessTimes(processHandle, out var creation, out _, out _, out _))
        {
            return null;
        }

        var fileTime = ((long)creation.HighDateTime << 32) + creation.LowDateTime;
        try
        {
            return DateTimeOffset.FromFileTime(fileTime);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static (string? Sid, string? AccountName) QueryProcessIdentity(
        IntPtr processHandle,
        bool resolveAccounts)
    {
        if (!NativeMethods.OpenProcessToken(processHandle, NativeMethods.TokenQuery, out var tokenHandle))
        {
            return (null, null);
        }

        try
        {
            _ = NativeMethods.GetTokenInformation(tokenHandle, NativeMethods.TokenUser, IntPtr.Zero, 0, out var length);
            if (length <= 0)
            {
                return (null, null);
            }

            var buffer = Marshal.AllocHGlobal(length);
            try
            {
                if (!NativeMethods.GetTokenInformation(tokenHandle, NativeMethods.TokenUser, buffer, length, out _))
                {
                    return (null, null);
                }

                var tokenUser = Marshal.PtrToStructure<TokenUser>(buffer);
                var sid = ConvertSid(tokenUser.User.Sid);
                var account = resolveAccounts ? LookupAccount(tokenUser.User.Sid) : null;
                return (sid, account);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            NativeMethods.CloseHandle(tokenHandle);
        }
    }

    private static string? ConvertSid(IntPtr sid)
    {
        if (!NativeMethods.ConvertSidToStringSid(sid, out var stringSid))
        {
            return null;
        }

        try
        {
            return Marshal.PtrToStringUni(stringSid);
        }
        finally
        {
            NativeMethods.LocalFree(stringSid);
        }
    }

    private static string? LookupAccount(IntPtr sid)
    {
        uint nameLength = 0;
        uint domainLength = 0;
        _ = NativeMethods.LookupAccountSid(null, sid, null, ref nameLength, null, ref domainLength, out _);
        if (nameLength == 0)
        {
            return null;
        }

        var name = new StringBuilder((int)nameLength);
        var domain = new StringBuilder((int)Math.Max(domainLength, 1));
        return NativeMethods.LookupAccountSid(null, sid, name, ref nameLength, domain, ref domainLength, out _)
            ? string.IsNullOrWhiteSpace(domain.ToString()) ? name.ToString() : $"{domain}\\{name}"
            : null;
    }

    private static IReadOnlyDictionary<int, ParentEntry> CollectParentMap(List<CollectorDiagnostic> diagnostics)
    {
        var result = new Dictionary<int, ParentEntry>();
        var snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.Th32csSnapProcess, 0);
        if (snapshot == NativeMethods.InvalidHandleValue)
        {
            diagnostics.Add(new("process_owners", CollectorStatus.Partial, "parent_snapshot_failed",
                $"Toolhelp snapshot failed with Win32 error {Marshal.GetLastWin32Error()}."));
            return result;
        }

        try
        {
            var entry = new ProcessEntry32 { Size = (uint)Marshal.SizeOf<ProcessEntry32>() };
            if (!NativeMethods.Process32First(snapshot, ref entry))
            {
                return result;
            }

            var names = new Dictionary<int, string>();
            var rawParents = new Dictionary<int, int>();
            do
            {
                names[(int)entry.ProcessId] = entry.ExecutableFile;
                rawParents[(int)entry.ProcessId] = (int)entry.ParentProcessId;
                entry.Size = (uint)Marshal.SizeOf<ProcessEntry32>();
            }
            while (NativeMethods.Process32Next(snapshot, ref entry));

            foreach (var pair in rawParents)
            {
                names.TryGetValue(pair.Value, out var parentName);
                result[pair.Key] = new(pair.Value, names[pair.Key], parentName);
            }
        }
        finally
        {
            NativeMethods.CloseHandle(snapshot);
        }

        return result;
    }

    private static IReadOnlyDictionary<int, ServiceAttribution> CollectServiceMap(List<CollectorDiagnostic> diagnostics)
    {
        var result = new Dictionary<int, ServiceAccumulator>();
        var manager = NativeMethods.OpenSCManager(null, null, NativeMethods.ScManagerEnumerateService);
        if (manager == IntPtr.Zero)
        {
            diagnostics.Add(new("services", CollectorStatus.Partial, "scm_open_failed",
                $"Service Control Manager access failed with Win32 error {Marshal.GetLastWin32Error()}."));
            return new Dictionary<int, ServiceAttribution>();
        }

        try
        {
            _ = NativeMethods.EnumServicesStatusEx(
                manager,
                NativeMethods.ScEnumProcessInfo,
                NativeMethods.ServiceWin32,
                NativeMethods.ServiceActive,
                IntPtr.Zero,
                0,
                out var bytesNeeded,
                out _,
                IntPtr.Zero,
                null);

            if (bytesNeeded == 0)
            {
                return new Dictionary<int, ServiceAttribution>();
            }

            var buffer = Marshal.AllocHGlobal((int)bytesNeeded);
            try
            {
                if (!NativeMethods.EnumServicesStatusEx(
                    manager,
                    NativeMethods.ScEnumProcessInfo,
                    NativeMethods.ServiceWin32,
                    NativeMethods.ServiceActive,
                    buffer,
                    bytesNeeded,
                    out _,
                    out var count,
                    IntPtr.Zero,
                    null))
                {
                    diagnostics.Add(new("services", CollectorStatus.Partial, "service_enumeration_failed",
                        $"Service enumeration failed with Win32 error {Marshal.GetLastWin32Error()}."));
                    return new Dictionary<int, ServiceAttribution>();
                }

                var size = Marshal.SizeOf<EnumServiceStatusProcess>();
                for (var index = 0; index < count; index++)
                {
                    var item = Marshal.PtrToStructure<EnumServiceStatusProcess>(buffer + (index * size));
                    var pid = (int)item.Status.ProcessId;
                    var name = Marshal.PtrToStringUni(item.ServiceName);
                    if (pid <= 0 || string.IsNullOrWhiteSpace(name))
                    {
                        continue;
                    }

                    if (!result.TryGetValue(pid, out var accumulator))
                    {
                        accumulator = new();
                        result[pid] = accumulator;
                    }

                    accumulator.Names.Add(name);
                    accumulator.HasSharedProcessService |=
                        (item.Status.ServiceType & NativeMethods.ServiceWin32ShareProcess) != 0;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            NativeMethods.CloseServiceHandle(manager);
        }

        return result.ToDictionary(
            static pair => pair.Key,
            static pair => new ServiceAttribution(
                pair.Value.Names.Order(StringComparer.OrdinalIgnoreCase).ToArray(),
                pair.Value.HasSharedProcessService || pair.Value.Names.Count > 1));
    }

    private sealed record ParentEntry(int ParentPid, string ImageName, string? ParentImageName);

    private sealed record ServiceAttribution(IReadOnlyList<string> Names, bool AreCandidates)
    {
        public static ServiceAttribution None { get; } = new([], false);
    }

    private sealed class ServiceAccumulator
    {
        public List<string> Names { get; } = [];

        public bool HasSharedProcessService { get; set; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint LowDateTime;
        public uint HighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenUser
    {
        public SidAndAttributes User;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public IntPtr DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int PriorityClassBase;
        public uint Flags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string ExecutableFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EnumServiceStatusProcess
    {
        public IntPtr ServiceName;
        public IntPtr DisplayName;
        public ServiceStatusProcess Status;
    }

    private static class NativeMethods
    {
        public const uint ProcessQueryLimitedInformation = 0x1000;
        public const uint TokenQuery = 0x0008;
        public const int TokenUser = 1;
        public const uint Th32csSnapProcess = 0x00000002;
        public const uint ScManagerEnumerateService = 0x0004;
        public const int ScEnumProcessInfo = 0;
        public const uint ServiceWin32 = 0x00000030;
        public const uint ServiceWin32ShareProcess = 0x00000020;
        public const uint ServiceActive = 0x00000001;
        public static readonly IntPtr InvalidHandleValue = new(-1);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryFullProcessImageName(
            IntPtr process,
            uint flags,
            StringBuilder fileName,
            ref int size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetProcessTimes(
            IntPtr process,
            out FileTime creationTime,
            out FileTime exitTime,
            out FileTime kernelTime,
            out FileTime userTime);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(
            IntPtr token,
            int informationClass,
            IntPtr information,
            int informationLength,
            out int returnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupAccountSid(
            string? systemName,
            IntPtr sid,
            StringBuilder? name,
            ref uint nameLength,
            StringBuilder? domainName,
            ref uint domainNameLength,
            out int use);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr memory);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Process32First(IntPtr snapshot, ref ProcessEntry32 entry);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry32 entry);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr OpenSCManager(string? machineName, string? databaseName, uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumServicesStatusEx(
            IntPtr manager,
            int infoLevel,
            uint serviceType,
            uint serviceState,
            IntPtr services,
            uint bufferSize,
            out uint bytesNeeded,
            out uint servicesReturned,
            IntPtr resumeHandle,
            string? groupName);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseServiceHandle(IntPtr serviceHandle);
    }
}
