using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

[assembly: InternalsVisibleTo("PortCVE.Tests")]

namespace PortCVE.Platforms.Windows;

public sealed class WindowsEndpointCollector
{
    private const uint NoError = 0;
    private const uint ErrorInsufficientBuffer = 122;
    private const int TableHeaderSize = sizeof(uint);
    private const int MaxBufferAttempts = 8;

    [SupportedOSPlatform("windows")]
    public IReadOnlyList<WindowsRawEndpoint> Collect()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                $"{nameof(WindowsEndpointCollector)} is only supported on Windows.");
        }

        var endpoints = new List<WindowsRawEndpoint>();

        ReadNativeTable(
            (IntPtr buffer, ref uint size) => NativeMethods.GetExtendedTcpTable(
                buffer,
                ref size,
                order: false,
                addressFamily: (uint)AddressFamily.InterNetwork,
                tableClass: TcpTableClass.OwnerPidListener,
                reserved: 0),
            "IPv4 TCP listener table",
            (buffer, length) => ParseTcpV4(buffer, length, endpoints));

        ReadNativeTable(
            (IntPtr buffer, ref uint size) => NativeMethods.GetExtendedTcpTable(
                buffer,
                ref size,
                order: false,
                addressFamily: (uint)AddressFamily.InterNetworkV6,
                tableClass: TcpTableClass.OwnerPidListener,
                reserved: 0),
            "IPv6 TCP listener table",
            (buffer, length) => ParseTcpV6(buffer, length, endpoints));

        ReadNativeTable(
            (IntPtr buffer, ref uint size) => NativeMethods.GetExtendedUdpTable(
                buffer,
                ref size,
                order: false,
                addressFamily: (uint)AddressFamily.InterNetwork,
                tableClass: UdpTableClass.OwnerPid,
                reserved: 0),
            "IPv4 UDP endpoint table",
            (buffer, length) => ParseUdpV4(buffer, length, endpoints));

        ReadNativeTable(
            (IntPtr buffer, ref uint size) => NativeMethods.GetExtendedUdpTable(
                buffer,
                ref size,
                order: false,
                addressFamily: (uint)AddressFamily.InterNetworkV6,
                tableClass: UdpTableClass.OwnerPid,
                reserved: 0),
            "IPv6 UDP endpoint table",
            (buffer, length) => ParseUdpV6(buffer, length, endpoints));

        return endpoints.AsReadOnly();
    }

    internal static int DecodePort(uint networkOrderPort)
    {
        var networkOrderValue = unchecked((short)(networkOrderPort & ushort.MaxValue));
        return unchecked((ushort)IPAddress.NetworkToHostOrder(networkOrderValue));
    }

    internal static long DecodeScopeId(uint rawScopeId)
    {
        var networkDecoded = unchecked((uint)IPAddress.NetworkToHostOrder(unchecked((int)rawScopeId)));

        // Microsoft documents this field as network byte order, but current Windows builds can
        // return host-order interface indexes in these owner tables. Prefer the only plausible
        // small interface index when the two representations disagree dramatically.
        if (rawScopeId <= ushort.MaxValue && networkDecoded > ushort.MaxValue)
        {
            return rawScopeId;
        }

        return networkDecoded;
    }

    private static void ReadNativeTable(
        NativeTableReader reader,
        string tableDescription,
        Action<IntPtr, int> parse)
    {
        uint requiredSize = 0;
        var result = reader(IntPtr.Zero, ref requiredSize);

        if (result == NoError && requiredSize == 0)
        {
            return;
        }

        if (result != ErrorInsufficientBuffer && result != NoError)
        {
            throw CreateNativeException(result, tableDescription);
        }

        if (requiredSize < TableHeaderSize)
        {
            requiredSize = TableHeaderSize;
        }

        for (var attempt = 0; attempt < MaxBufferAttempts; attempt++)
        {
            if (requiredSize > int.MaxValue)
            {
                throw new InvalidOperationException(
                    $"The {tableDescription} requires an unsupported {requiredSize}-byte buffer.");
            }

            var bufferLength = checked((int)requiredSize);
            var buffer = Marshal.AllocHGlobal(bufferLength);

            try
            {
                var suppliedSize = requiredSize;
                result = reader(buffer, ref suppliedSize);

                if (result == NoError)
                {
                    parse(buffer, bufferLength);
                    return;
                }

                if (result != ErrorInsufficientBuffer)
                {
                    throw CreateNativeException(result, tableDescription);
                }

                requiredSize = suppliedSize > requiredSize
                    ? suppliedSize
                    : checked(requiredSize * 2);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        throw new Win32Exception(
            (int)ErrorInsufficientBuffer,
            $"The {tableDescription} kept changing while it was being read.");
    }

    private static Win32Exception CreateNativeException(uint result, string tableDescription) =>
        new(checked((int)result), $"Unable to read the {tableDescription}.");

    private static void ParseTcpV4(
        IntPtr buffer,
        int bufferLength,
        ICollection<WindowsRawEndpoint> endpoints)
    {
        var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
        var entryCount = ReadEntryCount(buffer, bufferLength, rowSize, "IPv4 TCP");

        for (var index = 0; index < entryCount; index++)
        {
            var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(
                IntPtr.Add(buffer, TableHeaderSize + (index * rowSize)));

            endpoints.Add(new WindowsRawEndpoint(
                WindowsEndpointProtocol.Tcp,
                AddressFamily.InterNetwork,
                DecodeIpv4Address(row.LocalAddress),
                DecodePort(row.LocalPort),
                row.OwningProcessId,
                DecodeTcpState(row.State)));
        }
    }

    private static void ParseTcpV6(
        IntPtr buffer,
        int bufferLength,
        ICollection<WindowsRawEndpoint> endpoints)
    {
        var rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();
        var entryCount = ReadEntryCount(buffer, bufferLength, rowSize, "IPv6 TCP");

        for (var index = 0; index < entryCount; index++)
        {
            var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(
                IntPtr.Add(buffer, TableHeaderSize + (index * rowSize)));

            endpoints.Add(new WindowsRawEndpoint(
                WindowsEndpointProtocol.Tcp,
                AddressFamily.InterNetworkV6,
                DecodeIpv6Address(row.LocalAddress, row.LocalScopeId),
                DecodePort(row.LocalPort),
                row.OwningProcessId,
                DecodeTcpState(row.State)));
        }
    }

    private static void ParseUdpV4(
        IntPtr buffer,
        int bufferLength,
        ICollection<WindowsRawEndpoint> endpoints)
    {
        var rowSize = Marshal.SizeOf<MibUdpRowOwnerPid>();
        var entryCount = ReadEntryCount(buffer, bufferLength, rowSize, "IPv4 UDP");

        for (var index = 0; index < entryCount; index++)
        {
            var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(
                IntPtr.Add(buffer, TableHeaderSize + (index * rowSize)));

            endpoints.Add(new WindowsRawEndpoint(
                WindowsEndpointProtocol.Udp,
                AddressFamily.InterNetwork,
                DecodeIpv4Address(row.LocalAddress),
                DecodePort(row.LocalPort),
                row.OwningProcessId,
                TcpState: null));
        }
    }

    private static void ParseUdpV6(
        IntPtr buffer,
        int bufferLength,
        ICollection<WindowsRawEndpoint> endpoints)
    {
        var rowSize = Marshal.SizeOf<MibUdp6RowOwnerPid>();
        var entryCount = ReadEntryCount(buffer, bufferLength, rowSize, "IPv6 UDP");

        for (var index = 0; index < entryCount; index++)
        {
            var row = Marshal.PtrToStructure<MibUdp6RowOwnerPid>(
                IntPtr.Add(buffer, TableHeaderSize + (index * rowSize)));

            endpoints.Add(new WindowsRawEndpoint(
                WindowsEndpointProtocol.Udp,
                AddressFamily.InterNetworkV6,
                DecodeIpv6Address(row.LocalAddress, row.LocalScopeId),
                DecodePort(row.LocalPort),
                row.OwningProcessId,
                TcpState: null));
        }
    }

    private static int ReadEntryCount(
        IntPtr buffer,
        int bufferLength,
        int rowSize,
        string tableDescription)
    {
        if (bufferLength < TableHeaderSize)
        {
            throw new InvalidDataException($"The {tableDescription} table is missing its header.");
        }

        var entryCount = Marshal.ReadInt32(buffer);
        var maximumEntries = (bufferLength - TableHeaderSize) / rowSize;

        if (entryCount < 0 || entryCount > maximumEntries)
        {
            throw new InvalidDataException(
                $"The {tableDescription} table declared {entryCount} rows, " +
                $"but its buffer can hold at most {maximumEntries}.");
        }

        return entryCount;
    }

    private static IPAddress DecodeIpv4Address(uint address) =>
        new(BitConverter.GetBytes(address));

    private static IPAddress DecodeIpv6Address(byte[] address, uint networkOrderScopeId)
    {
        var scopeId = DecodeScopeId(networkOrderScopeId);
        return new IPAddress(address, scopeId);
    }

    private static TcpState DecodeTcpState(uint state) =>
        state is >= (uint)TcpState.Closed and <= (uint)TcpState.DeleteTcb
            ? (TcpState)state
            : TcpState.Unknown;

    private delegate uint NativeTableReader(IntPtr buffer, ref uint size);

    private enum TcpTableClass
    {
        OwnerPidListener = 3,
    }

    private enum UdpTableClass
    {
        OwnerPid = 1,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        internal uint State;
        internal uint LocalAddress;
        internal uint LocalPort;
        internal uint RemoteAddress;
        internal uint RemotePort;
        internal uint OwningProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] LocalAddress;

        internal uint LocalScopeId;
        internal uint LocalPort;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] RemoteAddress;

        internal uint RemoteScopeId;
        internal uint RemotePort;
        internal uint State;
        internal uint OwningProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        internal uint LocalAddress;
        internal uint LocalPort;
        internal uint OwningProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] LocalAddress;

        internal uint LocalScopeId;
        internal uint LocalPort;
        internal uint OwningProcessId;
    }

    private static class NativeMethods
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        internal static extern uint GetExtendedTcpTable(
            IntPtr tcpTable,
            ref uint size,
            [MarshalAs(UnmanagedType.Bool)] bool order,
            uint addressFamily,
            TcpTableClass tableClass,
            uint reserved);

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        internal static extern uint GetExtendedUdpTable(
            IntPtr udpTable,
            ref uint size,
            [MarshalAs(UnmanagedType.Bool)] bool order,
            uint addressFamily,
            UdpTableClass tableClass,
            uint reserved);
    }
}
