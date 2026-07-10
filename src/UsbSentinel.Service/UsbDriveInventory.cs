using System.Management;
using UsbSentinel.Contracts;

namespace UsbSentinel.Service;

public sealed class UsbDriveInventory
{
    private const int UsbBusType = 7;

    public IReadOnlyList<UsbDeviceInfo> GetConnectedUsbStorageDevices()
    {
        var devices = new Dictionary<string, UsbDeviceInfo>(StringComparer.OrdinalIgnoreCase);
        var usbPhysicalDrives = GetUsbPhysicalDriveIds();
        try
        {
            using var diskSearcher = new ManagementObjectSearcher(
                "SELECT DeviceID, Model, InterfaceType, PNPDeviceID, Status FROM Win32_DiskDrive");
            foreach (ManagementObject disk in diskSearcher.Get())
            {
                using (disk)
                {
                    if (!IsUsbBackedDisk(disk, usbPhysicalDrives))
                        continue;
                    var pnpId = disk["PNPDeviceID"]?.ToString() ?? string.Empty;
                    var id = string.IsNullOrWhiteSpace(pnpId) ? disk["DeviceID"]?.ToString() ?? Guid.NewGuid().ToString() : pnpId;
                    devices[id] = new UsbDeviceInfo(id, disk["Model"]?.ToString() ?? "USB storage device",
                        disk["Status"]?.ToString() ?? "Connected");
                }
            }

            using var pnpSearcher = new ManagementObjectSearcher(
                "SELECT DeviceID, Name, Status, Service FROM Win32_PnPEntity WHERE Service = 'USBSTOR' OR Service = 'UASPStor'");
            foreach (ManagementObject device in pnpSearcher.Get())
            {
                using (device)
                {
                    var id = device["DeviceID"]?.ToString();
                    if (string.IsNullOrWhiteSpace(id))
                        continue;
                    devices[id] = new UsbDeviceInfo(id, device["Name"]?.ToString() ?? "USB storage device",
                        device["Status"]?.ToString() ?? "Connected");
                }
            }
        }
        catch (ManagementException)
        {
        }

        return devices.Values.OrderBy(device => device.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public IReadOnlyList<string> GetMountedUsbVolumes()
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var usbPhysicalDrives = GetUsbPhysicalDriveIds();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT DeviceID, InterfaceType, PNPDeviceID FROM Win32_DiskDrive");
            foreach (ManagementObject disk in searcher.Get())
            {
                using (disk)
                {
                    if (!IsUsbBackedDisk(disk, usbPhysicalDrives))
                        continue;

                    foreach (ManagementObject partition in disk.GetRelated("Win32_DiskPartition"))
                    {
                        using (partition)
                        {
                            foreach (ManagementObject logicalDisk in partition.GetRelated("Win32_LogicalDisk"))
                            {
                                using (logicalDisk)
                                {
                                    var deviceId = logicalDisk["DeviceID"]?.ToString();
                                    TryAddDriveRoot(roots, deviceId);
                                }
                            }
                        }
                    }
                }
            }
        }
        catch (ManagementException)
        {
            // DriveInfo fallback still covers standard removable media.
        }

        foreach (var root in GetUsbVolumeRootsFromStorageApi())
            TryAddDriveRoot(roots, root);

        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.DriveType == DriveType.Removable && drive.IsReady)
                TryAddDriveRoot(roots, drive.RootDirectory.FullName);
        }

        return roots.OrderBy(root => root, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public bool IsMountedUsbVolume(string root) =>
        GetMountedUsbVolumes().Contains(NormalizeRoot(root), StringComparer.OrdinalIgnoreCase);

    public bool IsAccessibleDriveRoot(string root) =>
        TryNormalizeDriveRoot(root, out var normalized) && IsUsableDriveRoot(normalized);

    public static string NormalizeRoot(string root)
    {
        var pathRoot = Path.GetPathRoot(root);
        if (string.IsNullOrWhiteSpace(pathRoot) || pathRoot.Length < 2 || pathRoot[1] != ':')
            throw new ArgumentException("A valid drive root is required.", nameof(root));
        return char.ToUpperInvariant(pathRoot[0]) + @":\";
    }

    private static bool IsUsbBackedDisk(ManagementBaseObject disk, IReadOnlySet<string> usbPhysicalDrives)
    {
        var deviceId = disk["DeviceID"]?.ToString();
        var interfaceType = disk["InterfaceType"]?.ToString();
        var pnpDeviceId = disk["PNPDeviceID"]?.ToString() ?? string.Empty;
        return string.Equals(interfaceType, "USB", StringComparison.OrdinalIgnoreCase) ||
               pnpDeviceId.StartsWith("USBSTOR", StringComparison.OrdinalIgnoreCase) ||
               pnpDeviceId.Contains("USB", StringComparison.OrdinalIgnoreCase) ||
               (!string.IsNullOrWhiteSpace(deviceId) && usbPhysicalDrives.Contains(deviceId));
    }

    private static IReadOnlySet<string> GetUsbPhysicalDriveIds()
    {
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"root\Microsoft\Windows\Storage",
                $"SELECT Number, BusType FROM MSFT_Disk WHERE BusType = {UsbBusType}");
            foreach (ManagementObject disk in searcher.Get())
            {
                using (disk)
                {
                    if (uint.TryParse(disk["Number"]?.ToString(), out var number))
                        ids.Add($@"\\.\PHYSICALDRIVE{number}");
                }
            }
        }
        catch (ManagementException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        return ids;
    }

    private static IEnumerable<string> GetUsbVolumeRootsFromStorageApi()
    {
        var roots = new List<string>();
        var diskNumbers = new HashSet<uint>();
        try
        {
            using var diskSearcher = new ManagementObjectSearcher(
                @"root\Microsoft\Windows\Storage",
                $"SELECT Number, BusType FROM MSFT_Disk WHERE BusType = {UsbBusType}");
            foreach (ManagementObject disk in diskSearcher.Get())
            {
                using (disk)
                {
                    if (uint.TryParse(disk["Number"]?.ToString(), out var number))
                        diskNumbers.Add(number);
                }
            }

            if (diskNumbers.Count == 0)
                return roots;

            using var partitionSearcher = new ManagementObjectSearcher(
                @"root\Microsoft\Windows\Storage",
                "SELECT DiskNumber, DriveLetter, AccessPaths FROM MSFT_Partition");
            foreach (ManagementObject partition in partitionSearcher.Get())
            {
                using (partition)
                {
                    if (!uint.TryParse(partition["DiskNumber"]?.ToString(), out var diskNumber) ||
                        !diskNumbers.Contains(diskNumber))
                        continue;

                    var driveLetter = partition["DriveLetter"]?.ToString();
                    if (TryNormalizeDriveRoot(driveLetter, out var root))
                    {
                        roots.Add(root);
                        continue;
                    }

                    if (partition["AccessPaths"] is string[] accessPaths)
                    {
                        foreach (var accessPath in accessPaths)
                        {
                            if (TryNormalizeDriveRoot(accessPath, out root))
                                roots.Add(root);
                        }
                    }
                }
            }
        }
        catch (ManagementException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        return roots;
    }

    private static void TryAddDriveRoot(HashSet<string> roots, string? value)
    {
        if (TryNormalizeDriveRoot(value, out var root) && IsUsableDriveRoot(root))
            roots.Add(root);
    }

    private static bool TryNormalizeDriveRoot(string? value, out string root)
    {
        root = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        var candidate = value.Trim();
        if (candidate.Length >= 2 && char.IsAsciiLetter(candidate[0]) && candidate[1] == ':')
        {
            root = char.ToUpperInvariant(candidate[0]) + @":\";
            return true;
        }

        if (candidate.Length == 1 && char.IsAsciiLetter(candidate[0]))
        {
            root = char.ToUpperInvariant(candidate[0]) + @":\";
            return true;
        }

        return false;
    }

    private static bool IsUsableDriveRoot(string root)
    {
        try
        {
            var drive = new DriveInfo(root);
            if (!drive.IsReady || string.IsNullOrWhiteSpace(drive.DriveFormat))
                return false;
            _ = Directory.EnumerateFileSystemEntries(root).Take(1).ToArray();
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }
}
