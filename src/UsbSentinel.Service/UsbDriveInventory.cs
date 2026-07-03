using System.Management;

namespace UsbSentinel.Service;

public sealed class UsbDriveInventory
{
    public IReadOnlyList<string> GetMountedUsbVolumes()
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT DeviceID, InterfaceType, PNPDeviceID FROM Win32_DiskDrive");
            foreach (ManagementObject disk in searcher.Get())
            {
                using (disk)
                {
                    var interfaceType = disk["InterfaceType"]?.ToString();
                    var pnpDeviceId = disk["PNPDeviceID"]?.ToString();
                    if (!string.Equals(interfaceType, "USB", StringComparison.OrdinalIgnoreCase) &&
                        !(pnpDeviceId?.StartsWith("USBSTOR", StringComparison.OrdinalIgnoreCase) ?? false))
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
                                    if (!string.IsNullOrWhiteSpace(deviceId))
                                        roots.Add(Path.GetPathRoot(deviceId + "\\") ?? deviceId + "\\");
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

        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.DriveType == DriveType.Removable && drive.IsReady)
                roots.Add(drive.RootDirectory.FullName);
        }

        return roots.OrderBy(root => root, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public bool IsMountedUsbVolume(string root) =>
        GetMountedUsbVolumes().Contains(NormalizeRoot(root), StringComparer.OrdinalIgnoreCase);

    public static string NormalizeRoot(string root)
    {
        var pathRoot = Path.GetPathRoot(root);
        if (string.IsNullOrWhiteSpace(pathRoot) || pathRoot.Length < 2 || pathRoot[1] != ':')
            throw new ArgumentException("A valid drive root is required.", nameof(root));
        return char.ToUpperInvariant(pathRoot[0]) + @":\";
    }
}
