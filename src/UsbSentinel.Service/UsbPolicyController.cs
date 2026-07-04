using Microsoft.Win32;

namespace UsbSentinel.Service;

public sealed class UsbPolicyController
{
    private const string UsbStorPath = @"SYSTEM\CurrentControlSet\Services\USBSTOR";
    private const string RemovableStoragePath =
        @"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices";

    public bool IsStorageBlocked()
    {
        using var key = Registry.LocalMachine.OpenSubKey(RemovableStoragePath);
        return Convert.ToInt32(key?.GetValue("Deny_All", 0)) == 1;
    }

    public void BlockStorage()
    {
        // Keep the driver available so Windows can identify hardware while policy denies access.
        SetDword(UsbStorPath, "Start", 3);
        SetDword(RemovableStoragePath, "Deny_All", 1);
        BroadcastPolicyChange();
        RescanDevices();
    }

    public void AllowStorageForScan()
    {
        SetDword(UsbStorPath, "Start", 3);
        SetDword(RemovableStoragePath, "Deny_All", 0);
        BroadcastPolicyChange();
        RescanDevices();
    }

    public void SetBlockAllUsb(bool enabled)
    {
        // Installation restrictions affect newly installed USB devices. Existing HID devices
        // remain usable, avoiding accidental keyboard/mouse lockout.
        const string restrictions = @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
        SetDword(restrictions, "DenyUnspecified", enabled ? 1 : 0);
        SetDword(restrictions, "DenyDeviceIDsRetroactive", 0);
        BroadcastPolicyChange();
    }

    private static void SetDword(string path, string name, int value)
    {
        using var key = Registry.LocalMachine.CreateSubKey(path, writable: true)
            ?? throw new InvalidOperationException($"Unable to open HKLM\\{path}.");
        key.SetValue(name, value, RegistryValueKind.DWord);
    }

    private static void BroadcastPolicyChange()
    {
        _ = NativeMethods.SendMessageTimeout(
            new IntPtr(0xffff), 0x001A, IntPtr.Zero, "Policy",
            0x0002, 5000, out _);
    }

    private static void RescanDevices()
    {
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = Path.Combine(Environment.SystemDirectory, "pnputil.exe"),
            Arguments = "/scan-devices",
            UseShellExecute = false,
            CreateNoWindow = true
        };
        using var process = System.Diagnostics.Process.Start(psi);
        process?.WaitForExit(15000);
    }

    private static class NativeMethods
    {
        [System.Runtime.InteropServices.DllImport(
            "user32.dll",
            CharSet = System.Runtime.InteropServices.CharSet.Unicode,
            SetLastError = true)]
        internal static extern IntPtr SendMessageTimeout(
            IntPtr hWnd, uint msg, IntPtr wParam, string lParam,
            uint flags, uint timeout, out IntPtr result);
    }
}
