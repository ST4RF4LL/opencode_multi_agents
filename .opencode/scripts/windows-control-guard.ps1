param(
    [ValidateSet('Paths', 'Target')][string]$Mode,
    [uint32]$TargetPid,
    [string]$WindowHandle,
    [string]$StartTimeTicks,
    [int]$SessionId,
    [string]$ExePath,
    [string]$ToolPath,
    [string]$AutomationId
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class WinappControlGuard {
    [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll")] public static extern bool CloseDesktop(IntPtr desktop);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool GetUserObjectInformation(IntPtr handle, int index, StringBuilder text, int bytes, out uint needed);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern uint GetDriveType(string root);
}
'@
    if ($Mode -eq 'Paths') {
        foreach ($candidate in @($ExePath, $ToolPath)) {
            if ($candidate -notmatch '^[A-Za-z]:\\' -or [WinappControlGuard]::GetDriveType([IO.Path]::GetPathRoot($candidate)) -ne 3) { throw 'drive' }
            $part = Get-Item -LiteralPath $candidate
            while ($null -ne $part) {
                if (($part.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse' }
                if ($part -is [IO.FileInfo]) { $part = $part.Directory } else { $part = $part.Parent }
            }
        }
        @{ local_fixed_drives = $true } | ConvertTo-Json -Compress
        exit 0
    }
    if ($Mode -ne 'Target') { throw 'mode' }
    $targetProcess = Get-Process -Id $TargetPid
    $controllerProcess = [Diagnostics.Process]::GetCurrentProcess()
    if ($SessionId -le 0 -or $targetProcess.SessionId -ne $SessionId -or $controllerProcess.SessionId -ne $SessionId) { throw 'session' }
    if ($targetProcess.StartTime.ToUniversalTime().Ticks.ToString() -cne $StartTimeTicks) { throw 'pid-reuse' }
    if (-not [string]::Equals($targetProcess.MainModule.FileName, $ExePath, [StringComparison]::OrdinalIgnoreCase)) { throw 'exe' }
    $targetHwnd = [IntPtr]([long]::Parse($WindowHandle))
    [uint32]$windowOwnerPid = 0
    if (-not [WinappControlGuard]::IsWindow($targetHwnd)) { throw 'window' }
    $null = [WinappControlGuard]::GetWindowThreadProcessId($targetHwnd, [ref]$windowOwnerPid)
    if ($windowOwnerPid -ne $TargetPid) { throw 'owner' }
    $desktopHandle = [WinappControlGuard]::OpenInputDesktop(0, $false, 1)
    if ($desktopHandle -eq [IntPtr]::Zero) { throw 'desktop' }
    try {
        $desktopName = [System.Text.StringBuilder]::new(256)
        [uint32]$needed = 0
        if (-not [WinappControlGuard]::GetUserObjectInformation($desktopHandle, 2, $desktopName, 512, [ref]$needed) -or $desktopName.ToString() -cne 'Default') { throw 'secure-desktop' }
    } finally { $null = [WinappControlGuard]::CloseDesktop($desktopHandle) }
    $result = @{ valid = $true }
    if ($AutomationId) {
        Add-Type -AssemblyName UIAutomationClient
        Add-Type -AssemblyName UIAutomationTypes
        $window = [System.Windows.Automation.AutomationElement]::FromHandle($targetHwnd)
        $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $AutomationId)
        $controlMatches = $window.FindAll([System.Windows.Automation.TreeScope]::Subtree, $condition)
        if ($controlMatches.Count -ne 1) { throw 'ambiguous-control' }
        $element = $controlMatches.Item(0)
        if ($element.Current.ProcessId -ne $TargetPid) { throw 'foreign-control' }
        $passwordCondition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::IsPasswordProperty, $true)
        $child = $element.FindFirst([System.Windows.Automation.TreeScope]::Children, [System.Windows.Automation.Condition]::TrueCondition)
        $password = $element.FindFirst([System.Windows.Automation.TreeScope]::Subtree, $passwordCondition)
        $result.runtime_id = ($element.GetRuntimeId() -join '.')
        $result.is_password = $element.Current.IsPassword
        $result.subtree_has_password = ($null -ne $password)
        $result.enabled = $element.Current.IsEnabled
        $result.is_leaf = ($null -eq $child)
        $result.can_invoke = $element.GetCurrentPropertyValue([System.Windows.Automation.AutomationElement]::IsInvokePatternAvailableProperty)
        $result.can_set_value = $element.GetCurrentPropertyValue([System.Windows.Automation.AutomationElement]::IsValuePatternAvailableProperty)
    }
    $result | ConvertTo-Json -Compress
} catch {
    # Never serialize process paths, control values or exception text.
    [Console]::Out.WriteLine('{"error":"WINDOWS_TARGET_GUARD_FAILED"}')
    exit 1
}
