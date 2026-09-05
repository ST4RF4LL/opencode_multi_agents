using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;

// Offline, memory-only control fixture. This is not a vulnerable application.
internal static class Program
{
    [STAThread]
    private static void Main()
    {
        var app = new Application();
        var window = new Window { Title = "winappCli 本机控制测试", Width = 520, Height = 260 };
        var panel = new StackPanel { Margin = new Thickness(24) };
        var input = new TextBox { Margin = new Thickness(0, 8, 0, 8), MaxLength = 100 };
        var status = new TextBlock { Text = "等待测试 marker", Margin = new Thickness(0, 12, 0, 12) };
        var submit = new Button { Content = "提交测试 marker", Margin = new Thickness(0, 0, 0, 8) };
        var clear = new Button { Content = "清理本次测试数据" };
        AutomationProperties.SetAutomationId(input, "MarkerInput");
        AutomationProperties.SetAutomationId(status, "MarkerStatus");
        AutomationProperties.SetAutomationId(submit, "SubmitMarker");
        AutomationProperties.SetAutomationId(clear, "ClearMarker");
        submit.Click += (_, _) => status.Text = input.Text.StartsWith("audit-winapp-", StringComparison.Ordinal)
            ? input.Text : "请输入有效的测试 marker";
        clear.Click += (_, _) => { input.Clear(); status.Text = "已清理"; };
        panel.Children.Add(new TextBlock { Text = "仅在内存中保存测试字符串，不访问文件或网络。" });
        panel.Children.Add(input);
        panel.Children.Add(submit);
        panel.Children.Add(status);
        panel.Children.Add(clear);
        window.Content = panel;
        app.Run(window);
    }
}
