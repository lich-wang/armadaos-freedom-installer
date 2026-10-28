using System.Windows;

namespace FreedomInstaller.App;

/// <summary>
/// 「支持项目」独立视图：顶栏按钮打开，页内「← 返回」关闭。
/// <para>
/// 这里只持有一个状态 <see cref="_showingSupport"/>；打开与关闭都只调用
/// <see cref="ApplyFunctionView"/>，可见性仍然只有那一个出口。
/// 因此支持页不发起查询、不切步骤、不改写安装模式、不清空输入，也不发送任何设备命令：
/// 返回后仍然停在打开前的首页或向导（步骤、路径、勾选、计划与日志原样保留）。
/// </para>
/// <para>
/// 页面文字与主题全部用 DynamicResource 绑定，切换语言或明暗主题时立即跟随，
/// 支持页打开期间也照常可用；这里不抢焦点、不弹对话框。
/// </para>
/// </summary>
public partial class MainWindow
{
    /// <summary>true 表示当前正停在支持页；与 <c>_showingHome</c> 相互独立。</summary>
    private bool _showingSupport;

    /// <summary>顶栏「支持项目」：只切视图，忙时忽略。</summary>
    private void OnShowSupport(object sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            return;
        }

        _showingSupport = true;
        ApplyFunctionView();
    }

    /// <summary>页内「← 返回」：回到打开前的首页或向导，忙时忽略。</summary>
    private void OnCloseSupport(object sender, RoutedEventArgs e)
    {
        if (_busy)
        {
            return;
        }

        _showingSupport = false;
        ApplyFunctionView();
    }
}
