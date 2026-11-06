using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace FreedomInstaller.Mac;

/// <summary>
/// The window's own message box (Avalonia has none): a card with the same palette and buttons as the pages,
/// standing in for the WPF MessageBox calls. Returns true only for an explicit Yes / OK.
/// </summary>
internal sealed class MessageDialog : Window
{
    private MessageDialog(string title, string body, string primary, string? secondary)
    {
        Title = title;
        Width = 520;
        SizeToContent = SizeToContent.Height;
        CanResize = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        this[!BackgroundProperty] = this.GetResourceObservable("CanvasBrush").ToBinding();

        var heading = new TextBlock { Text = title, Classes = { "H2Text" } };
        var text = new TextBlock { Text = body, Classes = { "BodyInkText" }, Margin = new Thickness(0, 10, 0, 0) };
        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 18, 0, 0),
        };

        if (secondary is not null)
        {
            var no = new Button { Content = secondary, IsDefault = false, IsCancel = true };
            no.Theme = (Avalonia.Styling.ControlTheme?)Application.Current!.FindResource("SecondaryButton");
            no.Click += (_, _) => Close(false);
            buttons.Children.Add(no);
        }

        var yes = new Button { Content = primary, Margin = new Thickness(10, 0, 0, 0) };
        yes.Theme = (Avalonia.Styling.ControlTheme?)Application.Current!.FindResource("PrimaryButton");
        yes.Click += (_, _) => Close(true);
        buttons.Children.Add(yes);

        var card = new Border { Classes = { "CardBorder" }, Margin = new Thickness(16), Child = new StackPanel { Children = { heading, text, buttons } } };
        Content = card;
    }

    internal static Task<bool> AskAsync(Window owner, string title, string body, string yes, string no) =>
        new MessageDialog(title, body, yes, no).ShowDialog<bool>(owner);

    internal static Task<bool> ShowAsync(Window owner, string title, string body, string ok) =>
        new MessageDialog(title, body, ok, null).ShowDialog<bool>(owner);
}
