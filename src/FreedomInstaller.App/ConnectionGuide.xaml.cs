using System;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;

namespace FreedomInstaller.App;

/// <summary>
/// 连接图示：三张原创矢量图讲解「开发者选项 → USB 调试 → 连接授权」。
/// <para>
/// 说明：
/// 1. 这里画的都是界面示意，不是平板真实截图，也不对应任何具体型号的系统界面；
///    因此不写任何设备型号、Android 版本或 build 号，数值一律用「—」。
/// 2. 本控件自成一页：<see cref="_guideStep"/>（0..2）只在图 1/2/3 之间切换，
///    与主流程页码完全无关，也不会自动翻页；切图不触碰设备、进程或网络。
/// 3. 动画都是 3 秒左右的非循环 Storyboard，只作用于本地元素的 Opacity / TranslateTransform.X /
///    ScaleTransform，结束后保持「最终高亮姿态」（XAML 里的基础值就是最终姿态）。
///    系统关闭客户端动画时不做动画，直接显示同一静态姿态。
/// 4. 时钟一律以可控方式挂在本控件上，切图、控件隐藏、卸载前先 Remove，避免留下永久运行的隐藏动画。
/// </para>
/// </summary>
public partial class ConnectionGuide : UserControl
{
    private const int StepCount = 3;

    /// <summary>图 1 点击环脉冲次数：中文/英文都写「连续点 7 次」，图上也要能数出来。</summary>
    private const int SevenPulses = 7;

    /// <summary>单次脉冲的一半时长（往返合计约 0.48 秒），7 次约 3.4 秒。</summary>
    private static readonly TimeSpan PulseHalfDuration = TimeSpan.FromMilliseconds(240);

    private int _guideStep;

    private Storyboard? _sceneStoryboard;

    public ConnectionGuide()
    {
        InitializeComponent();

        Loaded += OnGuideLoaded;
        Unloaded += OnGuideUnloaded;
        IsVisibleChanged += OnGuideIsVisibleChanged;

        // 构造时只摆静态姿态（1 / 3，图 1 的最终高亮），动画等真正可见后再启动。
        ApplyStep(0, animate: false);
    }

    /// <summary>当前图示步骤（0..2），只影响本控件，不牵动主流程。</summary>
    private int GuideStep => _guideStep;

    private void OnGuideLoaded(object sender, RoutedEventArgs e)
    {
        if (IsVisible)
        {
            StartSceneStoryboard();
        }
    }

    private void OnGuideUnloaded(object sender, RoutedEventArgs e)
    {
        // 离开连接页 / 父容器被移除：移除时钟，静态姿态保留。
        StopSceneStoryboard();
    }

    private void OnGuideIsVisibleChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        // 折叠（例如收起「连接准备」面板）时停掉，展开时重新播放当前图。
        if (e.NewValue is true)
        {
            StartSceneStoryboard();
        }
        else
        {
            StopSceneStoryboard();
        }
    }

    private void OnDeveloperChipClick(object sender, RoutedEventArgs e) => SwitchToStep(0);

    private void OnUsbDebugChipClick(object sender, RoutedEventArgs e) => SwitchToStep(1);

    private void OnAuthorizeChipClick(object sender, RoutedEventArgs e) => SwitchToStep(2);

    private void OnPreviousPictureClick(object sender, RoutedEventArgs e) => SwitchToStep(GuideStep - 1);

    private void OnNextPictureClick(object sender, RoutedEventArgs e) => SwitchToStep(GuideStep + 1);

    private void OnReplayClick(object sender, RoutedEventArgs e)
    {
        // 重播只重放当前这张图：页码、选中步骤、应用与设备状态都不变。
        StopSceneStoryboard();
        StartSceneStoryboard();
    }

    private void SwitchToStep(int step)
    {
        if (step == _guideStep)
        {
            // 点当前步骤：只把胶囊勾选状态复原，画面保持静止（重播请用「重播」）。
            ApplyStep(step, animate: false);
            return;
        }

        ApplyStep(step, animate: true);
    }

    private void ApplyStep(int step, bool animate)
    {
        _guideStep = Math.Clamp(step, 0, StepCount - 1);

        // 先撤掉上一步的时钟，再切可见性：不留跨页运行的动画。
        StopSceneStoryboard();

        Scene1.Visibility = _guideStep == 0 ? Visibility.Visible : Visibility.Collapsed;
        Scene2.Visibility = _guideStep == 1 ? Visibility.Visible : Visibility.Collapsed;
        Scene3.Visibility = _guideStep == 2 ? Visibility.Visible : Visibility.Collapsed;

        GuideCaption1.Visibility = _guideStep == 0 ? Visibility.Visible : Visibility.Collapsed;
        GuideCaption2.Visibility = _guideStep == 1 ? Visibility.Visible : Visibility.Collapsed;
        GuideCaption3.Visibility = _guideStep == 2 ? Visibility.Visible : Visibility.Collapsed;

        DeveloperChip.IsChecked = _guideStep == 0;
        UsbDebugChip.IsChecked = _guideStep == 1;
        AuthorizeChip.IsChecked = _guideStep == 2;

        GuideCounter.Text = string.Format(
            CultureInfo.InvariantCulture,
            "{0} / {1}",
            _guideStep + 1,
            StepCount);

        PreviousPictureButton.IsEnabled = _guideStep > 0;
        NextPictureButton.IsEnabled = _guideStep < StepCount - 1;

        if (animate)
        {
            StartSceneStoryboard();
        }
    }

    private void StartSceneStoryboard()
    {
        StopSceneStoryboard();

        // 未加载 / 不可见（父面板收起）或系统关闭了动画：停在 XAML 里的最终静态姿态即可。
        if (!IsLoaded || !IsVisible || !SystemParameters.ClientAreaAnimation)
        {
            return;
        }

        var storyboard = CreateSceneStoryboard(_guideStep);
        if (storyboard is null)
        {
            return;
        }

        _sceneStoryboard = storyboard;

        // Timeline.Completed 的 sender 是 Clock，不是 Storyboard，所以这里用局部变量捕获本次实例，
        // 回调里忽略 sender，只处理当前这次 storyboard，避免旧动画的回调推翻新状态。
        // 有限动画播完就撤时钟：Storyboard.Remove 把各元素还回 XAML 基础值
        // （图 2 开关停在「开」、最终高亮不透明度与比例），留下静态高亮姿态；不用计时器、不循环。
        storyboard.Completed += (_, _) =>
        {
            if (ReferenceEquals(_sceneStoryboard, storyboard))
            {
                StopSceneStoryboard();
            }
        };

        storyboard.Begin(this, true);
    }

    private void StopSceneStoryboard()
    {
        var storyboard = _sceneStoryboard;
        if (storyboard is null)
        {
            return;
        }

        _sceneStoryboard = null;

        // 与 Begin(this, true) 成对：移除时钟后各元素回到基础值（即最终高亮姿态）。
        storyboard.Remove(this);
    }

    private Storyboard? CreateSceneStoryboard(int step) => step switch
    {
        0 => CreateStepOneStoryboard(),
        1 => CreateStepTwoStoryboard(),
        2 => CreateStepThreeStoryboard(),
        _ => null,
    };

    /// <summary>图 1：点击环与 ×7 徽标同步脉冲 7 次，强调「连点 7 次」。</summary>
    private Storyboard CreateStepOneStoryboard()
    {
        var storyboard = new Storyboard();

        var ringFade = new DoubleAnimation
        {
            From = 0.22,
            To = 0.95,
            Duration = PulseHalfDuration,
            AutoReverse = true,
            RepeatBehavior = new RepeatBehavior(SevenPulses),
            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut },
        };
        Storyboard.SetTarget(ringFade, Scene1TapRing);
        Storyboard.SetTargetProperty(ringFade, new PropertyPath(UIElement.OpacityProperty));
        storyboard.Children.Add(ringFade);

        var ringSwellX = new DoubleAnimation
        {
            From = 0.86,
            To = 1,
            Duration = PulseHalfDuration,
            AutoReverse = true,
            RepeatBehavior = new RepeatBehavior(SevenPulses),
            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut },
        };
        Storyboard.SetTarget(ringSwellX, Scene1TapRingScale);
        Storyboard.SetTargetProperty(ringSwellX, new PropertyPath(ScaleTransform.ScaleXProperty));
        storyboard.Children.Add(ringSwellX);

        var ringSwellY = new DoubleAnimation
        {
            From = 0.86,
            To = 1,
            Duration = PulseHalfDuration,
            AutoReverse = true,
            RepeatBehavior = new RepeatBehavior(SevenPulses),
            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut },
        };
        Storyboard.SetTarget(ringSwellY, Scene1TapRingScale);
        Storyboard.SetTargetProperty(ringSwellY, new PropertyPath(ScaleTransform.ScaleYProperty));
        storyboard.Children.Add(ringSwellY);

        return storyboard;
    }

    /// <summary>图 2：开关从「关」滑到「开」一次，随后点击环脉冲 3 次。</summary>
    private Storyboard CreateStepTwoStoryboard()
    {
        var storyboard = new Storyboard();

        var knobSlide = new DoubleAnimationUsingKeyFrames
        {
            Duration = TimeSpan.FromSeconds(1.5),
        };
        knobSlide.KeyFrames.Add(new LinearDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.Zero)));
        knobSlide.KeyFrames.Add(new LinearDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(0.35))));
        knobSlide.KeyFrames.Add(new EasingDoubleKeyFrame(
            20,
            KeyTime.FromTimeSpan(TimeSpan.FromSeconds(1.25)),
            new QuadraticEase { EasingMode = EasingMode.EaseInOut }));
        knobSlide.KeyFrames.Add(new LinearDoubleKeyFrame(20, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(1.5))));
        Storyboard.SetTarget(knobSlide, Scene2KnobShift);
        Storyboard.SetTargetProperty(knobSlide, new PropertyPath(TranslateTransform.XProperty));
        storyboard.Children.Add(knobSlide);

        var trackOn = new DoubleAnimationUsingKeyFrames
        {
            Duration = TimeSpan.FromSeconds(1.5),
        };
        trackOn.KeyFrames.Add(new LinearDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.Zero)));
        trackOn.KeyFrames.Add(new LinearDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(1.05))));
        trackOn.KeyFrames.Add(new EasingDoubleKeyFrame(1, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(1.4))));
        trackOn.KeyFrames.Add(new LinearDoubleKeyFrame(1, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(1.5))));
        Storyboard.SetTarget(trackOn, Scene2SwitchOn);
        Storyboard.SetTargetProperty(trackOn, new PropertyPath(UIElement.OpacityProperty));
        storyboard.Children.Add(trackOn);

        var cuePulse = new DoubleAnimation
        {
            From = 0.22,
            To = 0.95,
            Duration = PulseHalfDuration,
            AutoReverse = true,
            RepeatBehavior = new RepeatBehavior(3),
            BeginTime = TimeSpan.FromSeconds(1.5),
        };
        Storyboard.SetTarget(cuePulse, Scene2TapCue);
        Storyboard.SetTargetProperty(cuePulse, new PropertyPath(UIElement.OpacityProperty));
        storyboard.Children.Add(cuePulse);

        return storyboard;
    }

    /// <summary>图 3：连接后弹窗里的「允许」被点击环脉冲 3 次。</summary>
    private Storyboard CreateStepThreeStoryboard()
    {
        var storyboard = new Storyboard();

        var cuePulse = new DoubleAnimation
        {
            From = 0.25,
            To = 0.95,
            Duration = PulseHalfDuration,
            AutoReverse = true,
            RepeatBehavior = new RepeatBehavior(3),
            BeginTime = TimeSpan.FromSeconds(0.15),
        };
        Storyboard.SetTarget(cuePulse, Scene3TapCue);
        Storyboard.SetTargetProperty(cuePulse, new PropertyPath(UIElement.OpacityProperty));
        storyboard.Children.Add(cuePulse);

        return storyboard;
    }
}
