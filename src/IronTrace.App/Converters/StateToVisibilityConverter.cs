using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using IronTrace.Contracts.Enums;

namespace IronTrace.App.Converters;

public sealed class StateToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var current = value?.ToString();
        var expected = parameter?.ToString();
        return string.Equals(current, expected, StringComparison.OrdinalIgnoreCase)
            ? Visibility.Visible
            : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var invert = string.Equals(parameter?.ToString(), "invert", StringComparison.OrdinalIgnoreCase);
        var visible = value is not null && (value is not string s || !string.IsNullOrWhiteSpace(s));
        if (invert)
        {
            visible = !visible;
        }

        return visible ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var flag = value is true;
        if (string.Equals(parameter?.ToString(), "invert", StringComparison.OrdinalIgnoreCase))
        {
            flag = !flag;
        }

        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class SeverityBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var sev = value switch
        {
            FindingSeverity fs => fs,
            string s when Enum.TryParse<FindingSeverity>(s, true, out var parsed) => parsed,
            _ => FindingSeverity.Information
        };

        return sev switch
        {
            FindingSeverity.Critical => Brush("#C45C5C"),
            FindingSeverity.High => Brush("#D17A4A"),
            FindingSeverity.Medium => Brush("#C4A35A"),
            FindingSeverity.Low => Brush("#6B8CAE"),
            _ => Brush("#5A6A78")
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();

    private static SolidColorBrush Brush(string hex)
    {
        var b = (SolidColorBrush)new BrushConverter().ConvertFrom(hex)!;
        b.Freeze();
        return b;
    }
}

public sealed class SignatureBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var status = value switch
        {
            DriverSignatureStatus ds => ds,
            string s when Enum.TryParse<DriverSignatureStatus>(s, true, out var parsed) => parsed,
            _ => DriverSignatureStatus.Unknown
        };

        return status switch
        {
            DriverSignatureStatus.MicrosoftSigned => Brush("#6FBF8B"),
            DriverSignatureStatus.AuthenticodeSigned => Brush("#3D8B7A"),
            DriverSignatureStatus.CatalogSigned => Brush("#3D8B7A"),
            DriverSignatureStatus.Unsigned => Brush("#C4A35A"),
            DriverSignatureStatus.Expired => Brush("#D17A4A"),
            DriverSignatureStatus.Untrusted => Brush("#D17A4A"),
            DriverSignatureStatus.Error => Brush("#C45C5C"),
            _ => Brush("#5A6A78")
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();

    private static SolidColorBrush Brush(string hex)
    {
        var b = (SolidColorBrush)new BrushConverter().ConvertFrom(hex)!;
        b.Freeze();
        return b;
    }
}

public sealed class CountToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var count = value is int i ? i : 0;
        var invert = string.Equals(parameter?.ToString(), "invert", StringComparison.OrdinalIgnoreCase);
        var visible = count > 0;
        if (invert)
        {
            visible = !visible;
        }

        return visible ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
