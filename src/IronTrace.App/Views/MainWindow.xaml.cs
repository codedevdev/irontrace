using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using IronTrace.App.ViewModels;

namespace IronTrace.App.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    private MainViewModel? Vm => DataContext as MainViewModel;

    private void DevicePreview_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is ListBoxItem { DataContext: DeviceListItem item })
        {
            Vm?.SelectDeviceCommand.Execute(item);
        }
    }

    private void DeviceList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is ListBox { SelectedItem: DeviceListItem item })
        {
            Vm?.SelectDeviceCommand.Execute(item);
        }
    }

    private void FindingList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is ListBox { SelectedItem: FindingListItem item })
        {
            Vm?.OpenFindingDeviceCommand.Execute(item);
        }
    }
}
