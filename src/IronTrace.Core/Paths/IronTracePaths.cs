namespace IronTrace.Core.Paths;

public static class IronTracePaths
{
    public static string Root =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "IronTrace");

    public static string Logs => Path.Combine(Root, "logs");

    public static string Reference => Path.Combine(Root, "reference");

    public static string Keys => Path.Combine(Root, "keys");

    public static void EnsureCreated()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(Logs);
        Directory.CreateDirectory(Reference);
        Directory.CreateDirectory(Keys);
    }
}
