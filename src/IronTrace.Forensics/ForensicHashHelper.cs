using System.Security.Cryptography;
using System.Text;

namespace IronTrace.Forensics;

internal static class ForensicHashHelper
{
    public static string HashText(string? text)
    {
        if (string.IsNullOrEmpty(text))
            return "";
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(text));
        return Convert.ToHexString(bytes).ToLowerInvariant()[..16];
    }

    public static string TruncatePath(string? path, int maxLen = 120)
    {
        if (string.IsNullOrEmpty(path))
            return "";
        return path.Length <= maxLen ? path : "..." + path[^Math.Min(maxLen - 3, path.Length)..];
    }
}
