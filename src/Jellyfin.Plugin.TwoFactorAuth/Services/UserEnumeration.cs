using System;
using System.Collections;
using System.Collections.Generic;
using Jellyfin.Database.Implementations.Entities;
using MediaBrowser.Controller.Library;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Every Jellyfin account, on any supported host. Moved out of
/// TwoFactorAuthController so the uninstall restore (#213) uses the same shim.
/// </summary>
public static class UserEnumeration
{
    /// <summary>
    /// Reflection-based to dodge Jellyfin 10.11.9's IUserManager.Users
    /// return-type ABI break (issue #27): an IL call site compiled against
    /// 10.11.8 throws MissingMethodException on a 10.11.9 host, and reflection
    /// re-binds at runtime against either ABI. Jellyfin 10.11.10 then renamed
    /// the Users property to a GetUsers() method, so the method is tried first
    /// and the old property is the fallback for older 10.11.x hosts;
    /// nameof(IUserManager.Users) fails to compile against 10.11.10. Empty on
    /// any failure, so callers degrade gracefully.
    /// </summary>
    public static IEnumerable<User> All(IUserManager userManager)
    {
        IEnumerable? raw = null;
        try
        {
            var getUsersMethod = typeof(IUserManager).GetMethod("GetUsers", Type.EmptyTypes);
            if (getUsersMethod is not null)
            {
                raw = getUsersMethod.Invoke(userManager, null) as IEnumerable;
            }
            else
            {
                var prop = typeof(IUserManager).GetProperty("Users");
                raw = prop?.GetValue(userManager) as IEnumerable;
            }
        }
        catch (Exception)
        {
            yield break;
        }
        if (raw is null) yield break;
        foreach (var item in raw)
        {
            if (item is User u) yield return u;
        }
    }
}
