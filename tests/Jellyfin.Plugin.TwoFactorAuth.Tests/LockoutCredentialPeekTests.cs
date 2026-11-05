using System.Text;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class LockoutCredentialPeekTests
{
    [Theory]
    [InlineData("Pw")]
    [InlineData("PW")]
    [InlineData("pw")]
    [InlineData("Password")]
    [InlineData("password")]
    public async Task PeekCredentials_AcceptsKnownPasswordFieldCasings(string field)
    {
        var context = new DefaultHttpContext();
        var bytes = Encoding.UTF8.GetBytes($"{{\"Username\":\"alice\",\"{field}\":\"secret\"}}");
        context.Request.Method = HttpMethods.Post;
        context.Request.Body = new MemoryStream(bytes);
        context.Request.ContentLength = bytes.Length;

        var (username, password) = await LockoutMessageMiddleware.PeekCredentialsAsync(context.Request);

        Assert.Equal("alice", username);
        Assert.Equal("secret", password);
    }
}
