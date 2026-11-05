using System.Text.Json;
using Jellyfin.Data;
using Jellyfin.Data.Events.Users;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Database.Implementations.Enums;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Events;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class CredentialChangeLockoutTests
{
    [Fact]
    public void The_registrator_resolves_the_completed_change_consumer()
    {
        using var fixture = new Fixture();

        Assert.Single(fixture.Services.GetServices<IEventConsumer<UserPasswordChangedEventArgs>>());
    }

    [Fact]
    public async Task A_completed_change_clears_only_the_users_temporary_lockout_and_persists_it()
    {
        using var fixture = new Fixture();
        var user = new User("locked", "provider", "reset") { InvalidLoginAttemptCount = 7 };
        user.SetPermission(PermissionKind.IsDisabled, true);
        var data = Locked(user.Id);
        data.TotpEnabled = true;
        data.TotpVerified = true;
        data.EncryptedTotpSecret = "existing-ciphertext";
        data.ForceRecoveryOnNextLogin = true;
        data.RecoveryCodes.Add(new RecoveryCode { Hash = "existing-recovery-hash" });
        data.Passkeys.Add(new PasskeyCredential { CredentialId = "existing-credential" });
        data.TrustedDevices.Add(new TrustedDevice { TokenHash = "existing-device-hash" });
        data.IpAllowlistCidrs.Add("192.0.2.0/24");
        var other = Locked(Guid.NewGuid());
        await fixture.Store.SaveUserDataAsync(data);
        await fixture.Store.SaveUserDataAsync(other);
        Assert.True(await fixture.Store.IsLockedOutAsync(user.Id));
        var otherBefore = await File.ReadAllTextAsync(fixture.RecordPath(other.UserId));

        await fixture.Consumer.OnEvent(new UserPasswordChangedEventArgs(user));

        Assert.False(await fixture.Store.IsLockedOutAsync(user.Id));
        data.FailedAttemptCount = 0;
        data.LockoutEnd = null;
        Assert.Equal(JsonSerializer.Serialize(data), JsonSerializer.Serialize(await fixture.Store.GetUserDataAsync(user.Id)));
        using var reloaded = new UserTwoFactorStore(fixture.Paths, fixture.Services);
        Assert.Equal(JsonSerializer.Serialize(data), JsonSerializer.Serialize(await reloaded.GetUserDataAsync(user.Id)));
        Assert.True(await fixture.Store.IsLockedOutAsync(other.UserId));
        Assert.Equal(otherBefore, await File.ReadAllTextAsync(fixture.RecordPath(other.UserId)));
        Assert.Equal(7, user.InvalidLoginAttemptCount);
        Assert.True(user.HasPermission(PermissionKind.IsDisabled));
    }

    [Theory]
    [InlineData(3, false)]
    [InlineData(0, true)]
    public async Task A_completed_change_clears_partial_counts_and_expired_lockouts(int count, bool expired)
    {
        using var fixture = new Fixture();
        var user = new User("changed", "provider", "reset");
        var data = new UserTwoFactorData
        {
            UserId = user.Id,
            FailedAttemptCount = count,
            LockoutEnd = expired ? DateTime.UtcNow.AddMinutes(-1) : null,
        };
        await fixture.Store.SaveUserDataAsync(data);

        await fixture.Consumer.OnEvent(new UserPasswordChangedEventArgs(user));

        var actual = await fixture.Store.GetUserDataAsync(user.Id);
        Assert.Equal(0, actual.FailedAttemptCount);
        Assert.Null(actual.LockoutEnd);
    }

    [Fact]
    public async Task An_unknown_user_does_not_create_a_record_or_change_another_lockout()
    {
        using var fixture = new Fixture();
        var other = Locked(Guid.NewGuid());
        await fixture.Store.SaveUserDataAsync(other);
        var before = await File.ReadAllTextAsync(fixture.RecordPath(other.UserId));
        var unknown = new User("unknown", "provider", "reset");

        await fixture.Consumer.OnEvent(new UserPasswordChangedEventArgs(unknown));

        Assert.False(File.Exists(fixture.RecordPath(unknown.Id)));
        Assert.Equal(before, await File.ReadAllTextAsync(fixture.RecordPath(other.UserId)));
        Assert.Single(Directory.GetFiles(Path.GetDirectoryName(fixture.RecordPath(other.UserId))!));
    }

    [Fact]
    public async Task A_store_failure_is_logged_without_propagating_or_logging_event_data()
    {
        using var fixture = new Fixture();
        var user = new User("sensitive-identity", "provider", "reset");
        await fixture.Store.SaveUserDataAsync(Locked(user.Id));
        File.Delete(fixture.RecordPath(user.Id));
        Directory.CreateDirectory(fixture.RecordPath(user.Id));

        await fixture.Consumer.OnEvent(new UserPasswordChangedEventArgs(user));

        var entry = Assert.Single(fixture.Log.Entries);
        Assert.Equal(LogLevel.Error, entry.Level);
        Assert.Equal("[2FA] Could not clear temporary sign-in lockout after a completed credential change.", entry.Message);
        Assert.Null(entry.Error);
    }

    private static UserTwoFactorData Locked(Guid id) => new()
    {
        UserId = id,
        FailedAttemptCount = 5,
        LockoutEnd = DateTime.UtcNow.AddMinutes(15),
    };

    private sealed class Fixture : IDisposable
    {
        private readonly string _root;

        public Fixture()
        {
            Paths = TestApplicationPaths.Create(out _root);
            var services = new ServiceCollection();
            services.AddSingleton(Paths);
            services.AddLogging(builder => builder.AddProvider(Log));
            new PluginServiceRegistrator().RegisterServices(services, Substitute.For<IServerApplicationHost>());
            Services = services.BuildServiceProvider();
        }

        public MediaBrowser.Common.Configuration.IApplicationPaths Paths { get; }
        public ServiceProvider Services { get; }
        public RecordingLog Log { get; } = new();
        public UserTwoFactorStore Store => Services.GetRequiredService<UserTwoFactorStore>();
        public IEventConsumer<UserPasswordChangedEventArgs> Consumer =>
            Assert.Single(Services.GetServices<IEventConsumer<UserPasswordChangedEventArgs>>());

        public string RecordPath(Guid id) => Path.Combine(Paths.PluginConfigurationsPath, "TwoFactorAuth", "users", $"{id}.json");

        public void Dispose()
        {
            Services.Dispose();
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed class RecordingLog : ILoggerProvider, ILogger
    {
        public List<(LogLevel Level, string Message, Exception? Error)> Entries { get; } = new();
        public ILogger CreateLogger(string categoryName) => this;
        public bool IsEnabled(LogLevel logLevel) => true;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add((logLevel, formatter(state, exception), exception));
        public void Dispose() { }
    }
}
