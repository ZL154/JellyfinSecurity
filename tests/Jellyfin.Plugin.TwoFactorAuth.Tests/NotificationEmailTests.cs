using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

// [#259] The admin alert addresses only produced a log line. These tests pin
// that each address now gets the alert over SMTP, that the test button reports
// the email channel, and that neither a real event nor the test button waits
// on SMTP longer than it has to.
public class NotificationEmailTests
{
    private static PluginConfiguration Config(params string[] addresses) => new()
    {
        NotifyEmailAddresses = addresses,
        SmtpHost = "smtp.example.com",
        SmtpFromAddress = "jellyfin@example.com",
    };

    // Stands in for EmailOtpService.SendAlertEmailsAsync: one call is one SMTP
    // session for every address.
    private sealed class Outbox
    {
        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

        public ConcurrentQueue<(string To, string Subject, string Body)> Sent { get; } = new();

        public TaskCompletionSource FirstSent { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        // Runs at the start of each session with the session number: throwing is
        // a server that cannot be reached, an unfinished task holds the session.
        public Func<int, Task>? BeforeConnect { get; init; }

        // Addresses the server refuses.
        public HashSet<string> Refuse { get; init; } = new();

        public async Task<IReadOnlyList<(string Address, Exception Error)>> SendAsync(
            IReadOnlyList<string> to, string subject, string body)
        {
            var call = Interlocked.Increment(ref _calls);
            if (BeforeConnect is not null)
            {
                await BeforeConnect(call).ConfigureAwait(false);
            }

            var failed = new List<(string Address, Exception Error)>();
            foreach (var address in to)
            {
                if (Refuse.Contains(address))
                {
                    failed.Add((address, new InvalidOperationException("refused")));
                    continue;
                }

                Sent.Enqueue((address, subject, body));
            }

            FirstSent.TrySetResult();
            return failed;
        }
    }

    private static NotificationService Build(PluginConfiguration cfg, Outbox outbox)
        => new(NullLogger<NotificationService>.Instance, outbox.SendAsync, () => cfg);

    private static NotificationService.ChannelResult Email(IReadOnlyList<NotificationService.ChannelResult> results)
        => Assert.Single(results, r => r.Channel == "email");

    // A real event hands the email to the background and returns. Bounding the
    // wait makes a regression fail the test instead of hanging the run.
    private static async Task Returns(Task notify)
        => Assert.Same(notify, await Task.WhenAny(notify, Task.Delay(TimeSpan.FromSeconds(5))));

    [Fact]
    public async Task The_test_button_emails_every_admin_address_once_in_one_session()
    {
        var outbox = new Outbox();
        var svc = Build(Config("a@example.com", " ", "b@example.com", "A@example.com"), outbox);

        var email = Email(await svc.SendTestAsync());

        Assert.True(email.Configured);
        Assert.True(email.Success);
        Assert.Null(email.Error);
        Assert.Equal(1, outbox.Calls);
        Assert.Equal(new[] { "a@example.com", "b@example.com" }, outbox.Sent.Select(m => m.To).OrderBy(t => t));
        Assert.All(outbox.Sent, m =>
        {
            Assert.Equal("Jellyfin Security test notification", m.Subject);
            Assert.Contains("If you can read this", m.Body);
            Assert.Contains("Event: test", m.Body);
        });
    }

    [Fact]
    public async Task Without_SMTP_the_email_channel_says_so_and_sends_nothing()
    {
        var outbox = new Outbox();
        var cfg = Config("a@example.com");
        cfg.SmtpHost = string.Empty;

        var email = Email(await Build(cfg, outbox).SendTestAsync());

        Assert.True(email.Configured);
        Assert.False(email.Success);
        Assert.Contains("SMTP is not configured", email.Error);
        Assert.Equal(0, outbox.Calls);
    }

    [Fact]
    public async Task No_alert_addresses_means_the_email_channel_is_skipped()
    {
        var outbox = new Outbox();

        var email = Email(await Build(Config(), outbox).SendTestAsync());

        Assert.False(email.Configured);
        Assert.Equal(0, outbox.Calls);
    }

    [Fact]
    public async Task A_refused_address_is_reported_and_the_others_still_get_the_alert()
    {
        var outbox = new Outbox { Refuse = new() { "bad@example.com" } };

        var email = Email(await Build(Config("bad@example.com", "good@example.com"), outbox).SendTestAsync());

        Assert.False(email.Success);
        Assert.Equal("SMTP send failed for 1 of 2 addresses (InvalidOperationException).", email.Error);
        Assert.Equal("good@example.com", Assert.Single(outbox.Sent).To);
    }

    [Fact]
    public async Task A_server_that_does_not_answer_is_tried_once_for_every_address()
    {
        var outbox = new Outbox { BeforeConnect = _ => Task.FromException(new TimeoutException()) };

        var email = Email(await Build(Config("a@example.com", "b@example.com"), outbox).SendTestAsync());

        Assert.False(email.Success);
        Assert.Equal("SMTP send failed (TimeoutException).", email.Error);
        Assert.Equal(1, outbox.Calls);
        Assert.Empty(outbox.Sent);
    }

    [Fact]
    public async Task A_real_event_does_not_wait_for_SMTP()
    {
        // Several controller actions await the notification inside the
        // request, so a slow SMTP server must not hold them up.
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var outbox = new Outbox { BeforeConnect = _ => release.Task };
        var svc = Build(Config("a@example.com"), outbox);
        try
        {
            await Returns(svc.NotifyEmergencyLockoutAsync("alice", "203.0.113.7"));
            Assert.Empty(outbox.Sent);
        }
        finally
        {
            // Always let the held send finish: background alerts share a gate.
            release.TrySetResult();
        }

        await outbox.FirstSent.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var sent = Assert.Single(outbox.Sent);
        Assert.Equal("Account locked by user", sent.Subject);
        Assert.Contains("Event: emergency_lockout", sent.Body);
    }

    [Fact]
    public async Task The_test_button_does_not_wait_behind_a_background_alert()
    {
        var hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var outbox = new Outbox { BeforeConnect = call => call == 1 ? hold.Task : Task.CompletedTask };
        var svc = Build(Config("a@example.com"), outbox);
        try
        {
            await Returns(svc.NotifyEmergencyLockoutAsync("alice", "203.0.113.7"));
            for (var i = 0; i < 250 && outbox.Calls == 0; i++)
            {
                await Task.Delay(20);
            }

            Assert.Equal(1, outbox.Calls);

            var test = svc.SendTestAsync();
            Assert.Same(test, await Task.WhenAny(test, Task.Delay(TimeSpan.FromSeconds(5))));
            Assert.True(Email(await test).Success);
            Assert.Equal("Jellyfin Security test notification", Assert.Single(outbox.Sent).Subject);
        }
        finally
        {
            hold.TrySetResult();
        }
    }

    [Fact]
    public async Task Background_alerts_go_out_one_session_at_a_time()
    {
        var hold = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var outbox = new Outbox { BeforeConnect = call => call == 1 ? hold.Task : Task.CompletedTask };
        var svc = Build(Config("a@example.com"), outbox);
        try
        {
            await Returns(svc.NotifyEmergencyLockoutAsync("alice", "203.0.113.7"));
            await Returns(svc.NotifyEmergencyLockoutAsync("bob", "203.0.113.8"));

            // Wait for the background worker to pick up the first session (it may
            // not start within a fixed delay under a loaded parallel test host),
            // then confirm the second is still blocked behind it.
            for (var i = 0; i < 250 && outbox.Calls < 1; i++)
            {
                await Task.Delay(20);
            }
            await Task.Delay(100);

            // The second alert waits for the first session to finish.
            Assert.Equal(1, outbox.Calls);
        }
        finally
        {
            hold.TrySetResult();
        }

        for (var i = 0; i < 250 && outbox.Sent.Count < 2; i++)
        {
            await Task.Delay(20);
        }

        Assert.Equal(2, outbox.Calls);
        Assert.Equal(2, outbox.Sent.Count);
    }

    [Fact]
    public void The_alert_body_carries_the_message_the_event_and_the_time_in_UTC()
    {
        var body = NotificationService.BuildAlertEmailBody(
            "Sign-in from 203.0.113.7", "suspicious_login", new DateTime(2026, 10, 10, 17, 40, 5, DateTimeKind.Utc));

        Assert.StartsWith("Sign-in from 203.0.113.7\n\n", body);
        Assert.Contains("Event: suspicious_login\nTime: 2026-10-10 17:40:05 UTC", body);
    }
}
