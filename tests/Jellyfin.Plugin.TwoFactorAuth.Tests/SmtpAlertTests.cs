using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

// [#259] EmailOtpService.SendAlertEmailsAsync against a real SMTP conversation:
// one session for every address, and what happens when the server refuses an
// address, drops the connection or stops answering. Every call is bounded, so
// a regression fails instead of hanging the run.
public class SmtpAlertTests
{
    private static readonly TimeSpan Bound = TimeSpan.FromSeconds(30);

    private static EmailOtpService Build(FakeSmtpServer server, TimeSpan? budget = null)
    {
        var cfg = new PluginConfiguration
        {
            SmtpHost = "127.0.0.1",
            SmtpPort = server.Port,
            SmtpUseSsl = false,
            SmtpFromAddress = "jellyfin@example.test",
        };
        var smtp = new EmailOtpService(NullLogger<EmailOtpService>.Instance, () => cfg);
        if (budget is not null)
        {
            smtp.AlertSessionBudget = budget.Value;
        }

        return smtp;
    }

    [Fact]
    public async Task Every_address_gets_its_own_message_over_one_connection()
    {
        await using var server = new FakeSmtpServer();

        var failed = await Build(server).SendAlertEmailsAsync(
            new[] { "a@example.test", "b@example.test", "c@example.test" }, "Alert", "Body").WaitAsync(Bound);

        Assert.Empty(failed);
        Assert.Equal(1, server.Connections);
        Assert.Equal(new[] { "a@example.test", "b@example.test", "c@example.test" }, server.Delivered);
    }

    [Fact]
    public async Task A_refused_address_does_not_stop_the_rest()
    {
        await using var server = new FakeSmtpServer { Refuse = { "b@example.test" } };

        var failed = await Build(server).SendAlertEmailsAsync(
            new[] { "a@example.test", "b@example.test", "c@example.test" }, "Alert", "Body").WaitAsync(Bound);

        var refused = Assert.Single(failed);
        Assert.Equal("b@example.test", refused.Address);
        Assert.IsType<MailKit.Net.Smtp.SmtpCommandException>(refused.Error);
        Assert.Equal(new[] { "a@example.test", "c@example.test" }, server.Delivered);
    }

    [Fact]
    public async Task An_address_that_does_not_parse_does_not_stop_the_rest()
    {
        await using var server = new FakeSmtpServer();

        var failed = await Build(server).SendAlertEmailsAsync(
            new[] { "not an address", "a@example.test" }, "Alert", "Body").WaitAsync(Bound);

        Assert.Equal("not an address", Assert.Single(failed).Address);
        Assert.Equal(new[] { "a@example.test" }, server.Delivered);
    }

    [Fact]
    public async Task A_dropped_connection_fails_the_addresses_left()
    {
        await using var server = new FakeSmtpServer { DropAfter = 1 };

        var failed = await Build(server).SendAlertEmailsAsync(
            new[] { "a@example.test", "b@example.test", "c@example.test" }, "Alert", "Body").WaitAsync(Bound);

        Assert.Equal(new[] { "a@example.test" }, server.Delivered);
        Assert.Equal(new[] { "b@example.test", "c@example.test" }, failed.Select(f => f.Address));
    }

    [Fact]
    public async Task Running_out_of_time_keeps_what_went_out()
    {
        await using var server = new FakeSmtpServer { SilentAfter = 1 };

        var failed = await Build(server, TimeSpan.FromSeconds(2)).SendAlertEmailsAsync(
            new[] { "a@example.test", "b@example.test", "c@example.test" }, "Alert", "Body").WaitAsync(Bound);

        Assert.Equal(new[] { "a@example.test" }, server.Delivered);
        Assert.Equal(new[] { "b@example.test", "c@example.test" }, failed.Select(f => f.Address));
        Assert.All(failed, f => Assert.IsAssignableFrom<OperationCanceledException>(f.Error));
    }

    [Fact]
    public async Task No_server_means_nothing_went_out_and_the_call_throws()
    {
        int port;
        await using (var gone = new FakeSmtpServer())
        {
            port = gone.Port;
        }

        var cfg = new PluginConfiguration
        {
            SmtpHost = "127.0.0.1",
            SmtpPort = port,
            SmtpUseSsl = false,
            SmtpFromAddress = "jellyfin@example.test",
        };
        var smtp = new EmailOtpService(NullLogger<EmailOtpService>.Instance, () => cfg);

        await Assert.ThrowsAnyAsync<Exception>(
            () => smtp.SendAlertEmailsAsync(new[] { "a@example.test" }, "Alert", "Body").WaitAsync(Bound));
    }

    [Fact]
    public async Task A_failed_address_is_masked_in_the_log_even_inside_the_server_reply()
    {
        var cfg = new PluginConfiguration
        {
            NotifyEmailAddresses = new[] { "bob@example.test" },
            SmtpHost = "smtp.example.test",
            SmtpFromAddress = "jellyfin@example.test",
        };
        var log = new CapturingLogger();
        var svc = new NotificationService(
            log,
            (to, subject, body) => Task.FromResult<IReadOnlyList<(string Address, Exception Error)>>(new[]
            {
                ("bob@example.test", (Exception)new InvalidOperationException("5.1.1 <bob@example.test>: Recipient address rejected")),
            }),
            () => cfg);

        await svc.SendTestAsync().WaitAsync(Bound);

        Assert.DoesNotContain(log.Lines, l => l.Contains("bob@example.test", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(log.Lines, l => l.Contains("b***@example.test", StringComparison.Ordinal));
    }

    private sealed class CapturingLogger : Microsoft.Extensions.Logging.ILogger<NotificationService>
    {
        public ConcurrentQueue<string> Lines { get; } = new();

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull
            => null;

        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;

        public void Log<TState>(
            Microsoft.Extensions.Logging.LogLevel logLevel,
            Microsoft.Extensions.Logging.EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
            => Lines.Enqueue(formatter(state, exception) + (exception is null ? string.Empty : " | " + exception.Message));
    }

    [Fact]
    public void Blank_and_null_alert_addresses_are_skipped()
    {
        var cfg = new PluginConfiguration
        {
            NotifyEmailAddresses = new[] { "a@example.test", null!, "  ", "A@example.test" },
        };

        Assert.Equal(new[] { "a@example.test" }, NotificationService.AlertEmailTargets(cfg));
    }

    // Just enough SMTP for MailKit: greeting, EHLO, MAIL, RCPT, DATA, RSET,
    // NOOP and QUIT. Refuse rejects an address at RCPT; DropAfter closes the
    // connection after that many accepted messages; SilentAfter stops
    // answering after that many.
    private sealed class FakeSmtpServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly ConcurrentQueue<string> _delivered = new();
        private readonly Task _accepting;
        private int _connections;

        public FakeSmtpServer()
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _accepting = AcceptAsync();
        }

        public int Port { get; }

        public int Connections => Volatile.Read(ref _connections);

        public IReadOnlyList<string> Delivered => _delivered.ToArray();

        public HashSet<string> Refuse { get; } = new(StringComparer.OrdinalIgnoreCase);

        public int? DropAfter { get; init; }

        public int? SilentAfter { get; init; }

        public async ValueTask DisposeAsync()
        {
            _stop.Cancel();
            _listener.Stop();
            try
            {
                await _accepting.ConfigureAwait(false);
            }
            catch (Exception)
            {
                // The accept loop ends with the listener.
            }

            _stop.Dispose();
        }

        private async Task AcceptAsync()
        {
            while (!_stop.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(_stop.Token).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    return;
                }

                Interlocked.Increment(ref _connections);
                _ = Task.Run(() => ServeAsync(client));
            }
        }

        private async Task ServeAsync(TcpClient client)
        {
            try
            {
                using (client)
                {
                    var stream = client.GetStream();
                    using var reader = new StreamReader(stream, Encoding.ASCII);
                    using var writer = new StreamWriter(stream, Encoding.ASCII) { NewLine = "\r\n", AutoFlush = true };
                    await writer.WriteLineAsync("220 fake.test ESMTP").ConfigureAwait(false);
                    var accepted = 0;
                    string? recipient = null;
                    while (true)
                    {
                        var line = await reader.ReadLineAsync(_stop.Token).ConfigureAwait(false);
                        if (line is null)
                        {
                            return;
                        }

                        var verb = (line.Length >= 4 ? line[..4] : line).ToUpperInvariant();
                        switch (verb)
                        {
                            case "EHLO":
                            case "HELO":
                                await writer.WriteLineAsync("250 fake.test").ConfigureAwait(false);
                                break;
                            case "MAIL":
                                recipient = null;
                                await writer.WriteLineAsync("250 OK").ConfigureAwait(false);
                                break;
                            case "RCPT":
                                var address = line[(line.IndexOf('<') + 1)..line.LastIndexOf('>')];
                                if (Refuse.Contains(address))
                                {
                                    await writer.WriteLineAsync($"550 5.1.1 <{address}>: Recipient address rejected").ConfigureAwait(false);
                                }
                                else
                                {
                                    recipient = address;
                                    await writer.WriteLineAsync("250 OK").ConfigureAwait(false);
                                }

                                break;
                            case "DATA":
                                await writer.WriteLineAsync("354 End data with <CR><LF>.<CR><LF>").ConfigureAwait(false);
                                while ((line = await reader.ReadLineAsync(_stop.Token).ConfigureAwait(false)) is not null && line != ".")
                                {
                                }

                                accepted++;
                                if (recipient is not null)
                                {
                                    _delivered.Enqueue(recipient);
                                }

                                await writer.WriteLineAsync("250 OK queued").ConfigureAwait(false);
                                if (accepted == DropAfter)
                                {
                                    return;
                                }

                                if (accepted == SilentAfter)
                                {
                                    await Task.Delay(Timeout.Infinite, _stop.Token).ConfigureAwait(false);
                                }

                                break;
                            case "QUIT":
                                await writer.WriteLineAsync("221 bye").ConfigureAwait(false);
                                return;
                            default:
                                await writer.WriteLineAsync("250 OK").ConfigureAwait(false);
                                break;
                        }
                    }
                }
            }
            catch (Exception)
            {
                // Torn down by the test or by the client.
            }
        }
    }
}
