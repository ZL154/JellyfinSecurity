using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class StepUpServiceTests
{
    [Fact]
    public void Config_defaults_are_opt_in_off()
    {
        var cfg = new PluginConfiguration();
        Assert.False(cfg.RequireTwoFactorToDisable);
        Assert.Equal(StepUpLevel.Off, cfg.StepUpLevel);
        Assert.Equal(300, cfg.StepUpWindowSeconds);
    }
}
