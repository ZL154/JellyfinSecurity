using System;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class OnboardingSessionProofStoreTests
{
    [Fact]
    public void Proof_IsBoundToUser_AndSingleUse()
    {
        var store = new OnboardingSessionProofStore();
        var owner = Guid.NewGuid();
        var other = Guid.NewGuid();
        var proof = store.Mint(owner);

        Assert.False(store.Validate(other, proof, consume: false));

        // A wrong-user probe removes the suspect proof rather than allowing
        // the owner to reuse a token that may have leaked.
        Assert.False(store.Validate(owner, proof, consume: false));

        proof = store.Mint(owner);
        Assert.True(store.Validate(owner, proof, consume: false));
        Assert.True(store.Validate(owner, proof, consume: true));
        Assert.False(store.Validate(owner, proof, consume: true));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-proof")]
    public void MissingOrForgedProof_IsRejected(string? proof)
    {
        var store = new OnboardingSessionProofStore();
        Assert.False(store.Validate(Guid.NewGuid(), proof, consume: false));
    }
}
