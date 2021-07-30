namespace Bit.Core.Models.Request
{
    public class TwoFactorFido2ChallengeRequest
    {
        public string Email { get; set; }
        public string MasterPasswordHash { get; set; }
    }
}
