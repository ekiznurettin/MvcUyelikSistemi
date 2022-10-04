using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using MvcUyelikSistemi.Models;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace MvcUyelikSistemi.ClaimProviders
{
    public class ClaimProvider : IClaimsTransformation
    {
        private readonly UserManager<AppUser> UserManager;

        public ClaimProvider(UserManager<AppUser> userManager)
        {
            UserManager = userManager;
        }

        public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            if (principal != null && principal.Identity.IsAuthenticated)
            {
                ClaimsIdentity identity = principal.Identity as ClaimsIdentity;
                AppUser user = await UserManager.FindByNameAsync(identity.Name);

                

                if (user != null)
                {
                    if (user.BirthDay != null)
                    {
                        var today = DateTime.Today;
                        var age = today.Year - user.BirthDay?.Year;
                        if (age > 15)
                        {
                            Claim violanceClaim = new Claim("violance", true.ToString(), ClaimValueTypes.String, "Internal");
                            identity.AddClaim(violanceClaim);
                        }
                    }
                    if (user.City != null)
                    {
                        if (!principal.HasClaim(c => c.Type == "city"))
                        {
                            Claim cityClaim = new Claim("city", user.City,ClaimValueTypes.String,"Internal");
                            identity.AddClaim(cityClaim);
                        }
                    }
                }
            }
            return principal;
        }
    }
}
