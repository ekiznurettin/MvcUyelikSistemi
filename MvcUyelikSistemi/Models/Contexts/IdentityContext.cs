using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace MvcUyelikSistemi.Models.Contexts
{
    public class IdentityContext:IdentityDbContext<AppUser,AppRole,string>
    {
        public IdentityContext(DbContextOptions<IdentityContext> options):base(options)
        {
        }

    }
}
