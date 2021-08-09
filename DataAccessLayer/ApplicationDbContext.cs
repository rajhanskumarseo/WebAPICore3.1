using ClassLibrary.Model.Models.DbModel;
using ClassLibrary.Model.Models.SpModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace DataAccessLayer
{
    public class ApplicationDbContext : IdentityDbContext<IdentityUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {

        }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
        }

        public DbSet<Profile> Profiles { get; set; }

        public DbSet<RefreshToken> RefreshTokens { get; set; }

        public DbSet<GetUserById> GetUserByIds { get; set; }

        public DbSet<ResetPassword> ResetPasswords { get; set; }
    }
}
