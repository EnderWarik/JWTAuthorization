using Microsoft.EntityFrameworkCore;

namespace AuthorizationWithJWT.Models
{
    public class ApplicationContext : DbContext
    {
        public ApplicationContext() { }
        public DbSet<Account> accounts{ get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseMySql(
                "server=localhost;user=root;password=EnderWarAdmin;database=firstdb;",
                new MySqlServerVersion(new Version(8, 0, 27))
            );
        }
    }
}
