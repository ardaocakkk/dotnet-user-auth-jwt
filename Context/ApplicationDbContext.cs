using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using WebApplication4.Entity;

namespace WebApplication4.Context;

public class ApplicationDbContext : IdentityDbContext<AppUser>
{
    public ApplicationDbContext (DbContextOptions<ApplicationDbContext> options) : base(options)
    {
    }
    
    public DbSet<AppUser> AppUsers { get; set; }
    
}