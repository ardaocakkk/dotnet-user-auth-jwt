using Microsoft.AspNetCore.Identity;

namespace WebApplication4.Entity;

public class AppUser : IdentityUser
{
    [MaxLength(100)]
    public string? FullName { get; set; } 
}