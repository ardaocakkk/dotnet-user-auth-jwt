using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using WebApplication4.Dto;
using WebApplication4.Entity;

namespace WebApplication4.Controller;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{

    private readonly SignInManager<AppUser> _signInManager;
    private readonly UserManager<AppUser> _userManager;
    private readonly IConfiguration _config;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ApplicationDbContext _context;
    
    public UserController(SignInManager<AppUser> signInManager, UserManager<AppUser> userManager, IConfiguration config, ApplicationDbContext context, RoleManager<IdentityRole> roleManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _config = config;
        _roleManager = roleManager;
        _context = context;
    }
    
    [HttpGet]
    [Authorize (Roles = "Admin")]
    public Task<List<AppUser>> Get()
    {
        return _context.AppUsers.ToListAsync();
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterUser regUser)
    {

        var user = new AppUser
        {
            FullName = regUser.Email,
            UserName = regUser.Email,
            Email = regUser.Email,
            PasswordHash = regUser.Password
        };
        var checkAdmin = await _roleManager.FindByNameAsync("Admin");
        var result = await _userManager.CreateAsync(user, user.PasswordHash!);
        if (!result.Succeeded)
        {
            BadRequest(result);
        }
        if (checkAdmin is  null)
        {
            var role = new IdentityRole("Admin");
            await _roleManager.CreateAsync(role);
            await _userManager.AddToRoleAsync(user, "Admin");
            return Ok( new {message = "User created successfully", result = result, token = GenerateJwtToken(user)}  );
        }
        var checkUser = await _roleManager.FindByNameAsync("User");
        if (checkUser is null)
        {
            await _roleManager.CreateAsync(new IdentityRole("User"));
        }
        await _userManager.AddToRoleAsync(user, "User");
        await _context.SaveChangesAsync();
        return Ok( new {message = "User created successfully", result = result, token = GenerateJwtToken(user)}  );
        
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(RegisterUser regUser)
    {
        AppUser user = await _userManager.FindByEmailAsync(regUser.Email);
        
        
        
        if (user == null)
        {
            
            return BadRequest(new {message = "Invalid email or password user is null"});
        }

       
        try
        {
            var result = await _signInManager.PasswordSignInAsync(user.UserName, regUser.Password, false, false);
            if (!result.Succeeded)
            {
                return BadRequest(new
                    { message = "Invalid email or password result is not successful", result = result });
            }
        }
        catch (Exception e)
        {
            return BadRequest(new {message = "Invalid email or password", exception = e.Message});
        } 
        return Ok(new {message = "Login successful", token = GenerateJwtToken(user)});





    }
    [HttpGet("test")]
    [Authorize (Roles = "User")]
    public IActionResult Test()
    {
        return Ok(new {message = "Test successful"});
    }
    
    
    private string GenerateJwtToken(AppUser user)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role , _userManager.GetRolesAsync(user).Result.FirstOrDefault()!)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expires = DateTime.Now.AddDays(Convert.ToDouble(_config["Jwt:ExpireDays"]));

        var token = new JwtSecurityToken(
            _config["Jwt:Issuer"],
            _config["Jwt:Audience"],
            claims,
            expires: expires,
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

}