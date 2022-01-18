using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using AuthorizationWithJWT.Models;
using Microsoft.Extensions.Options;
using AuthorizationWithJWT.Library;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

namespace AuthorizationWithJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IOptions<AuthOptions> options;
        public AuthController(IOptions<AuthOptions> options )
        {
            this.options = options;
        }




        [Route("login")]
        [HttpPost]
        public IActionResult Login([FromBody] Login login)
        {
            var user = AuthenticateUser(login.Email, login.Password);

            if (user != null)
            {
                var token = GenerateJWT(user);
                return Ok(new { access_token = token });
                //generate jwt
            }
            return Unauthorized();

        }

        private Account AuthenticateUser(string email, string password)
        {
            using ApplicationContext db = new ApplicationContext();
            {
                foreach (var l in db.accounts.ToList())
                {
                    if (l.Email == email && l.Password == password)
                    {
                        return l;
                    }
                }

            }
            return null;

        }
  

        [Route("Register")]
        [HttpPost]
        public IActionResult Register([FromBody] Login login)
        {
            if (login != null)
            {
                using ApplicationContext db = new ApplicationContext();
                {
                    db.accounts.Add(new Account { Email=login.Email, Password=login.Password, Role ="Admin"});
                    db.SaveChanges();
                    return Login(login);

                }

            }
            return BadRequest(); //шо це таке 
        }

        private string GenerateJWT(Account user)
        {
            var authParams = options.Value;
            var securityKey = authParams.GetSymmetricSecurityKey();
            var credentinals = new SigningCredentials(securityKey,SecurityAlgorithms.HmacSha256);
            var claims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Email,user.Email),
                new Claim(JwtRegisteredClaimNames.Sub,user.Id.ToString()),
               // new Claim(ClaimsIdentity.DefaultRoleClaimType,"Admin"),
                new Claim("role","User")
                //new Claim(JwtRegisteredClaimNames.Iss,authParams.Issure)
            };
            //foreach(var role in user.Role)
            //{
            //    claims.Add(new Claim("role",role.ToString()));

            //}

            var token = new JwtSecurityToken(authParams.Issure,
                authParams.Audience,
                claims,
                expires: DateTime.Now.AddSeconds(authParams.TokenLifeTime),
                signingCredentials: credentinals);
            
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
