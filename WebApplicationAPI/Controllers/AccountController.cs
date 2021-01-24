using ClassLibrary.Model.Models;
using ClassLibrary.Model.Models.DbModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace WebApplicationAPI.Controllers
{
    [Authorize]
    [ApiController]
    [Route("Account")]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext databaseContext;

        public AccountController(UserManager<IdentityUser> userManager
            , RoleManager<IdentityRole> roleManager
            , IConfiguration configuration
            , ApplicationDbContext applicationDbContext)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            _configuration = configuration;
            databaseContext = applicationDbContext;
        }

        /// <summary>
        /// Login
        /// </summary>
        /// <param name="loginModel"></param>
        /// <returns></returns>
        [HttpPost]
        [AllowAnonymous]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] Login loginModel)
        {
            var user = await userManager.FindByNameAsync(loginModel.Username);
            if (user != null && await userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                RefreshTokenModel refreshTokenModel = await GenerateAccessToken(user);

                return Ok(new
                {
                    success = true,
                    token = refreshTokenModel.Token,
                    refreshToken = refreshTokenModel.RefreshToken,
                    expiration = refreshTokenModel.Expiration
                });
            }

            return Unauthorized();
        }

        /// <summary>
        /// Generate the access token
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        private async Task<RefreshTokenModel> GenerateAccessToken(IdentityUser user)
        {
            var userRoles = await userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("id", user.Id)
            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.UtcNow.AddSeconds(300),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );
            
            var refreshTokenModel = new RefreshTokenModel
            {
                RefreshToken = (await GenerateRefreshToken(user.Id, token.Id)).Token,
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Expiration = token.ValidTo
            };

            return refreshTokenModel;
        }

        /// <summary>
        /// Generate Refresh Token
        /// </summary>
        /// <param name="UserId"></param>
        /// <param name="TokenId"></param>
        /// <returns><see cref="Task{RefreshToken}"/></returns>
        private async Task<RefreshToken> GenerateRefreshToken(string UserId, string TokenId)
        {
            var refreshToken = new RefreshToken();
            var randomNumber = new byte[32];

            using (var randomNumerGenerator = RandomNumberGenerator.Create())
            {
                randomNumerGenerator.GetBytes(randomNumber);
                refreshToken.Token = Convert.ToBase64String(randomNumber);
                refreshToken.ExpiryDateTimeUtc = DateTime.UtcNow.AddMonths(6);
                refreshToken.CreatedDateTimeUtc = DateTime.UtcNow;
                refreshToken.UserId = UserId;
                refreshToken.JwtId = TokenId;
            }

            await databaseContext.AddAsync(refreshToken);
            await databaseContext.SaveChangesAsync();

            return refreshToken;
        }

        /// <summary>
        /// Register administrator
        /// </summary>
        /// <param name="registerModel"></param>
        /// <returns></returns>
        [HttpPost]
        [AllowAnonymous]
        [Route("register")]
        public async Task<IActionResult> RegisterAdmin([FromBody] Register registerModel)
        {
            var userExists = await userManager.FindByNameAsync(registerModel.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

            IdentityUser user = new IdentityUser()
            {
                Email = registerModel.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerModel.Username
            };

            // Create user
            var result = await userManager.CreateAsync(user, registerModel.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            // Checking roles in database and creating if not exists
            if (!await roleManager.RoleExistsAsync(ApplicationUserRoles.Admin))
                await roleManager.CreateAsync(new IdentityRole(ApplicationUserRoles.Admin));
            if (!await roleManager.RoleExistsAsync(ApplicationUserRoles.User))
                await roleManager.CreateAsync(new IdentityRole(ApplicationUserRoles.User));

            // Add role to user
            if (!string.IsNullOrEmpty(registerModel.Role) && registerModel.Role == ApplicationUserRoles.Admin)
            {
                await userManager.AddToRoleAsync(user, ApplicationUserRoles.Admin);
            }
            else
            {
                await userManager.AddToRoleAsync(user, ApplicationUserRoles.User);
            }

            var profile = new Profile()
            {
                Address1 = registerModel.Address1,
                Address2 = registerModel.Address2,
                City = registerModel.City,
                Landmark = registerModel.Landmark,
                CountryCode = registerModel.CountryCode,
                Pin = registerModel.Pin,
                State = registerModel.State,
                UserId = user.Id
            };

            await databaseContext.AddAsync(profile);
            await databaseContext.SaveChangesAsync();

            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

        /// <summary>
        /// Get new access token and refresh token
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <returns><see cref="Task{TResult}"/></returns>
        [HttpPost]
        [AllowAnonymous]
        [Route("refreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenModel refreshToken)
        {
            var user = GetUserFromAccessToken(refreshToken.Token);

            if (user != null && ValidateRefreshToken(user, refreshToken.RefreshToken))
            {
                RefreshTokenModel refreshTokenModel = await GenerateAccessToken(user);

                return Ok(new
                {
                    success = true,
                    token = refreshTokenModel.Token,
                    refreshToken = refreshTokenModel.RefreshToken,
                    expiration = refreshTokenModel.Expiration
                });
            }

            return Unauthorized();
        }

        /// <summary>
        /// Validate the refresh token
        /// </summary>
        /// <param name="user"></param>
        /// <param name="refreshToken"></param>
        /// <returns><see cref="bool"/></returns>
        private bool ValidateRefreshToken(IdentityUser user, string refreshToken)
        {
            RefreshToken rtUser = databaseContext.RefreshTokens.Where(rt => rt.Token == refreshToken)
                .OrderByDescending(rt => rt.ExpiryDateTimeUtc)
                .FirstOrDefault();

            if (rtUser != null && rtUser.UserId == user.Id && rtUser.ExpiryDateTimeUtc > DateTime.UtcNow)
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Get user from access token including expired token
        /// </summary>
        /// <param name="token"></param>
        /// <returns><see cref="IdentityUser"/></returns>
        private IdentityUser GetUserFromAccessToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var key = Encoding.ASCII.GetBytes(_configuration["JWT:Secret"]);

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidAudience = _configuration["JWT:ValidAudience"],
                ValidIssuer = _configuration["JWT:ValidIssuer"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                RequireExpirationTime = false,
                ValidateLifetime = false,
                ClockSkew = TimeSpan.Zero
            };

            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);

            JwtSecurityToken jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken != null && jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                var userName = principal.FindFirst(ClaimTypes.Name)?.Value;

                var userInfo = databaseContext.Users.FirstOrDefault(u => u.UserName == userName);

                return userInfo;
            }

            return null;
        }
    }
}
