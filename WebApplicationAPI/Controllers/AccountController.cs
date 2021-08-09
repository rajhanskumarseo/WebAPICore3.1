using ClassLibrary.Model.Models;
using ClassLibrary.Model.Models.DbModel;
using ClassLibrary.Model.Models.SpModel;
using DataAccessLayer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using RepositoryServices;
using RepositoryServices.Interfaces;
using RepositoryServices.StaticMethods;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
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
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly IConfiguration _configuration;
        private readonly ApplicationDbContext databaseContext;
        private readonly IAccountRepository accountRepository;

        public AccountController(UserManager<IdentityUser> userManager
            , RoleManager<IdentityRole> roleManager
            , SignInManager<IdentityUser> signInManager
            , IConfiguration configuration
            , ApplicationDbContext applicationDbContext
            , IAccountRepository accountRepository)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.signInManager = signInManager;
            _configuration = configuration;
            databaseContext = applicationDbContext;
            this.accountRepository = accountRepository;
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
            if (user != null
                && await userManager.CheckPasswordAsync(user, loginModel.Password)
                && (await signInManager.PasswordSignInAsync(user, loginModel.Password, false, false)).Succeeded)
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
        public async Task<IActionResult> Registration([FromBody] Register registerModel)
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
                await signInManager.RefreshSignInAsync(user);

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

        /// <summary>
        /// Logout
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("logout")]
        public async Task<IActionResult> Logout()
        {
            await signInManager.SignOutAsync();

            var response = new Response
            {
                Message = "Logout success!",
                Status = "Success"
            };

            return Ok(response);
        }

        /// <summary>
        /// Update Profile
        /// </summary>
        /// <param name="profileModel"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("updateProfile")]
        public async Task<IActionResult> UpdateProfile(ProfileModel profileModel)
        {
            try
            {
                if (profileModel == null)
                {
                    return BadRequest();
                }

                // Update record using entity framework in .Net Core

                var currentUserId = User.Claims.ToList().FirstOrDefault(x => x.Type == "id").Value;

                var profile = new Profile
                {
                    Address1 = profileModel.Address1,
                    Address2 = profileModel.Address2,
                    City = profileModel.City,
                    State = profileModel.State,
                    Landmark = profileModel.Landmark,
                    Pin = profileModel.Pin,
                    CountryCode = profileModel.CountryCode
                };

                bool result = await accountRepository.UpdateProfileAsync(profile, currentUserId);

                if (result)
                {
                    return Ok();
                }

                return BadRequest();
            }
            catch (Exception)
            {

                throw;
            }
        }

        /// <summary>
        /// Get profile
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("Profile")]
        public async Task<IActionResult> GetProfile()
        {
            // Getting currently loggedIn userId
            var currentUserId = User.Claims.ToList().FirstOrDefault(x => x.Type == "id").Value;

            var userProfile = (await databaseContext.GetUserByIds.FromSqlInterpolated($"Exec GetProfile @userId = {currentUserId}").ToListAsync()).FirstOrDefault();

            return Ok(userProfile);
        }

        /// <summary>
        /// Get users
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("Users")]
        public async Task<IActionResult> GetUsers(int offset, int limit)
        {
            var users = (await databaseContext.GetUserByIds.FromSqlInterpolated($"Exec GetUsers @offset = {offset}, @limit = {limit}").ToListAsync());

            return Ok(users);
        }

        [AllowAnonymous]
        [Route("UploadImage")]
        public async Task<IActionResult> UploadImage(UploadImage imageDetails)
        {
            byte[] bytes = Convert.FromBase64String(imageDetails.Image);

            Image image;
            using (MemoryStream ms = new MemoryStream(bytes))
            {
                image = Image.FromStream(ms);
            }

            image.Save("wwwroot/xyz." + imageDetails.Type, ImageFormat.Png);

            return Ok();
        }

        [AllowAnonymous]
        [Route("CallAPI")]
        [HttpGet]
        public async Task<IActionResult> CallAPI()
        {
            // Call Get API
            //using (var client = new HttpClient())
            //{
            //    client.BaseAddress = new Uri("https://jsonplaceholder.typicode.com/");

            //    using (HttpResponseMessage response = await client.GetAsync("todos/1"))
            //    {
            //        var responseContent = response.Content.ReadAsStringAsync().Result;
            //        response.EnsureSuccessStatusCode();

            //        return Ok(responseContent);
            //    }
            //}

            // Call POST API
            //using (var client = new HttpClient())
            //{
            //    client.BaseAddress = new Uri("https://jsonplaceholder.typicode.com/");

            //    var postData = new
            //    {
            //        title = "foo",
            //        body = "bar",
            //        userId = 1
            //    };

            //    var content = new StringContent(JsonConvert.SerializeObject(postData), Encoding.UTF8, "application/json");

            //    using (HttpResponseMessage response = await client.PostAsync("posts", content))
            //    {
            //        var responseContent = response.Content.ReadAsStringAsync().Result;
            //        response.EnsureSuccessStatusCode();

            //        return Ok(responseContent);
            //    }
            //}

            // Call PUT API
            //using (var client = new HttpClient())
            //{
            //    client.BaseAddress = new Uri("https://jsonplaceholder.typicode.com/");

            //    var postData = new
            //    {
            //        title = "foo",
            //        body = "bar",
            //        userId = 1,
            //        id = 1
            //    };

            //    var content = new StringContent(JsonConvert.SerializeObject(postData), Encoding.UTF8, "application/json");

            //    using (HttpResponseMessage response = await client.PutAsync("todos/1", content))
            //    {
            //        var responseContent = response.Content.ReadAsStringAsync().Result;
            //        response.EnsureSuccessStatusCode();

            //        return Ok(responseContent);
            //    }
            //}

            // Call DELETE API
            using (var client = new HttpClient())
            {
                client.BaseAddress = new Uri("https://jsonplaceholder.typicode.com/");

                using (HttpResponseMessage response = await client.DeleteAsync("posts/1"))
                {
                    var responseContent = response.Content.ReadAsStringAsync().Result;
                    response.EnsureSuccessStatusCode();

                    return Ok(responseContent);
                }
            }
        }

        [AllowAnonymous]
        [Route("CallAPIRS")]
        [HttpGet]
        public async Task<IActionResult> CallAPIRestSharp()
        {
            var client = new RestClient("https://jsonplaceholder.typicode.com/");

            IRestRequest restRequest = new RestRequest("todos/1"
                , Method.DELETE, DataFormat.Json);

            var response = await client.ExecuteAsync(restRequest);

            return Ok(response.Content);
        }

        [AllowAnonymous]
        [Route("UploadFile")]
        [HttpPost]
        public async Task<IActionResult> UploadFile(UploadFile file)
        {
            var index = file.FileAsBase64.IndexOf(',');
            var base64stringWithoutSignature = file.FileAsBase64.Substring(index+1);

            index = file.FileAsBase64.IndexOf(';');
            var base64signatue = file.FileAsBase64.Substring(0, index);
            index = base64signatue.IndexOf("/");
            var extension = base64signatue.Substring(index + 1);

            byte[] bytes = Convert.FromBase64String(base64stringWithoutSignature);

            await System.IO.File.WriteAllBytesAsync("wwwroot/xyz." + extension, bytes);

            return Ok();
        }

        [HttpPost]
        [Route("ChangePassword")]
        public async Task<IActionResult> ChangePassword(ChangePassword changePassword)
        {
            // Get currently loggedin user Id
            var currentUserId = User.Claims.ToList()
                .FirstOrDefault(x => x.Type == "id").Value;

            // Get Identity User details user user manager
            var user = await userManager.FindByIdAsync(currentUserId);

            // Change password using user manager
            await userManager.ChangePasswordAsync(user,
                changePassword.CurrentPassword, changePassword.NewPassword);

            return Ok();
        }

        /// <summary>
        /// Send Password Reset Token or Code
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [HttpPost]
        [AllowAnonymous]
        [Route("SendPasswordResetCode")]
        public async Task<IActionResult> SendPasswordResetCode(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                return BadRequest("Email should not be null or empty");
            }

            // Get Identity User details user user manager
            var user = await userManager.FindByNameAsync(email);

            // Generate password reset token
            var token = await userManager.GeneratePasswordResetTokenAsync(user);

            // Generate OTP
            int otp = RandomNumberGeneartor.Generate(100000, 999999);

            var resetPassword = new ResetPassword()
            {
                Email = email,
                OTP = otp.ToString(),
                Token = token,
                UserId = user.Id,
                InsertDateTimeUTC = DateTime.UtcNow
            };

            // Save data into db with OTP
            await databaseContext.AddAsync(resetPassword);
            await databaseContext.SaveChangesAsync();

            // to do: Send token in email
            await EmailSender.SendEmailAsync(email, "Reset Password OTP", "Hello " 
                + email + "<br><br>Please find the reset password token below<br><br><b>"
                + otp + "<b><br><br>Thanks<br>oktests.com");

            return Ok("Token sent successfully in email");
        }

        /// <summary>
        /// Reset Password
        /// </summary>
        /// <param name="email"></param>
        /// <param name="newPassword"></param>
        /// <returns></returns>
        [HttpPost]
        [AllowAnonymous]
        [Route("ResetPassword")]
        public async Task<IActionResult> ResetPassword(string email, string otp, string newPassword)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(newPassword))
            {
                return BadRequest("Email & New Password should not be null or empty");
            }

            // Get Identity User details user user manager
            var user = await userManager.FindByNameAsync(email);

            // getting token from otp
            var resetPasswordDetails = await databaseContext.ResetPasswords
                .Where(rp => rp.OTP == otp && rp.UserId == user.Id)
                .OrderByDescending(rp => rp.InsertDateTimeUTC)
                .FirstOrDefaultAsync();

            // Verify if token is older than 15 minutes
            var expirationDateTimeUtc = resetPasswordDetails.InsertDateTimeUTC.AddMinutes(15);

            if (expirationDateTimeUtc < DateTime.UtcNow)
            {
                return BadRequest("OTP is expired, please generate the new OTP");
            }

            var res = await userManager.ResetPasswordAsync(user, resetPasswordDetails.Token, newPassword);

            if (!res.Succeeded)
            {
                return BadRequest();
            }

            return Ok();
        }
    }
}