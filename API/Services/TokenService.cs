using System;
using System.Security.Cryptography;
using API.Entities;
using API.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using System.Security.Claims;

namespace API.Services;

public class TokenService(IConfiguration config) : ITokenService
{
    public string CreateToken(AppUser user)
    {
        var tokenKey = config["TokenKey"] ?? throw new Exception("Can not access token key from appsettings.");
        if (tokenKey.Length < 64)
            throw new Exception("Your token key needs to be longer");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenKey));
        var claim = new List<Claim>
        {
           new(ClaimTypes.NameIdentifier, user.UserName),
        };
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claim),
            Expires = DateTime.UtcNow.AddDays(7),
            SigningCredentials = creds
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}
