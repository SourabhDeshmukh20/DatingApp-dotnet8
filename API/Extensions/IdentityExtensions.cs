using System;
using System.Collections;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace API.Extensions;

public static class IdentityExtensions
{
    public static IServiceCollection AddIdentityServices(this IServiceCollection services,
                                                              IConfiguration config)
    {
        services.AddAuthentication(Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            var tokenKey = config["TokenKey"] ?? throw new Exception("TokenKey not found");
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenKey)),
                ValidateIssuer = false,
                ValidateAudience = false
            };
        });
        return services;
    }
}
