using Microsoft.AspNetCore.Identity;
using MvcUyelikSistemi.Models;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace MvcUyelikSistemi.CustomValidation
{
    public class CustomPasswordValidator : IPasswordValidator<AppUser>
    {
        public Task<IdentityResult> ValidateAsync(UserManager<AppUser> manager, AppUser user, string password)
        {
            List<IdentityError> errors = new List<IdentityError>();
            if (password.ToLower().Contains(user.UserName.ToLower()))
            {
                if (!user.Email.ToLower().Contains(user.UserName.ToLower()))
                {
                    errors.Add(new IdentityError() { Code = "PasswordContainsUserName", Description = "Şifreniz alanı kullanıcı adı içeremez" });
                }
            }
            if (password.ToLower().Contains("1234"))
            {
                errors.Add(new IdentityError() { Code = "PasswordContains1234", Description = "Şifreniz alanı ardışık sayı içeremez" });
            }
            if (password.ToLower().Contains(user.Email.ToLower()))
            {
                errors.Add(new IdentityError() { Code = "PasswordContainsEmail", Description = "Şifreniz alanı email içeremez" });
            }
            if (errors.Count == 0)
            {
                return Task.FromResult(IdentityResult.Success);
            }
            else
            {
                return Task.FromResult(IdentityResult.Failed(errors.ToArray()));
            }
        }
    }
}
