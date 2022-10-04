using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MvcUyelikSistemi.CustomValidation
{
    public class CustomIdentityErrorDescriber:IdentityErrorDescriber
    {
        public override IdentityError InvalidUserName(string userName)
        {
            return new IdentityError()
            {
                Code="InvalidUsername",
                Description=$"{userName} geçersizdir."
            };
        }
        public override IdentityError DuplicateEmail(string email)
        {
            return new IdentityError()
            {
                Code = "DuplicateEmail",
                Description = $"{email} zaten sistemde mevcut."
            };
        }
        public override IdentityError PasswordTooShort(int length)
        {
            return new IdentityError()
            {
                Code = "PasswordTooShort",
                Description = $"Parolanız en az {length} karakter olmalıdır."
            };
        }
        public override IdentityError DuplicateUserName(string userName)
        {
            return new IdentityError()
            {
                Code = "DuplicateUserName",
                Description = $"{userName} zaten sistemde mevcut."
            };
        }
    }
}
