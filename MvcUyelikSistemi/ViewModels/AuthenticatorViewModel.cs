using MvcUyelikSistemi.Enums;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace MvcUyelikSistemi.ViewModels
{
    public class AuthenticatorViewModel
    {
        public string SharedKey { get; set; }
        public string AuthenticationUri { get; set; }
        [Display(Name = "Doğrulama Kodu")]
        [Required(ErrorMessage = "Bu alan zorunludur")]
        public string VerificationCode { get; set; }
        [Display(Name = "Doğrulama Tipi")]
        public TwoFactor TwoFactorType { get; set; }
    }
}
