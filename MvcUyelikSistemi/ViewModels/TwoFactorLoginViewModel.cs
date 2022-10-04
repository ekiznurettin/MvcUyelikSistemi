using MvcUyelikSistemi.Enums;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace MvcUyelikSistemi.ViewModels
{
    public class TwoFactorLoginViewModel
    {
        [Display(Name = "Doğrulama Kodunuz")]
        [Required(ErrorMessage = "Bu alan zorunludur")]
        [StringLength(8, ErrorMessage = "Doğrulama kodunuz en fazla 8 haneli olmalıdır")]
        public string VerificationCode { get; set; }

        public bool IsRememberMe { get; set; }

        public bool IsRecoveryCode { get; set; }

        public TwoFactor TwoFactorType { get; set; }

    }
}
