using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace MvcUyelikSistemi.ViewModels
{
    public class PasswordResetViewModel
    {
        [Required(ErrorMessage = "Email adresi gereklidir")]
        [Display(Name = "Email Adresi")]
        [EmailAddress(ErrorMessage = "Email adresiniz doğru formatta değil")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Parola gereklidir")]
        [Display(Name = "Yeni Parola")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "Şifreniz en az 4 karakter olmalıdır")]
        public string PasswordNew { get; set; }
    }
}
