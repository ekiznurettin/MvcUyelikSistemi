using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace MvcUyelikSistemi.ViewModels
{
    public class PasswordChangeViewModel
    {
        [Required(ErrorMessage = "Parola gereklidir")]
        [Display(Name = "Eski Parola")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "Şifreniz en az 4 karakter olmalıdır")]
        public string OldPassword { get; set; }

        [Required(ErrorMessage = "Yeni Parola gereklidir")]
        [Display(Name = "Yeni Parola")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "Yeni Şifreniz en az 4 karakter olmalıdır")]
        public string NewPassword { get; set; }

        [Required(ErrorMessage = "Yeni Parolanızı tekrar giriniz")]
        [Display(Name = "Yeni Parola Tekrar")]
        [DataType(DataType.Password)]
        [MinLength(4, ErrorMessage = "Yeni Şifreniz en az 4 karakter olmalıdır")]
        [Compare("NewPassword",ErrorMessage ="Yeni şifreniz onay şifreniz biribirinin aynısı olmalıdır")]
        public string NewPasswordConfirm { get; set; }
    }
}
