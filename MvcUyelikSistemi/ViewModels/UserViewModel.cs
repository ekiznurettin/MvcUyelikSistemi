using MvcUyelikSistemi.Enums;
using System;
using System.ComponentModel.DataAnnotations;

namespace MvcUyelikSistemi.ViewModels
{
    public class UserViewModel
    {
        [Required(ErrorMessage ="Kullanıcı ismi gereklidir")]
        [Display(Name ="Kullanıcı Adı")]
        public string UserName { get; set; }

        [Display(Name = "Telefon Numarası")]
        [RegularExpression(@"^(0(\d{3}) (\d{3}) (\d{ 2}) (\d { 2}))$",ErrorMessage ="Telefon numarası uygun formatta değil")]
        public string PhoneNumber { get; set; }

        [Required(ErrorMessage = "Email adresi gereklidir")]
        [Display(Name = "Email Adresi")]
        [EmailAddress(ErrorMessage ="Email adresiniz doğru formatta değil")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Parola gereklidir")]
        [Display(Name = "Parola")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "Şehir")]
        public string City { get; set; }
        [Display(Name = "Resim")]
        public string Picture { get; set; }
        [DataType(DataType.Date)]
        [Display(Name = "Doğum Tarihi")]
        public DateTime? BirthDay { get; set; }
        [Display(Name = "Cinsiyet")]
        public Gender Gender { get; set; }
    }
}
