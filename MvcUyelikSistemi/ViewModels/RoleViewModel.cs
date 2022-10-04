using System.ComponentModel.DataAnnotations;

namespace MvcUyelikSistemi.ViewModels
{
    public class RoleViewModel
    {
        public string Id { get; set; }
        [Required(ErrorMessage ="Rol ismi gereklidir")]
        [Display(Name="Rol Adı")]
        public string Name { get; set; }
    }
}
