using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MvcUyelikSistemi.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MvcUyelikSistemi.Controllers
{
    public class BaseController : Controller
    {
        protected readonly UserManager<AppUser> UserManager;
        protected readonly SignInManager<AppUser> SignInManager;
        protected readonly RoleManager<AppRole> RoleManager;
        protected AppUser CurrentUser => UserManager.FindByNameAsync(User.Identity.Name).Result;

        public BaseController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager=null, RoleManager<AppRole> roleManager=null)
        {
            UserManager = userManager;
            SignInManager = signInManager;
            RoleManager = roleManager;
        }
        public void AddModelError(IdentityResult result)
        {
            foreach (var item in result.Errors)
            {
                ModelState.AddModelError("", item.Description);
            }
        }
    }
}
