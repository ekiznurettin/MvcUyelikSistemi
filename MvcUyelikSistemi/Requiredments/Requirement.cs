using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MvcUyelikSistemi.Requiredments
{
    public class ExpireDateExchangeRequirement : IAuthorizationRequirement
    {

    }
    public class ExpireDateExchangeHandler : AuthorizationHandler<ExpireDateExchangeRequirement>
    {
        protected override  Task HandleRequirementAsync(AuthorizationHandlerContext context, ExpireDateExchangeRequirement requirement)
        {
           if(context.User!=null & context.User.Identity != null)
            {
                var claim = context.User.Claims.Where(a => a.Type == "ExpireDateExchange" && a.Value != null).FirstOrDefault();
                if (claim != null) {
                    if (DateTime.Now < Convert.ToDateTime(claim.Value))
                    {
                        context.Succeed(requirement);
                    }
                    else
                    {
                        context.Fail();
                    }
                }
            }
            return Task.CompletedTask;
        }
    }
}
