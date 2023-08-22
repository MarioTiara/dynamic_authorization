using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace DynamicAuthMVC
{
    public class DynamicAuthorizationHandler : AuthorizationHandler<DynamicRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, DynamicRequirement requirement)
        {
            if (context.Resource is not HttpContext httpCtx){
                context.Fail();
                return Task.CompletedTask;
            }

            var endpoint =httpCtx.GetEndpoint();
            var endpointName= endpoint.DisplayName;
            var authTags=endpoint.Metadata.OfType<TagsAttribute>()
                .SelectMany(x=>x.Tags)
                .Where(x=>x.StartsWith("auth"))
                .Select(x=>x.Split(':').Last());
            
            var userId =context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var scope = httpCtx.RequestServices.CreateScope();
            var database=scope.ServiceProvider.GetRequiredService<PermissionsDatabase>();

            foreach ( var authTag in authTags){
                if (database.HasPermission(userId, authTag)){
                    context.Succeed(requirement);
                    return Task.CompletedTask;
                }
             }

            context.Fail();
             return Task.CompletedTask;
        }
    }

    public class DynamicRequirement:IAuthorizationRequirement{}


}