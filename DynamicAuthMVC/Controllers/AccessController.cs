using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace DynamicAuthMVC.Controllers
{
    [Route("[controller]")]
    public class AccessController : Controller
    {
        private readonly ILogger<AccessController> _logger;
        private readonly PermissionsDatabase _permissionsDatabase;

        public AccessController(ILogger<AccessController> logger,
                                PermissionsDatabase permissionsDatabase)
        {
            this._permissionsDatabase=permissionsDatabase;
            _logger = logger;
        }

        [Authorize(Policy ="dynamic")]
        [Tags("auth:access/Index")]
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet("sign")]
        public IActionResult Login(){
            var identity = new ClaimsIdentity(
                new Claim[]{
                    new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())
                },
                "cookie"

            );
            return SignIn(new ClaimsPrincipal(identity),authenticationScheme:"cookie");
        }

        [HttpGet("GetUser")]
        [Authorize(Policy ="dynamic")]
        [Tags("auth:access/GetUser")]
        public IActionResult GetUser(){
         var user =HttpContext.User.Claims.Select(x=> new {x.Type, x.Value});
         return Ok(user);
        }

        [HttpGet("depromote")]
        public IActionResult Depromote([FromQuery] string permission){
            var userId=HttpContext.User.Claims.Where(x=>x.Type==ClaimTypes.NameIdentifier).First().Value;
            this._permissionsDatabase.RemovePermission(userId, permission);

            return Ok();
        }

        [HttpGet("promote")]
        public IActionResult Promote([FromQuery]  string permission){
            var userId=HttpContext.User.Claims.Where(x=>x.Type==ClaimTypes.NameIdentifier).First().Value;
            this._permissionsDatabase.AddPermission(userId, permission);

            return Ok();
        }
    }
}