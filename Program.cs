using System.Security.Claims;
using Dynamic_Authorization;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSingleton<PermissionsDatabase>();
builder.Services.AddAuthentication("cookie")
    .AddCookie("cookie");

builder.Services.AddAuthorization();
var app = builder.Build();

app.MapGet("/", (ClaimsPrincipal user)=> user.Claims.Select(x=> new {x.Type, x.Value}));
app.MapGet("/login", () => Results.SignIn(
    new ClaimsPrincipal(
        new ClaimsIdentity(
            new Claim[]{
                new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())
            },
            "cookie"
        )
    ),
    authenticationScheme:"cookie"
)); 

app.MapGet("/promote", (
    string permission,
    ClaimsPrincipal user,
    PermissionsDatabase database
)=>{
    var userId=user.FindFirstValue(ClaimTypes.NameIdentifier);
    database.AddPermission(userId, permission);
});

app.Run();
